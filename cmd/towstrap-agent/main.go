package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/towstrap/towstrap/internal/client"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/version"
)

// towstrap-agent 只含客户端：装在被控机器上，主动连出到 towstrap-server。
// 服务器端和账号管理在另一个二进制 towstrap-server 里——被控机上不需要
// （也不该有）SQLite 账号库、SSH 服务端这些东西。

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "agent": // 容忍旧的子命令写法
		os.Exit(runAgent(os.Args[2:]))
	case "token":
		if len(os.Args) < 3 || os.Args[2] != "refresh" {
			usageToken()
			os.Exit(2)
		}
		os.Exit(runTokenRefresh(os.Args[3:]))
	case "version", "-v", "--version":
		fmt.Println(version.String())
	default:
		os.Exit(runAgent(os.Args[1:]))
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `towstrap-agent — 装在要被访问的机器上（不用开 sshd），主动连出到服务器

用法:
  towstrap-agent [--config 文件.yaml] [选项]
  towstrap-agent version

选项:
  --config 文件.yaml
  --server wss://主机:443      服务器开了 --tls 就写 wss://
  --agent-token tsa-...        user add 生成的那个 token（会进 ps，不建议）
  --agent-token-file 路径      从文件读 token（推荐，文件权限设 0600）
                               （也可用环境变量 TOWSTRAP_AGENT_TOKEN；
                                配置文件里写 agent_token / agent_token_file 也行）
  --shell /bin/bash            不写用 $SHELL（Windows 用 %%COMSPEC%%，兜底 cmd.exe）
  --insecure                   服务器用自签证书时跳过证书校验
  --audit-log 路径             会话审计日志（默认 root: /var/lib/towstrap/audit.log，
                               否则 ~/.towstrap/audit.log）
  --quiet                      关掉会话开始/结束的桌面通知和 wall 广播
                               （审计日志不受影响，仍照写）

服务器地址、shell、审计路径这些长久配置建议写进 agent.yaml（见 examples/agent.yaml），
命令行旗标只做临时覆盖。

换 token 用 towstrap-agent token refresh（见 towstrap-agent token 不带参数的说明）。
`)
}

func usageToken() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap-agent token refresh [--machine 机器名]... [--all] [选项]

在一台已登记的 agent 机器上换发 token：本机 token + 账号密码 + TOTP 鉴权，
新 token 由服务器经各机器的 WebSocket 连接直接下推写进各自的 token 文件，
agent 不用重启、连接不断。目标是 token 从文件读的机器（--agent-token-file
或配置 agent_token_file）；命令行/环境变量给的 token 不能远程换。

  --machine 机器名   同账号下要换的机器（不带账号前缀，可重复；不给只换本机）
  --all              换账号下全部机器
  --allow-plain      服务器地址是明文 ws:// 且不在本机回环时必须加（密码不能裸奔）
  其余 --config/--server/--agent-token/--agent-token-file/--insecure 同主命令
`)
}

func visited(fs *flag.FlagSet) map[string]string {
	out := map[string]string{}
	fs.Visit(func(f *flag.Flag) { out[f.Name] = f.Value.String() })
	return out
}

func runAgent(args []string) int {
	fs := flag.NewFlagSet("towstrap-agent", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	fs.String("server", "", "")
	agentToken := fs.String("agent-token", "", "")
	tokenFile := fs.String("agent-token-file", "", "")
	fs.String("shell", "", "")
	fs.Bool("insecure", false, "")
	fs.Bool("quiet", false, "")
	fs.String("audit-log", "", "")
	_ = fs.Parse(args)

	var file config.Agent
	if *configPath != "" {
		var err error
		file, err = config.LoadAgent(*configPath)
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
	}
	cfg := config.MergeAgent(file, visited(fs))
	// token 优先级：--agent-token > --agent-token-file > 环境变量 > 配置文件。
	// 命令行直写 token 会进 ps，尽量用后几种。
	tok, tokenSource, tokFile, err := resolveAgentToken(*agentToken, *tokenFile, os.Getenv("TOWSTRAP_AGENT_TOKEN"), cfg.AgentToken, cfg.AgentTokenFile)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}
	slog.Info("agent token 来源", "source", tokenSource)
	if cfg.Server == "" {
		slog.Error("必须设置 server（配置文件或命令行）")
		return 2
	}
	// 上报给服务器的禁碰清单：token 文件（文件来源时）和配置文件（可能
	// 内嵌 agent_token）。清洗成绝对路径；配置文件只要用了 --config 就
	// 一律上报，不管 token 到底放没放里面。
	var protect []string
	if tokFile != "" {
		protect = append(protect, absPath(tokFile))
	}
	if *configPath != "" {
		protect = append(protect, absPath(*configPath))
	}
	if err := client.Run(client.Config{
		Server:       cfg.Server,
		AgentToken:   tok,
		TokenFile:    tokFile,
		ProtectPaths: protect,
		Shell:      cfg.Shell,
		Insecure:   cfg.Insecure,
		Quiet:      cfg.Quiet,
		AuditLog:   cfg.AuditLog,
	}); err != nil {
		slog.Error("agent", "err", err)
		return 1
	}
	return 0
}

// resolveAgentToken 按优先级取 token：显式旗标 > token 文件旗标 > 环境变量 >
// 配置文件 agent_token > 配置文件 agent_token_file。第二个返回值是来源
// （启动日志用），第三个是 token 文件路径——只有「从文件读」的来源才填，
// 服务器远程换发和重连重读都靠它。文件内容整体去空白（echo > file 会带换行）。
func resolveAgentToken(flagToken, flagFile, envToken, yamlToken, yamlFile string) (string, string, string, error) {
	if flagToken != "" {
		return flagToken, "旗标 --agent-token", "", nil
	}
	if flagFile != "" {
		tok, err := readTokenFile(flagFile)
		if err != nil {
			return "", "", "", err
		}
		return tok, "旗标 --agent-token-file " + flagFile, flagFile, nil
	}
	if envToken != "" {
		return strings.TrimSpace(envToken), "环境变量 TOWSTRAP_AGENT_TOKEN", "", nil
	}
	if yamlToken != "" {
		return yamlToken, "配置 agent_token", "", nil
	}
	if yamlFile != "" {
		tok, err := readTokenFile(yamlFile)
		if err != nil {
			return "", "", "", err
		}
		return tok, "配置 agent_token_file " + yamlFile, yamlFile, nil
	}
	return "", "", "", fmt.Errorf("必须提供 agent token：--agent-token、--agent-token-file 文件、环境变量 TOWSTRAP_AGENT_TOKEN 或配置文件 agent_token/agent_token_file")
}

// absPath 把用户给的路径清洗成绝对路径（相对路径按当前工作目录解析），
// 供 hello 上报禁碰清单——服务器侧只做清洗后的精确比对。
func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func readTokenFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("读 token 文件 %s: %w", path, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", fmt.Errorf("token 文件 %s 是空的", path)
	}
	return tok, nil
}
