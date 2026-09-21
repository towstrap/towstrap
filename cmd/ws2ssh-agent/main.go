package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"ws2ssh/internal/client"
	"ws2ssh/internal/config"
	"ws2ssh/internal/version"
)

// ws2ssh-agent 只含客户端：装在被控机器上，主动连出到 ws2ssh-server。
// 服务器端和账号管理在另一个二进制 ws2ssh-server 里——被控机上不需要
// （也不该有）SQLite 账号库、SSH 服务端这些东西。

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "agent": // 容忍旧的子命令写法
		os.Exit(runAgent(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println(version.String())
	default:
		os.Exit(runAgent(os.Args[1:]))
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ws2ssh-agent — 装在要被访问的机器上（不用开 sshd），主动连出到服务器

用法:
  ws2ssh-agent [--config 文件.yaml] [选项]
  ws2ssh-agent version

选项:
  --config 文件.yaml
  --server wss://主机:443      服务器开了 --tls 就写 wss://
  --agent-token w2s-...        user add 生成的那个 token（会进 ps，不建议）
  --agent-token-file 路径      从文件读 token（推荐，文件权限设 0600）
                               （也可用环境变量 WS2SSH_AGENT_TOKEN；
                                配置文件里写 agent_token / agent_token_file 也行）
  --shell /bin/bash            不写用 $SHELL，再不行 /bin/bash
  --insecure                   服务器用自签证书时跳过证书校验
  --audit-log 路径             会话审计日志（默认 root: /var/lib/ws2ssh/audit.log，
                               否则 ~/.ws2ssh/audit.log）
  --quiet                      关掉会话开始/结束的桌面通知和 wall 广播
                               （审计日志不受影响，仍照写）

服务器地址、shell、审计路径这些长久配置建议写进 agent.yaml（见 examples/agent.yaml），
命令行旗标只做临时覆盖。
`)
}

func visited(fs *flag.FlagSet) map[string]string {
	out := map[string]string{}
	fs.Visit(func(f *flag.Flag) { out[f.Name] = f.Value.String() })
	return out
}

func runAgent(args []string) int {
	fs := flag.NewFlagSet("ws2ssh-agent", flag.ExitOnError)
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
	tok, tokenSource, err := resolveAgentToken(*agentToken, *tokenFile, os.Getenv("WS2SSH_AGENT_TOKEN"), cfg.AgentToken, cfg.AgentTokenFile)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}
	slog.Info("agent token 来源", "source", tokenSource)
	if cfg.Server == "" {
		slog.Error("必须设置 server（配置文件或命令行）")
		return 2
	}
	if err := client.Run(client.Config{
		Server:     cfg.Server,
		AgentToken: tok,
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
// （启动日志用）。文件内容整体去空白（echo > file 会带换行）。
func resolveAgentToken(flagToken, flagFile, envToken, yamlToken, yamlFile string) (string, string, error) {
	if flagToken != "" {
		return flagToken, "旗标 --agent-token", nil
	}
	if flagFile != "" {
		tok, err := readTokenFile(flagFile)
		if err != nil {
			return "", "", err
		}
		return tok, "旗标 --agent-token-file " + flagFile, nil
	}
	if envToken != "" {
		return strings.TrimSpace(envToken), "环境变量 WS2SSH_AGENT_TOKEN", nil
	}
	if yamlToken != "" {
		return yamlToken, "配置 agent_token", nil
	}
	if yamlFile != "" {
		tok, err := readTokenFile(yamlFile)
		if err != nil {
			return "", "", err
		}
		return tok, "配置 agent_token_file " + yamlFile, nil
	}
	return "", "", fmt.Errorf("必须提供 agent token：--agent-token、--agent-token-file 文件、环境变量 WS2SSH_AGENT_TOKEN 或配置文件 agent_token/agent_token_file")
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
