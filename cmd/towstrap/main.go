package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/client"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/selfupdate"
	"github.com/towstrap/towstrap/internal/version"
)

// towstrap 只含客户端：装在被控机器上，主动连出到 towstrap-server。
// 服务器端和账号管理在另一个二进制 towstrap-server 里——被控机上不需要
// （也不该有）SQLite 账号库、SSH 服务端这些东西。

func main() {
	args := os.Args
	// busybox 式别名：以 mirror（或 towstrap-mirror）的名字被调起 = towstrap mirror。
	// install.sh 会建 PREFIX/mirror → towstrap 软链，让接入短成 `mirror work`。
	switch mirrorProg() {
	case "mirror", "towstrap-mirror":
		args = append([]string{args[0], "mirror"}, args[1:]...)
	}
	if len(args) < 2 {
		// 裸跑：装过的机器（默认路径有 agent.yaml）或环境变量已给足
		// 凭据时直接起 agent；什么都没装的机器才显示用法。
		if fileExists(config.DefaultAgentPath()) ||
			os.Getenv("TOWSTRAP_AGENT_TOKEN") != "" || os.Getenv("TOWSTRAP_SERVER") != "" {
			os.Exit(runAgent(nil))
		}
		usage()
		os.Exit(2)
	}
	if args[1] == "-h" || args[1] == "--help" {
		usage()
		os.Exit(2)
	}
	switch args[1] {
	case "agent": // 容忍旧的子命令写法
		os.Exit(runAgent(args[2:]))
	case "mirror":
		os.Exit(runMirror(args[2:]))
	case "token":
		if len(args) < 3 || args[2] != "refresh" {
			usageToken()
			os.Exit(2)
		}
		os.Exit(runTokenRefresh(args[3:]))
	case "oauth":
		os.Exit(runOAuth(args[2:]))
	case "register":
		os.Exit(runRegister(args[2:]))
	case "totp":
		os.Exit(runTOTP(args[2:]))
	case "passwd":
		os.Exit(runPasswd(args[2:]))
	case "update":
		os.Exit(runUpdate(args[2:]))
	case "status":
		os.Exit(runStatus(args[2:]))
	case "version", "-v", "--version":
		fmt.Println(version.String())
	default:
		os.Exit(runAgent(args[1:]))
	}
}

// mirrorProg 返回提示里该用的命令名：被软链成 mirror 起的就显示 mirror，
// 否则显示完整写法 towstrap mirror。
func mirrorProg() string {
	switch b := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe"); b {
	case "mirror", "towstrap-mirror":
		return b
	}
	return "towstrap mirror"
}

func usage() {
	fmt.Fprintf(os.Stderr, `towstrap — 装在要被访问的机器上（不用开 sshd），主动连出到服务器

用法:
  towstrap [--config 文件.yaml] [选项]
  towstrap oauth [--wait 5m] [选项]   发起 OIDC 授权，拿到短时效 SSH 凭据
  towstrap register [选项]            首次接入：没账号建号（服务器开 register:）、有账号登录加机
  towstrap totp [remove] [选项]       绑/换绑/解绑账号的 TOTP 二因素（SSH 里也能用 @totp）
  towstrap passwd [选项]              改账号的 SSH/登录密码（本机 token + 旧密码鉴权）
  towstrap mirror [ls|kill|<名字> [命令]]   本机的可接力终端（Ctrl-\ 脱离）
                                       （install.sh 会把它软链成 mirror，直接敲 mirror work）
  towstrap update [--version vX.Y.Z] [--check]   自升级：从官方 Release 拉新版，
                                       核 SHA256 后替换自身；服务托管的自动重启
  towstrap status [-q]               看这台机器上的 agent 跑没跑、连没连上
  towstrap version

选项:
  --config 文件.yaml
  --server wss://主机:443      服务器地址（默认官方服务器；自建才需要传）
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
  --mirror-idle 时长           镜像终端闲置多久自动终结（默认 72h；0/off 不启用）

服务器地址、shell、审计路径这些长久配置建议写进 agent.yaml（见 examples/agent.yaml），
命令行旗标只做临时覆盖。

换 token 用 towstrap token refresh（见 towstrap token 不带参数的说明）。
`)
}

func usageToken() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap token refresh [--machine 机器名]... [--all] [选项]

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
	fs := flag.NewFlagSet("towstrap", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	fs.String("server", "", "")
	agentToken := fs.String("agent-token", "", "")
	tokenFile := fs.String("agent-token-file", "", "")
	fs.String("shell", "", "")
	fs.Bool("insecure", false, "")
	fs.Bool("quiet", false, "")
	fs.String("audit-log", "", "")
	fs.String("mirror-idle", "", "")
	fs.String("mcp-policy", "", "")
	_ = fs.Parse(args)
	// 位置参数没有意义——拼错的子命令会落到这里，不拦就当成启动
	// agent 跑起来了，报错比误解安全。
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "未知参数 %q——是不是想打某个子命令？（oauth/register/totp/passwd/mirror/update/status/version）\n", fs.Args())
		return 2
	}

	var file config.Agent
	if *configPath == "" {
		// 不带 --config 时自动用安装脚本落的默认位置（root→/etc/towstrap，
		// 用户→~/.config/towstrap，Windows→%LOCALAPPDATA%\TowStrap）：
		// 装完裸跑 towstrap 就能起，配置不是必需品而是默认值。
		if d := config.DefaultAgentPath(); fileExists(d) {
			*configPath = d
			slog.Info("未带 --config，用默认安装位置", "config", d)
		}
	}
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
		cfg.Server = proto.OfficialServer
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
	mirrorIdle, err := parseMirrorIdle(cfg.MirrorIdle)
	if err != nil {
		slog.Error("mirror_idle 时长不对", "value", cfg.MirrorIdle, "err", err)
		return 2
	}
	if err := client.Run(client.Config{
		Server:       cfg.Server,
		AgentToken:   tok,
		TokenFile:    tokFile,
		ProtectPaths: protect,
		Shell:        cfg.Shell,
		Insecure:     cfg.Insecure,
		Quiet:        cfg.Quiet,
		AuditLog:     cfg.AuditLog,
		MirrorIdle:   mirrorIdle,
		MCPPolicy:    cfg.MCPPolicy,
	}); err != nil {
		slog.Error("agent", "err", err)
		return 1
	}
	return 0
}

// runUpdate：手工自升级（不是后台自动更新，什么时候换由人拍板）。
// 实现细节（下载/校验/原子替换/服务重启）都在 internal/selfupdate。
func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	tag := fs.String("version", "", "指定版本（默认 latest）")
	check := fs.Bool("check", false, "只查最新版本，不下载")
	_ = fs.Parse(args)
	if err := selfupdate.Run(selfupdate.Opts{Product: "towstrap", Tag: *tag, Check: *check}); err != nil {
		fmt.Fprintln(os.Stderr, "update:", err)
		return 1
	}
	return 0
}

// parseMirrorIdle 把 mirror_idle 配置（"72h"/"168h" 这类时长，或 0/off
// 关闭）解析成 Duration；空 = 默认 72h。
func parseMirrorIdle(s string) (time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default":
		return 72 * time.Hour, nil
	case "0", "off", "false", "no", "never":
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q 不是时长（如 72h）也不是 0/off", s)
	}
	return d, nil
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

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
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
