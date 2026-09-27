package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/service"
)

// runService 是 `towstrap service <install|uninstall|status>`：
// 把 agent 注册成系统常驻服务（launchd/systemd/计划任务）——装了就能
// 开机自启、掉线自拉，不用再靠 nohup 顶着。等价 install.sh 的服务段。
func runService(args []string) int {
	if len(args) == 0 {
		usageService()
		return 2
	}
	verb := args[0]
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	_ = fs.Parse(args[1:])
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "未知参数 %q\n", fs.Args())
		return 2
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "取自身路径失败:", err)
		return 1
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	cfg, err := serviceConfigPath(*configPath)
	if err != nil {
		if verb == "install" {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	o := service.Opts{
		Name:       "agent",
		Exe:        exe,
		ConfigPath: cfg,
		SysUser:    "towstrap", // root 装法跑 towstrap/_towstrap 专用账号
	}

	switch verb {
	case "install":
		if err := checkAgentTokenPresent(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		msg, err := service.Install(o)
		if err != nil {
			fmt.Fprintln(os.Stderr, "service install:", err)
			return 1
		}
		fmt.Println(">>", msg)
		return 0
	case "uninstall":
		msg, err := service.Uninstall(o)
		if err != nil {
			fmt.Fprintln(os.Stderr, "service uninstall:", err)
			return 1
		}
		fmt.Println(">>", msg)
		return 0
	case "status":
		fmt.Println(service.Status(o))
		return 0
	default:
		usageService()
		return 2
	}
}

// serviceConfigPath 定服务要用的 agent.yaml：旗标优先，其次默认安装
// 位置；都找不到就是没装过。
func serviceConfigPath(flagPath string) (string, error) {
	if flagPath != "" {
		if !fileExists(flagPath) {
			return "", fmt.Errorf("--config 指的文件不存在：%s", flagPath)
		}
		return flagPath, nil
	}
	if d := config.DefaultAgentPath(); fileExists(d) {
		return d, nil
	}
	return "", fmt.Errorf("没找到 agent.yaml（默认位置 %s 没有，也没给 --config）——这台机器还没装过 agent，先跑 install 脚本或 towstrap register", config.DefaultAgentPath())
}

// checkAgentTokenPresent 挡住「服务装了但永远起不来」：agent 没有 token
// 必崩退，Restart=always 会刷失败循环。token 三处任一就位才算有：
// 配置文件直写/agent_token_file 文件在/环境变量。
func checkAgentTokenPresent(cfgPath string) error {
	if os.Getenv("TOWSTRAP_AGENT_TOKEN") != "" {
		return nil
	}
	cfg, err := config.LoadAgent(cfgPath)
	if err != nil {
		return fmt.Errorf("读配置 %s: %w", cfgPath, err)
	}
	if cfg.AgentToken != "" {
		return nil
	}
	if cfg.AgentTokenFile != "" {
		if st, err := os.Stat(cfg.AgentTokenFile); err == nil && st.Size() > 0 {
			return nil
		}
	}
	return fmt.Errorf("这台机器还没有 agent token——先跑 towstrap register 建号拿凭据（或把 token 写进 %s），再装服务", cfgPath)
}

func usageService() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap service install [--config agent.yaml]   注册成常驻服务并启动
  towstrap service status                          查服务状态
  towstrap service uninstall                       停用并删掉服务

装了之后 agent 开机自启、掉线自拉，不用 nohup 顶着——
macOS 走 launchd（com.towstrap.agent），Linux 走 systemd（root→系统单元
跑 towstrap 账号；普通用户→~/.config/systemd/user），Windows 注册
「登录自起」计划任务。
`)
}
