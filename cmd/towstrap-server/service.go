package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/towstrap/towstrap/internal/service"
)

// runService 是 `towstrap-server service <install|uninstall|status>`：
// 把服务器注册成系统常驻服务——等价 install-server.sh 的 systemd 段，
// 补上 macOS launchd 和 Windows 计划任务两个平台。
func runServiceCmd(args []string) int {
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
	cfg := *configPath
	if verb == "install" {
		if cfg == "" {
			fmt.Fprintln(os.Stderr, "server 没有默认配置路径——用 --config 指明 server.yaml")
			return 2
		}
		if _, err := os.Stat(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "--config 指的文件不存在:", cfg)
			return 2
		}
	}
	o := service.Opts{
		Name:        "server",
		Exe:         exe,
		ConfigPath:  cfg,
		ProtectHome: true, // users.db 之外的家目录对服务进程不可见
	}

	switch verb {
	case "install":
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

func usageService() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap-server service install --config server.yaml   注册成常驻服务并启动
  towstrap-server service status                         查服务状态
  towstrap-server service uninstall                      停用并删掉服务

装了之后服务器开机自启、掉线自拉——Linux 走 systemd（系统单元），
macOS 走 launchd 守护项（com.towstrap.server），Windows 注册
「登录自起」计划任务。
`)
}
