//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// systemdUnit 渲染单元文本。root 装法走系统单元（可指定 SysUser +
// 加固项），用户装法走 ~/.config/systemd/user。root 参数注入而不是
// 直接查 euid——测试不用真当 root。
func systemdUnit(o Opts, root bool) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	if o.Name == "server" {
		b.WriteString("Description=towstrap server（SSH + HTTP + MCP 入口）\n")
	} else {
		b.WriteString("Description=towstrap agent\n")
	}
	b.WriteString("After=network-online.target\nWants=network-online.target\n\n[Service]\n")
	if root && o.SysUser != "" {
		fmt.Fprintf(&b, "User=%s\nGroup=%s\n", o.SysUser, o.SysUser)
	}
	fmt.Fprintf(&b, "ExecStart=%s", o.Exe)
	for _, a := range o.args() {
		fmt.Fprintf(&b, " %s", a)
	}
	b.WriteString("\nRestart=always\nRestartSec=5\n")
	if root {
		b.WriteString("NoNewPrivileges=true\nProtectSystem=true\n")
		if o.ProtectHome {
			b.WriteString("ProtectHome=true\n")
		}
	}
	b.WriteString("\n[Install]\n")
	if root {
		b.WriteString("WantedBy=multi-user.target\n")
	} else {
		b.WriteString("WantedBy=default.target\n")
	}
	return b.String()
}

// unitPath 按 root/用户返回单元文件位置；systemctl 前缀同理（系统级不带 --user）。
func systemdPaths() (unitPath, sysctl string) {
	if os.Geteuid() == 0 {
		return "/etc/systemd/system", "systemctl"
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user"), "systemctl --user"
}

func install(o Opts) (string, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", fmt.Errorf("这台机器没有 systemctl——用 nohup/tmux 顶着或换 init 系统对应的守护方式")
	}
	dir, sysctl := systemdPaths()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// root 装法要服务账号：没有就建（useradd -r -m，对齐 install.sh）。
	if o.SysUser != "" && os.Geteuid() == 0 {
		if exec.Command("id", "-u", o.SysUser).Run() != nil {
			if err := exec.Command("useradd", "-r", "-m", "-s", "/bin/bash", o.SysUser).Run(); err != nil {
				return "", fmt.Errorf("建服务账号 %s 失败：%w", o.SysUser, err)
			}
		}
		if o.ConfigPath != "" {
			// 配置目录要给服务账号——agent 读不到 agent.yaml/token 起不来。
			_ = exec.Command("chown", "-R", o.SysUser+":"+o.SysUser, filepath.Dir(o.ConfigPath)).Run()
		}
	}
	unit := filepath.Join(dir, o.unitName()+".service")
	if err := os.WriteFile(unit, []byte(systemdUnit(o, os.Geteuid() == 0)), 0o644); err != nil {
		return "", err
	}
	_ = sh(sysctl + " daemon-reload")
	// 已启用 = 重装：enable --now 对运行中的服务是空操作，必须 restart
	// 才让新二进制生效（install.sh 同款语义）。
	if sh(sysctl+" is-enabled --quiet "+o.unitName()) == nil {
		if err := sh(sysctl + " restart " + o.unitName()); err != nil {
			return "", fmt.Errorf("单元已装好但重启失败：%w（手工 %s restart %s）", err, sysctl, o.unitName())
		}
		return fmt.Sprintf("systemd 服务 %s 已重启，新二进制生效", o.unitName()), nil
	}
	if err := sh(sysctl + " enable --now " + o.unitName()); err != nil {
		return "", fmt.Errorf("单元写好（%s）但启动失败：%w（手工 %s enable --now %s）", unit, err, sysctl, o.unitName())
	}
	if os.Geteuid() == 0 {
		return fmt.Sprintf("systemd 服务 %s 已启动并设为开机自启（journalctl -u %s 看日志）", o.unitName(), o.unitName()), nil
	}
	return fmt.Sprintf("systemd 用户服务 %s 已启动并设为开机自启（journalctl --user -u %s 看日志）", o.unitName(), o.unitName()), nil
}

func uninstall(o Opts) (string, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", fmt.Errorf("没有 systemctl")
	}
	dir, sysctl := systemdPaths()
	unit := filepath.Join(dir, o.unitName()+".service")
	if _, err := os.Stat(unit); err != nil {
		return "", fmt.Errorf("没找到服务单元 %s——本来就没装过", unit)
	}
	_ = sh(sysctl + " disable --now " + o.unitName())
	if err := os.Remove(unit); err != nil {
		return "", err
	}
	_ = sh(sysctl + " daemon-reload")
	return fmt.Sprintf("已停用并删掉 %s（二进制和配置没动）", o.unitName()), nil
}

func status(o Opts) string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "没有 systemctl"
	}
	dir, sysctl := systemdPaths()
	unit := filepath.Join(dir, o.unitName()+".service")
	installed := ""
	if _, err := os.Stat(unit); err == nil {
		installed = "单元已写"
	}
	out, _ := exec.Command("sh", "-c", sysctl+" is-enabled "+o.unitName()+" 2>/dev/null; "+sysctl+" is-active "+o.unitName()+" 2>/dev/null").Output()
	state := strings.Join(strings.Fields(string(out)), " ")
	if installed == "" && state == "" {
		return "未安装"
	}
	return strings.TrimSpace(installed + " " + state)
}

// sh 走 shell 跑命令（sysctl 字符串里带 --user 这种空格参数）。
func sh(c string) error {
	return exec.Command("sh", "-c", c).Run()
}
