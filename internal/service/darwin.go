//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// launchdPaths 按 root/用户返回 plist 位置、launchd 域、日志路径。
func launchdPaths(o Opts) (plist, domain, log string) {
	label := o.label()
	if os.Geteuid() == 0 {
		return "/Library/LaunchDaemons/" + label + ".plist", "system",
			"/var/log/" + o.unitName() + ".log"
	}
	home := os.Getenv("HOME")
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist"),
		fmt.Sprintf("gui/%d", os.Getuid()),
		filepath.Join(home, ".towstrap", o.unitName()+".log")
}

// plistXML 渲染 plist。root 守护项带专用账号和资源上限（对齐
// install.sh：UserName/GroupName + FD/进程数 4096/1024）；用户项只限 FD——
// 进程数上限按 uid 全体统计，设硬顶会误伤本机其它程序。
// root 注入而不查 euid——测试不用真当 root。
func plistXML(o Opts, log string, root bool) string {
	var keys strings.Builder
	keys.WriteString("\t<key>SoftResourceLimits</key>\n\t<dict>\n\t\t<key>NumberOfFiles</key><integer>4096</integer>\n")
	if root {
		keys.WriteString("\t\t<key>NumberOfProcesses</key><integer>1024</integer>\n\t</dict>\n\t<key>HardResourceLimits</key>\n\t<dict>\n\t\t<key>NumberOfFiles</key><integer>4096</integer>\n\t\t<key>NumberOfProcesses</key><integer>1024</integer>\n\t</dict>")
	} else {
		keys.WriteString("\t</dict>\n\t<key>HardResourceLimits</key>\n\t<dict>\n\t\t<key>NumberOfFiles</key><integer>4096</integer>\n\t</dict>")
	}
	if root && o.SysUser != "" {
		keys.WriteString(fmt.Sprintf("\n\t<key>UserName</key><string>%s</string>\n\t<key>GroupName</key><string>%s</string>", o.SysUser, o.SysUser))
	}
	var args strings.Builder
	fmt.Fprintf(&args, "\t\t<string>%s</string>\n", o.Exe)
	for _, a := range o.args() {
		fmt.Fprintf(&args, "\t\t<string>%s</string>\n", a)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key>
	<array>
%s	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>5</integer>
%s
	<key>StandardOutPath</key><string>%s</string>
	<key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, o.label(), args.String(), keys.String(), log, log)
}

// ensureSysUser 建 darwin 系统账号（_towstrap）：400-499 系统账号段找个
// 空 UID/GID，dscl 建组+建号，home 放 /var/lib/towstrap。对齐 install.sh。
func ensureSysUser(name string) error {
	if exec.Command("id", name).Run() == nil {
		return nil
	}
	out, _ := exec.Command("sh", "-c",
		"{ dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}'").Output()
	used := map[string]bool{}
	for _, f := range strings.Fields(string(out)) {
		used[f] = true
	}
	newid := ""
	for c := 400; c <= 499; c++ {
		if !used[strconv.Itoa(c)] {
			newid = strconv.Itoa(c)
			break
		}
	}
	if newid == "" {
		return fmt.Errorf("400-499 段没有空 UID/GID 建 %s", name)
	}
	shell := "/bin/bash"
	if _, err := os.Stat("/bin/zsh"); err == nil {
		shell = "/bin/zsh"
	}
	steps := [][]string{
		{".", "-create", "/Groups/" + name, "PrimaryGroupID", newid},
		{".", "-create", "/Groups/" + name, "Password", "*"},
		{".", "-create", "/Users/" + name},
		{".", "-create", "/Users/" + name, "UniqueID", newid},
		{".", "-create", "/Users/" + name, "PrimaryGroupID", newid},
		{".", "-create", "/Users/" + name, "UserShell", shell},
		{".", "-create", "/Users/" + name, "RealName", "towstrap " + name},
		{".", "-create", "/Users/" + name, "NFSHomeDirectory", "/var/lib/towstrap"},
		{".", "-create", "/Users/" + name, "Password", "*"},
	}
	for _, s := range steps {
		if err := exec.Command("dscl", s...).Run(); err != nil {
			return fmt.Errorf("dscl %v 失败：%w", s, err)
		}
	}
	if err := os.MkdirAll("/var/lib/towstrap", 0o750); err != nil {
		return err
	}
	_ = exec.Command("chown", name+":"+name, "/var/lib/towstrap").Run()
	return nil
}

func install(o Opts) (string, error) {
	plist, domain, log := launchdPaths(o)
	if o.SysUser == "" && os.Geteuid() == 0 {
		o.SysUser = "_towstrap"
	}
	if os.Geteuid() == 0 && o.SysUser != "" {
		if !strings.HasPrefix(o.SysUser, "_") {
			o.SysUser = "_" + o.SysUser
		}
		if err := ensureSysUser(o.SysUser); err != nil {
			return "", err
		}
		if o.ConfigPath != "" {
			_ = exec.Command("chown", "-R", o.SysUser+":"+o.SysUser, filepath.Dir(o.ConfigPath)).Run()
		}
	}
	if err := os.MkdirAll(filepath.Dir(plist), 0o755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(log), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(plist, []byte(plistXML(o, log, os.Geteuid() == 0)), 0o644); err != nil {
		return "", err
	}
	if os.Geteuid() == 0 {
		_ = exec.Command("chown", "root:wheel", plist).Run()
		if f, err := os.OpenFile(log, os.O_CREATE, 0o644); err == nil {
			_ = f.Close()
			if o.SysUser != "" {
				_ = exec.Command("chown", o.SysUser+":"+o.SysUser, log).Run()
			}
		}
	}
	if o.NoStart {
		return fmt.Sprintf("launchd 服务已写好 plist（未加载：%s；launchctl bootstrap %s 拉起）", plist, domain), nil
	}
	if exec.Command("launchctl", "print", domain+"/"+o.label()).Run() == nil {
		if err := exec.Command("launchctl", "kickstart", "-k", domain+"/"+o.label()).Run(); err != nil {
			return "", fmt.Errorf("plist 已写好但重启失败：%w（手工 launchctl kickstart -k %s/%s）", err, domain, o.label())
		}
		return fmt.Sprintf("launchd 服务已重启，新二进制生效（日志 %s）", log), nil
	}
	if err := exec.Command("launchctl", "bootstrap", domain, plist).Run(); err != nil {
		return "", fmt.Errorf("plist 写好（%s）但加载失败：%w（手工 launchctl bootstrap %s %s）", plist, err, domain, plist)
	}
	return fmt.Sprintf("launchd 服务已加载启动（日志 %s；查状态 launchctl print %s/%s）", log, domain, o.label()), nil
}

func uninstall(o Opts) (string, error) {
	plist, domain, _ := launchdPaths(o)
	if _, err := os.Stat(plist); err != nil {
		return "", fmt.Errorf("没找到 %s——本来就没装过", plist)
	}
	_ = exec.Command("launchctl", "bootout", domain+"/"+o.label()).Run()
	if err := os.Remove(plist); err != nil {
		return "", err
	}
	return fmt.Sprintf("已停用并删掉 %s（二进制和配置没动）", o.label()), nil
}

func status(o Opts) string {
	plist, domain, _ := launchdPaths(o)
	parts := []string{}
	if _, err := os.Stat(plist); err == nil {
		parts = append(parts, "plist 已写")
	}
	if exec.Command("launchctl", "print", domain+"/"+o.label()).Run() == nil {
		parts = append(parts, "已加载")
	}
	if len(parts) == 0 {
		return "未安装"
	}
	return strings.Join(parts, "，")
}
