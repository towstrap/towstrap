//go:build windows

package service

import (
	"fmt"
	"os/exec"
	"strings"
)

// installSchtasks 注册「登录自起」计划任务（install.ps1 同款：
// /sc onlogon /rl limited）。Windows 的服务要服务控制管理器注册，
// 普通进程用计划任务最省事。
func install(o Opts) (string, error) {
	tr := fmt.Sprintf(`"%s"`, o.Exe)
	for _, a := range o.args() {
		tr += fmt.Sprintf(` "%s"`, a)
	}
	if out, err := exec.Command("schtasks", "/create", "/tn", o.unitName(),
		"/sc", "onlogon", "/rl", "limited", "/f", "/tr", tr).CombinedOutput(); err != nil {
		return "", fmt.Errorf("计划任务注册失败：%w（%s）", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("schtasks", "/run", "/tn", o.unitName()).Run()
	return fmt.Sprintf("计划任务 %s 已注册并拉起（登录时自动启动）", o.unitName()), nil
}

func uninstall(o Opts) (string, error) {
	if exec.Command("schtasks", "/query", "/tn", o.unitName()).Run() != nil {
		return "", fmt.Errorf("没找到计划任务 %s——本来就没装过", o.unitName())
	}
	_ = exec.Command("schtasks", "/end", "/tn", o.unitName()).Run()
	if out, err := exec.Command("schtasks", "/delete", "/tn", o.unitName(), "/f").CombinedOutput(); err != nil {
		return "", fmt.Errorf("删除失败：%w（%s）", err, strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("已删掉计划任务 %s（二进制和配置没动）", o.unitName()), nil
}

func status(o Opts) string {
	if exec.Command("schtasks", "/query", "/tn", o.unitName()).Run() != nil {
		return "未安装"
	}
	out, _ := exec.Command("schtasks", "/query", "/tn", o.unitName(), "/fo", "list", "/v").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Status") || strings.Contains(line, "状态") {
			return "已注册 " + strings.TrimSpace(line)
		}
	}
	return "已注册"
}
