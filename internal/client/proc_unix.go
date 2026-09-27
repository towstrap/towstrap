//go:build !windows

package client

import (
	"os/exec"
	"syscall"
	"time"
)

// setPgid 让子进程自立进程组：杀会话时按组杀，shell 死了它正在跑的
// 前台命令不能漏网成孤儿（不然「超时已杀」是假的——rm/编译还在跑）。
// 用户真想要脱离会话的守护进程用 setsid 起，那是标准做法。
func setPgid(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProc 杀整个进程组；组没了（进程已退）退回杀单个进程。和
// killSession 一个路数：先 SIGHUP 给个收尾窗口（shell -c 的命令行
// 收 HUP 会写历史/清理现场再走），300ms 后 SIGKILL 兜底。
func killProc(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGHUP)
	time.Sleep(killGrace)
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
