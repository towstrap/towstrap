//go:build windows

package client

import "os/exec"

// setPgid Windows 没有 Unix 意义的进程组——杀整棵树要 Job Object，
// 暂不做（文档里写明 Windows 下超时只杀 shell 主进程）。
func setPgid(cmd *exec.Cmd) {}

// killProc Windows 下只能杀主进程；它的子进程可能继续跑（已知的
// 平台差异，技术手册有写）。
func killProc(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
