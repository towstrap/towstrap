//go:build !windows

package client

import (
	"log/slog"
	"os"
	"syscall"
)

// restartSelf 原地 exec 换新映像：进程保留 PID/argv/环境，内存映像换成
// 磁盘上的新二进制重新执行。只在 selfupdate 的 restartManaged 没接管
// （没注册成 systemd/launchd 服务，比如 nohup/前台跑）时才会走到它——
// 受管服务在那一步已经被拉起重来了。
func restartSelf() {
	exe, err := os.Executable()
	if err != nil {
		slog.Error("取自身路径失败，请手动重启 agent 生效新版", "err", err)
		return
	}
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		slog.Error("原地重启失败，请手动重启 agent 生效新版", "err", err)
	}
}
