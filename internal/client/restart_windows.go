//go:build windows

package client

import "log/slog"

// restartSelf：Windows 没有 exec 语义，且运行中的 exe 被锁定换不掉
// （selfupdate 的替换多半已经先失败了）。新文件就位时提醒手动重启；
// 注册成计划任务的由 restartManaged 拉起，走不到这。
func restartSelf() {
	slog.Warn("新二进制已就位：请重启 agent 进程生效（或注册成计划任务让它自动拉起）")
}
