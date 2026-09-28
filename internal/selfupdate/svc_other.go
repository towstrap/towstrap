//go:build !windows

package selfupdate

// 非 Windows 没有服务控制管理器，恒为 false。
func runningAsService() bool { return false }
