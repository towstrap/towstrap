//go:build !windows

package client

// 非 Windows 没有服务控制管理器，恒为 false。
func IsWindowsService() bool { return false }

// RunService 只有 Windows 才有真身；这里给 main 的统一调用一个编译桩。
func RunService(Config) int { return 1 }
