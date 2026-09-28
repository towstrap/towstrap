//go:build windows

package selfupdate

import "golang.org/x/sys/windows/svc"

// runningAsService 报告本进程是不是被 SCM 拉起的——服务形态下 SCM 的
// stop 会连自己一起杀，重启只能走「退出让恢复策略拉起」。
func runningAsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}
