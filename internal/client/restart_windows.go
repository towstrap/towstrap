//go:build windows

package client

import (
	"log/slog"
	"os"
	"os/exec"
)

// restartSelf：Windows 没有 exec 语义，且运行中的 exe 被锁定换不掉
// （selfupdate 用「挪走再挪入」绕过去了）。重启按托管形态分发：
//   - 服务托管：非零退出 → SCM 恢复策略 3 秒拉起新二进制
//   - 计划任务注册过：先 /run 拉新实例（StopExisting/单实例锁会收掉
//     我们）再退——不能只靠 RestartOnFailure，它只管「正在跑的任务
//     崩了」，手动跑的 agent 退了没人拉。
//   - 都没托管：没人会拉我们——只提醒，别自作主张退出（机器会掉线）。
func restartSelf() {
	if IsWindowsService() {
		slog.Info("服务托管中：进程退出，由服务管理器拉起新版本")
		os.Exit(1)
	}
	if exec.Command("schtasks", "/query", "/tn", "towstrap").Run() == nil {
		if err := exec.Command("schtasks", "/run", "/tn", "towstrap").Run(); err == nil {
			slog.Info("计划任务托管中：新实例已由任务计划器拉起")
			os.Exit(0)
		}
	}
	slog.Warn("新二进制已就位：请重启 agent 进程生效（或 towstrap service install 注册常驻）")
}
