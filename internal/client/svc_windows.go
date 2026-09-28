//go:build windows

package client

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"

	"golang.org/x/sys/windows/svc"
)

// IsWindowsService 报告进程是不是被服务控制管理器（SCM）拉起的——是的话
// agent 必须走 svc.Run 跟 SCM 握手（报 Running/接 Stop），不然 SCM 会把
// 服务标记为「启动失败」并杀掉进程。
func IsWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// RunService 把 agent 包成 Windows 服务跑：SCM 拉起进程 → svc.Run 握手 →
// Execute 里跑 Run 主循环；SCM 发 Stop/Shutdown 时 Execute 返回 → svc.Run
// 返回 → 进程退出。Run 自身没有取消口，SCM 停服务时直接让进程死收尾。
func RunService(cfg Config) int {
	// 服务没有控制台，stderr/slog 全丢——重定向到共享日志文件，崩溃至少
	// 留得下遗言。
	if f, err := openServiceLog(); err == nil {
		slog.SetDefault(slog.New(slog.NewTextHandler(f, nil)))
		os.Stderr = f
	}
	h := &svcHandler{cfg: cfg, done: make(chan error, 1)}
	if err := svc.Run(serviceName(), h); err != nil {
		slog.Error("svc.Run 失败", "err", err)
		return 1
	}
	// svc.Run 返回 = Execute 已交回控制权：SCM 停我们是正常退出（0）；
	// agent 自己死掉时 Execute 已把 code 置 1——进程以非零退出，SCM 按
	// 失败计，恢复策略拉起新实例。
	return int(h.code.Load())
}

func serviceName() string { return "towstrap" }

func openServiceLog() (*os.File, error) {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "TowStrap")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(dir, "towstrap-svc.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}

type svcHandler struct {
	cfg  Config
	done chan error
	code atomic.Int32 // agent 自己死掉时置 1，进程退出码=SCM 失败信号
}

func (h *svcHandler) Execute(_ []string, r <-chan svc.ChangeRequest,
	st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	go func() { h.done <- Run(h.cfg) }()
	st <- svc.Status{State: svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-h.done:
			// agent 自己退了（配置错、互斥锁被抢、自升级 exit(1) 等）——
			// 进程非零退出，SCM 的恢复策略把服务拉回来。
			if err != nil {
				slog.Error("agent", "err", err)
			}
			h.code.Store(1)
			return false, 1
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Run 没有取消口——Execute 返回后 svc.Run 收尾、main
				// 返回、进程退出，Run 的 goroutine 随进程一起死。
				st <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}
