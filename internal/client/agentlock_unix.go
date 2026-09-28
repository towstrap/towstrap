//go:build !windows

package client

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// agentLockPath：Unix 上锁文件放 ~/.towstrap/——agent 的用户身份统一
// （没有 Windows 那种 Session0/桌面会话跨界问题）。
func agentLockPath(cfg Config) string {
	dir, err := os.UserHomeDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, ".towstrap", "agent-"+agentTag(cfg)+".lock")
}

// acquireAgentLock 抢锁文件的 flock 锁；拿不到说明旧 agent 还活着，读
// 文件里的 pid 杀掉再抢（「启动新的关闭旧的」）。flock 随进程死自动
// 释放，持锁进程退出后新实例一次就能抢到。返回解锁函数。
func acquireAgentLock(cfg Config) (func(), error) {
	lockPath := agentLockPath(cfg)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 5; i++ {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			if err := f.Truncate(0); err == nil {
				_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
				_ = f.Sync()
			}
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		// 锁被占：文件里就是持锁者的 pid，杀掉后等内核放锁再抢。
		if pid := readPID(lockPath); pid > 0 && pid != os.Getpid() {
			slog.Info("单实例接管：关闭旧的 agent 进程", "pid", pid)
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = f.Close()
	return nil, fmt.Errorf("旧的 agent 进程没退干净，接管失败（锁 %s）", lockPath)
}
