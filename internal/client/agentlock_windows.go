//go:build windows

package client

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/windows"
)

// acquireAgentLock 抢命名 mutex 的单实例锁；锁被占说明旧 agent 还活着，
// 读 pidfile 把它杀了再抢回来（「启动新的关闭旧的」）。返回解锁函数。
func acquireAgentLock(cfg Config) (func(), error) {
	lockPath := agentLockPath(cfg)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	// Global\ 跨会话（Session0 的服务和桌面任务互相看得见）；普通用户
	// 建不了 Global 对象时退回 Local\——同上下文互相还挡得住，跨上下
	// 文的接管只能靠 pidfile。
	name, err := windows.UTF16PtrFromString(`Global\TowStrap-` + agentTag(cfg))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateMutex(nil, true, name)
	if err == windows.ERROR_ACCESS_DENIED {
		name, _ = windows.UTF16PtrFromString(`Local\TowStrap-` + agentTag(cfg))
		h, err = windows.CreateMutex(nil, true, name)
	}
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return nil, err
	}
	if err == windows.ERROR_ALREADY_EXISTS {
		// 已有人持锁：杀旧持有者再等锁空。CreateMutex 给了我们对同一
		// mutex 的句柄，WaitForSingleObject 拿到才算真正持锁。
		killLockHolder(lockPath)
		if _, werr := windows.WaitForSingleObject(h, 8000); werr != nil {
			// 第一次没抢到：pidfile 可能写的慢/被换了，再杀一轮
			killLockHolder(lockPath)
			if _, werr := windows.WaitForSingleObject(h, 8000); werr != nil {
				_ = windows.CloseHandle(h)
				return nil, fmt.Errorf("旧的 agent 进程没退干净，接管失败")
			}
		}
	}
	if err := os.WriteFile(lockPath, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		_ = windows.ReleaseMutex(h)
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return func() {
		_ = windows.ReleaseMutex(h)
		_ = windows.CloseHandle(h)
		_ = os.Remove(lockPath)
	}, nil
}

// killLockHolder 按 lock 文件里的 pid 杀旧 agent。pid 复用理论上可能杀错
// 进程，但只有 mutex 真被占着才会走到这——占锁的就是 agent 自己。
func killLockHolder(lockPath string) {
	pid := readPID(lockPath)
	if pid <= 0 || pid == os.Getpid() {
		return
	}
	p, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return
	}
	slog.Info("单实例接管：关闭旧的 agent 进程", "pid", pid)
	defer windows.CloseHandle(p)
	_ = windows.TerminateProcess(p, 1)
	_, _ = windows.WaitForSingleObject(p, 3000)
}

// agentLockPath：Windows 上锁文件放 %ProgramData%\TowStrap\——服务跑
// SYSTEM（Session 0）、手动跑/任务跑在用户会话，用户目录互不相通，
// ProgramData 谁都能读写，跨上下文接管才能找到对方的 pid。
func agentLockPath(cfg Config) string {
	if dir := os.Getenv("ProgramData"); dir != "" {
		return filepath.Join(dir, "TowStrap", "agent-"+agentTag(cfg)+".lock")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".towstrap", "agent-"+agentTag(cfg)+".lock")
	}
	return filepath.Join(os.TempDir(), "towstrap-agent-"+agentTag(cfg)+".lock")
}
