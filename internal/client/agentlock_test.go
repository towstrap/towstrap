//go:build !windows

package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 新实例接管必须杀掉持锁的旧进程——不然两个 agent 顶同一个 token 会在
// 服务端反复互相蹬下线。flock 是进程级的，所以用一个真辅助进程占锁。
func TestAgentLockTakeover(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfg := Config{Server: "wss://x", ID: "test"}
	lockPath := agentLockPath(cfg)
	if !filepath.IsAbs(lockPath) || !strings.HasPrefix(lockPath, dir) {
		t.Fatalf("锁路径不在 HOME 下：%s", lockPath)
	}

	// 辅助进程扮「旧 agent」：占锁睡死
	helper := exec.Command(os.Args[0], "-test.run=TestLockHelper")
	helper.Env = append(os.Environ(), "TOWSTRAP_LOCK_HELPER=1", "HOME="+dir)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	defer helper.Process.Kill()

	// 等它把 pid 写进锁文件（占锁成功）
	deadline := time.Now().Add(5 * time.Second)
	for readPID(lockPath) <= 0 {
		if time.Now().After(deadline) {
			t.Fatal("辅助进程没占上锁")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 本进程接管：应杀掉辅助进程并抢到锁
	release, err := acquireAgentLock(cfg)
	if err != nil {
		t.Fatalf("接管失败：%v", err)
	}
	defer release()
	done := make(chan struct{})
	go func() { _ = helper.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("旧进程没有被杀")
	}
}

// TestLockHelper 辅助测试进程：环境变量开门才干活，占上 agent 锁就睡。
func TestLockHelper(t *testing.T) {
	if os.Getenv("TOWSTRAP_LOCK_HELPER") != "1" {
		return
	}
	release, err := acquireAgentLock(Config{Server: "wss://x", ID: "test"})
	if err != nil {
		os.Exit(1)
	}
	defer release()
	time.Sleep(30 * time.Second)
}
