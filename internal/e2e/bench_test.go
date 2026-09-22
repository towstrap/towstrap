package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"towstrap/internal/client"
)

// TestCapacityBench 容量基准：N 台 agent 上线 + N 个并发 SSH 会话，量每个单元的
// 内存/goroutine/fd 开销，用来外推服务器容量。默认跳过：
//
//	TOWSTRAP_BENCH=1 go test ./internal/e2e/ -run TestCapacityBench -v -timeout 20m
func TestCapacityBench(t *testing.T) {
	const n = 300
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	g0 := runtime.NumGoroutine()
	f0 := countFDs(t)

	srv, httpPort, sshPort, users := startServer(t)

	tokens := make([]string, 0, n)
	for i := 0; i < n; i++ {
		acct, err := users.Add(fmt.Sprintf("u%03d", i), "benchpw12345", nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, acct.Machines[0].Token)
	}
	t.Logf("建 %d 个账号耗时见上（bcrypt 主导）", n)

	audit := filepath.Join(t.TempDir(), "devnull")
	_ = os.MkdirAll(filepath.Dir(audit), 0o755)
	audit = "/dev/null"

	// n 台机器上线（每台一个 WebSocket，Shell 用 /bin/cat 模拟轻量会话）
	for i, tok := range tokens {
		go func(i int, tok string) {
			_ = client.ConnectOnce(client.Config{
				ID:         fmt.Sprintf("h%03d", i),
				Server:     fmt.Sprintf("ws://127.0.0.1:%d", httpPort),
				AgentToken: tok,
				Shell:      "/bin/cat",
				Quiet:      true,
				AuditLog:   audit,
			})
		}(i, tok)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.Hub.Names()) == n {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(srv.Hub.Names()) != n {
		t.Fatalf("agent 没全上线: %d", len(srv.Hub.Names()))
	}
	runtime.GC()
	var afterAgents runtime.MemStats
	runtime.ReadMemStats(&afterAgents)
	g1 := runtime.NumGoroutine()
	f1 := countFDs(t)

	// n 个并发 SSH 会话（并行拨号，限并发 50 免得把握手本身压垮）
	var mu sync.Mutex
	var ok int
	sem := make(chan struct{}, 50)
	t0 := time.Now()
	for i := 0; i < n; i++ {
		go func(i int) {
			cfg := &gossh.ClientConfig{
				User:            fmt.Sprintf("u%03d", i),
				Auth:            []gossh.AuthMethod{gossh.Password("benchpw12345")},
				HostKeyCallback: gossh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			}
			// 槽只管拨号阶段的并发；建好后就还回去，会话本身挂住不放
			sem <- struct{}{}
			var setupErr error
			c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
			if err != nil {
				setupErr = fmt.Errorf("dial: %w", err)
			} else {
				s, err := c.NewSession()
				if err == nil {
					err = s.RequestPty("xterm", 24, 80, gossh.TerminalModes{})
				}
				if err == nil {
					err = s.Shell()
				}
				if err != nil {
					setupErr = err
				}
			}
			<-sem
			if setupErr != nil {
				t.Errorf("会话 %d: %v", i, setupErr)
				return
			}
			mu.Lock()
			ok++
			mu.Unlock()
			// 挂住不放（函数返回不清理，故意持有）
			select {}
		}(i)
	}
	// 等会话建满或超时
	d2 := time.Now().Add(120 * time.Second)
	for time.Now().Before(d2) {
		mu.Lock()
		done := ok
		mu.Unlock()
		if done == n {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	mu.Lock()
	t.Logf("%d/%d 个 SSH 会话建立，耗时 %s", ok, n, time.Since(t0).Round(time.Millisecond))
	mu.Unlock()
	if ok < n {
		t.Fatalf("会话没建满: %d", ok)
	}

	time.Sleep(3 * time.Second) // 等输出 goroutine 都跑稳
	runtime.GC()
	var afterSessions runtime.MemStats
	runtime.ReadMemStats(&afterSessions)
	g2 := runtime.NumGoroutine()
	f2 := countFDs(t)

	mb := func(b uint64) string { return strconv.FormatUint(b/1024/1024, 10) + "MB" }
	t.Logf("基线: heap=%s goroutines=%d", mb(base.HeapAlloc), g0)
	t.Logf("+%d agent(WS): heap=%s(+%s) goroutines=%d(+%d) fds=%d(+%d)",
		n, mb(afterAgents.HeapAlloc), mb(afterAgents.HeapAlloc-base.HeapAlloc), g1, g1-g0, f1, f1-f0)
	t.Logf("+%d SSH 会话: heap=%s(+%s) goroutines=%d(+%d) fds=%d(+%d)",
		n, mb(afterSessions.HeapAlloc), mb(afterSessions.HeapAlloc-afterAgents.HeapAlloc), g2, g2-g1, f2, f2-f1)
	t.Logf("平均: 每台在线 agent ≈ %dKB，每个活跃 SSH 会话(含 agent 侧 PTY) ≈ %dKB",
		(afterAgents.HeapAlloc-base.HeapAlloc)/uint64(n)/1024,
		(afterSessions.HeapAlloc-afterAgents.HeapAlloc)/uint64(n)/1024)
}

func countFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Logf("读不了 /dev/fd: %v", err)
		return 0
	}
	// 列目录本身占一个 fd
	return len(entries) - 1
}
