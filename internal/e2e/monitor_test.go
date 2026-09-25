package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/towstrap/towstrap/internal/monitor"
	"github.com/towstrap/towstrap/internal/server"
)

// monReceiver 是假的旁路监控接收端：接受 WS 连接，把每条文本帧存起来。
type monReceiver struct {
	srv *httptest.Server

	mu     sync.Mutex
	frames []map[string]any
}

func newMonReceiver(t *testing.T) *monReceiver {
	t.Helper()
	r := &monReceiver{}
	up := websocket.Upgrader{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := up.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			for {
				_, raw, err := conn.ReadMessage()
				if err != nil {
					return
				}
				var f map[string]any
				if json.Unmarshal(raw, &f) != nil {
					continue
				}
				r.mu.Lock()
				r.frames = append(r.frames, f)
				r.mu.Unlock()
			}
		}()
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *monReceiver) url() string { return "ws" + r.srv.URL[len("http"):] }

func (r *monReceiver) waitEvent(t *testing.T, event, key, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, f := range r.frames {
			if f["type"] == "event" && f["event"] == event {
				if key == "" {
					r.mu.Unlock()
					return f
				}
				if kv, _ := f["kv"].(map[string]any); kv[key] == want {
					r.mu.Unlock()
					return f
				}
			}
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("没等到监控事件 %s %s=%s", event, key, want)
	return nil
}

func (r *monReceiver) waitMetrics(t *testing.T, key string, min float64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, f := range r.frames {
			if f["type"] != "metrics" {
				continue
			}
			if mm, _ := f["metrics"].(map[string]any); mm != nil {
				if v, _ := mm[key].(float64); v >= min {
					r.mu.Unlock()
					return
				}
			}
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("没等到 metrics.%s >= %v", key, min)
}

// TestMonitorPush 旁路监控端到端：server 主动把审计事件和指标推给接收端。
// 事件要和本地审计日志同源同内容；metrics 里要有在线 agent 数和认证计数。
func TestMonitorPush(t *testing.T) {
	r := newMonReceiver(t)
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{
		Monitor: monitor.Config{URL: r.url(), Interval: 100 * time.Millisecond, Buffer: 64},
	})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	sshEcho(t, sshPort, "alice", "alicepw123", "echo mon-marker")

	r.waitEvent(t, "AGENT-CONNECT", "id", "alice+default")
	r.waitEvent(t, "AUTH-OK", "user", "alice")
	r.waitEvent(t, "SESSION-START", "", "")
	r.waitMetrics(t, "agents_online", 1)
	r.waitMetrics(t, "auth_ok", 1)
}

// TestMonitorReceiverDown 接收端从头到尾不存在：server 照常工作，
// 事件丢帧只计数。旁路的第一要义——监控挂了不能拖累主流程。
func TestMonitorReceiverDown(t *testing.T) {
	// 找一个没人监听的端口当接收端
	dead := freePort(t)
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{
		Monitor: monitor.Config{
			URL:      fmt.Sprintf("ws://127.0.0.1:%d/mon", dead),
			Interval: 100 * time.Millisecond, Buffer: 8,
		},
	})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	// 主流程不受影响：SSH 正常登录跑命令。多跑几轮让事件数超过队列
	// 容量（每条 SESSION-START/END/AUTH-OK 都算），丢帧才会发生。
	for i := 0; i < 5; i++ {
		sshEcho(t, sshPort, "alice", "alicepw123", "echo still-works")
	}

	deadline := time.Now().Add(3 * time.Second)
	for srv.MonitorDropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if srv.MonitorDropped() == 0 {
		t.Fatal("接收端不存在时应有丢帧计数")
	}
}
