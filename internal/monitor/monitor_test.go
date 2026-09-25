package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// receiver 是假监控接收端：升级 WS 后把每条文本帧解成 map 存起来。
// closeConns 为 true 时每收满几条就主动断开，用来测重连。
type receiver struct {
	srv *httptest.Server

	mu     sync.Mutex
	frames []map[string]any
	conns  int

	closeAfter int // >0 时每收这么多帧就断开连接
}

var up = websocket.Upgrader{}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := up.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.conns++
		r.mu.Unlock()
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
				n := len(r.frames)
				ca := r.closeAfter
				r.mu.Unlock()
				if ca > 0 && n >= ca {
					_ = conn.Close()
					return
				}
			}
		}()
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) url() string { return "ws" + r.srv.URL[len("http"):] }

// waitFrame 等到出现满足条件的帧，超时 fail。返回帧本体。
func (r *receiver) waitFrame(t *testing.T, pred func(map[string]any) bool, what string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, f := range r.frames {
			if pred(f) {
				r.mu.Unlock()
				return f
			}
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("没等到帧: %s", what)
	return nil
}

func (r *receiver) connCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns
}

func TestMonitorPushEventAndMetrics(t *testing.T) {
	r := newReceiver(t)
	m := New(Config{URL: r.url(), Interval: 50 * time.Millisecond, Buffer: 16})
	m.SetSnapshot(func() map[string]any { return map[string]any{"agents_online": 3} })
	m.Start()
	defer m.Close()

	m.Emit("AUTH-OK", "user", "alice+build", "ip", "1.2.3.4")

	hello := r.waitFrame(t, func(f map[string]any) bool { return f["type"] == "hello" }, "hello")
	if hello["ver"] == "" || hello["name"] == "" {
		t.Fatalf("hello 帧缺字段: %v", hello)
	}
	ev := r.waitFrame(t, func(f map[string]any) bool { return f["type"] == "event" && f["event"] == "AUTH-OK" }, "event")
	kv, _ := ev["kv"].(map[string]any)
	if kv["user"] != "alice+build" || kv["ip"] != "1.2.3.4" {
		t.Fatalf("event 帧 kv 不对: %v", ev)
	}
	mt := r.waitFrame(t, func(f map[string]any) bool { return f["type"] == "metrics" }, "metrics")
	mm, _ := mt["metrics"].(map[string]any)
	if mm["agents_online"] != float64(3) {
		t.Fatalf("metrics 帧内容不对: %v", mt)
	}
}

func TestMonitorDropWhenReceiverDown(t *testing.T) {
	// 接收端不存在：队列很快填满，之后 Emit 丢帧计数，但永不阻塞。
	m := New(Config{URL: "ws://127.0.0.1:1/none", Buffer: 8})
	m.Start()
	defer m.Close()

	start := time.Now()
	for i := 0; i < 200; i++ {
		m.Emit("E", "i", "x")
	}
	if time.Since(start) > time.Second {
		t.Fatal("Emit 阻塞了")
	}
	// 连不上时队列里的帧发不出去：8 条在队列，其余全丢。
	deadline := time.Now().Add(3 * time.Second)
	for m.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if m.Dropped() == 0 {
		t.Fatal("接收端挂了应该有丢帧计数")
	}
}

func TestMonitorReconnect(t *testing.T) {
	r := newReceiver(t)
	r.closeAfter = 1 // 收一帧（hello）就踢掉，逼它重连
	m := New(Config{URL: r.url(), Interval: time.Hour, Buffer: 16})
	m.Start()
	defer m.Close()

	r.waitFrame(t, func(f map[string]any) bool { return f["type"] == "hello" }, "first hello")
	// 等它重连上第二次（第二条连接也各收一帧后被踢，但至少证明会重连）
	deadline := time.Now().Add(10 * time.Second)
	for r.connCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if r.connCount() < 3 {
		t.Fatalf("断线后没有自动重连，conns=%d", r.connCount())
	}
}

func TestMonitorNilSafe(t *testing.T) {
	var m *Monitor
	m.Emit("X", "k", "v")
	m.Start()
	m.Close()
	if m.Dropped() != 0 {
		t.Fatal("nil monitor 不该有状态")
	}
}
