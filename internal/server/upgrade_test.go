package server

import (
	"errors"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/towstrap/towstrap/internal/proto"
)

// waitUpgrade 等到一条 upgrade 帧（非 upgrade 帧跳过）；超时算没收。
func waitUpgrade(t *testing.T, c *websocket.Conn, timeout time.Duration) (proto.Msg, bool) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	for {
		_, raw, err := c.ReadMessage()
		if err != nil {
			return proto.Msg{}, false
		}
		m, err := proto.Decode(raw)
		if err == nil && m.T == proto.TypeUpgrade {
			return m, true
		}
	}
}

func TestNotifyUpgradeTargetsStale(t *testing.T) {
	h := NewHub(0)
	srv, dial := wsAttach(t, h)
	defer srv.Close()

	stale := dial("old", "t1", "0.1.0")    // 落后 → 应收到
	fresh := dial("fresh", "t2", "99.0.0") // 已是最新 → 不该收
	none := dial("ancient", "t3", "")      // 没报版本的旧 agent → 也推（按 0.0.0 算）
	waitAgentCount(t, h, 3)

	h.NotifyUpgrade("v0.5.1")

	m, ok := waitUpgrade(t, stale, 2*time.Second)
	if !ok || m.Ver != "v0.5.1" {
		t.Fatalf("落后 agent 应收到升级推送 v0.5.1，实际 %+v ok=%v", m, ok)
	}
	if _, ok := waitUpgrade(t, none, 2*time.Second); !ok {
		t.Fatal("没报版本的旧 agent 也应收到升级推送")
	}
	if _, ok := waitUpgrade(t, fresh, 300*time.Millisecond); ok {
		t.Fatal("已是新版的 agent 不该收到升级推送")
	}
}

func TestCheckLatestOncePushesOnChange(t *testing.T) {
	s := New(Config{})
	srv, dial := wsAttach(t, s.Hub)
	defer srv.Close()
	c := dial("old", "t1", "0.1.0")
	waitAgentCount(t, s.Hub, 1)

	orig := latestTagFunc
	latestTagFunc = func() (string, error) { return "v0.5.1", nil }
	defer func() { latestTagFunc = orig }()

	s.checkLatestOnce()
	if m, ok := waitUpgrade(t, c, 2*time.Second); !ok || m.Ver != "v0.5.1" {
		t.Fatalf("扫描发现新版应推给落后 agent，实际 %+v ok=%v", m, ok)
	}
	// 同一 tag 再来一轮不重复推（不然每轮扫描都骚扰一遍）。
	s.checkLatestOnce()
	if _, ok := waitUpgrade(t, c, 300*time.Millisecond); ok {
		t.Fatal("tag 没变不该重复推送")
	}
	// 扫描失败静默过：旧 tag 留着继续用，服务不炸。
	latestTagFunc = func() (string, error) { return "", errors.New("GitHub 不通") }
	s.checkLatestOnce()
	if tag, _ := s.latestTag.Load().(string); tag != "v0.5.1" {
		t.Fatalf("扫描失败不该清掉已存 tag，实际 %q", tag)
	}
}

func TestMaybePushUpgradeOnAttach(t *testing.T) {
	s := New(Config{})
	s.latestTag.Store("v0.5.1")
	srv, dial := wsAttach(t, s.Hub)
	defer srv.Close()

	// 落后的连进来 → 接入补推
	stale := dial("old", "t1", "0.1.0")
	waitAgentCount(t, s.Hub, 1)
	a, err := s.Hub.Agent("old")
	if err != nil {
		t.Fatal(err)
	}
	s.maybePushUpgrade(a)
	if _, ok := waitUpgrade(t, stale, 2*time.Second); !ok {
		t.Fatal("落后 agent 接入时应立即收到升级提示")
	}
	// 已新的连进来 → 不推
	fresh := dial("new", "t2", "99.0.0")
	waitAgentCount(t, s.Hub, 2)
	a2, _ := s.Hub.Agent("new")
	s.maybePushUpgrade(a2)
	if _, ok := waitUpgrade(t, fresh, 300*time.Millisecond); ok {
		t.Fatal("新版 agent 不该收到升级推送")
	}
}
