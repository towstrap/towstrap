package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"ws2ssh/internal/proto"
)

func TestAgentHello(t *testing.T) {
	helloCh := make(chan proto.Msg, 1)
	sawToken := make(chan string, 1)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawToken <- r.Header.Get("X-Agent-Token")
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, raw, err := c.ReadMessage()
		if err != nil {
			return
		}
		var hello proto.Msg
		if err := json.Unmarshal(raw, &hello); err != nil {
			return
		}
		helloCh <- hello
		// 挂着等 agent 被关掉
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	go func() {
		_ = ConnectOnce(Config{
			ID:         "box",
			Server:     "ws://" + strings.TrimPrefix(srv.URL, "http://"),
			AgentToken: "tok",
			Shell:      "/bin/bash",
		})
	}()

	select {
	case tok := <-sawToken:
		if tok != "tok" {
			t.Fatalf("token header = %q", tok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent 没有连上来")
	}

	select {
	case hello := <-helloCh:
		if hello.T != proto.TypeHello || hello.Name != "box" {
			t.Fatalf("%#v", hello)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没收到 hello")
	}
}

func TestDefaultID(t *testing.T) {
	if !proto.ValidName(DefaultID()) {
		t.Fatalf("DefaultID() = %q 不合法", DefaultID())
	}
}

func TestBackoff(t *testing.T) {
	cases := []struct {
		cur, want time.Duration
	}{
		{2 * time.Second, 4 * time.Second},
		{4 * time.Second, 8 * time.Second},
		{16 * time.Second, 30 * time.Second}, // 32s 封顶到 30s
		{30 * time.Second, 30 * time.Second},
	}
	for _, c := range cases {
		if got := backoff(c.cur); got != c.want {
			t.Errorf("backoff(%v) = %v, want %v", c.cur, got, c.want)
		}
	}
}
