package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"towstrap/internal/accounts"
	"towstrap/internal/allow"
	"towstrap/internal/proto"
)

// TestAgentMessageLimit 超过单条消息上限的 agent 输入应被服务端断开，
// 不能拿一条大消息把内存打爆。
func TestAgentMessageLimit(t *testing.T) {
	dir := t.TempDir()
	users, err := accounts.Open(filepath.Join(dir, "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Close()
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ips, err := allow.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Users: users, AllowIPs: ips})
	ts := httptest.NewServer(s.routes())
	defer ts.Close()

	hdr := http.Header{}
	hdr.Set("X-Agent-Token", acct.Machines[0].Token)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/agent", hdr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 正常 hello：挂上去
	if err := c.WriteMessage(websocket.TextMessage, proto.Msg{T: proto.TypeHello, Name: "h1"}.Bytes()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !s.Hub.Has("alice+default") {
		time.Sleep(20 * time.Millisecond)
	}
	if !s.Hub.Has("alice+default") {
		t.Fatal("agent 没挂上")
	}

	// 超限消息：服务端应关闭连接
	big := make([]byte, proto.MaxMessageBytes+1024)
	for i := range big {
		big[i] = 'a'
	}
	_ = c.WriteMessage(websocket.TextMessage, big)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("超限消息应导致连接被关闭")
	}
}
