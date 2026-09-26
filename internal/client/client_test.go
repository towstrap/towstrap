package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/towstrap/towstrap/internal/proto"
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

// TestChildEnvDropsToken 远程会话的 shell 环境里不能有 agent token。
func TestChildEnvDropsToken(t *testing.T) {
	t.Setenv("TOWSTRAP_AGENT_TOKEN", "tsa-secret")
	hasTerm := false
	for _, kv := range childEnv() {
		if strings.HasPrefix(kv, "TOWSTRAP_AGENT_TOKEN=") {
			t.Fatal("子进程环境不应带 agent token")
		}
		if kv == "TERM=xterm-256color" {
			hasTerm = true
		}
	}
	if !hasTerm {
		t.Fatal("子进程环境应有 TERM")
	}
}

// TestChildEnvDropsMirror 继承来的 TOWSTRAP_MIRROR 不能漏给子进程——镜像
// 标记只应由 mirror 创建路径（startPtyEnv）显式打上，否则 rc 钩子会误判
// 「已在镜像里」而跳过本不该跳的接入。
func TestChildEnvDropsMirror(t *testing.T) {
	t.Setenv("TOWSTRAP_MIRROR", "stale")
	for _, kv := range childEnv() {
		if strings.HasPrefix(kv, "TOWSTRAP_MIRROR=") {
			t.Fatal("子进程环境不应继承 TOWSTRAP_MIRROR")
		}
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

// writeTokenFile 原子写 token 文件：内容带换行、权限 0600、覆盖旧文件、
// 不留临时文件。
func TestWriteTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("tsa-old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeTokenFile(path, "tsa-new-abc"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "tsa-new-abc\n" {
		t.Fatalf("内容不对: %q", raw)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("权限应为 0600: %o", st.Mode().Perm())
	}
	left, err := filepath.Glob(filepath.Join(dir, ".token-*"))
	if err != nil || len(left) != 0 {
		t.Fatalf("临时文件应清干净: %v", left)
	}
}

// tokenState.reloadFrom：文件变了返回 true 且 cur 更新；空文件/读不到/
// 内容没变都不动。
func TestTokenStateReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	ts := &tokenState{cur: "tsa-cur"}

	if ts.reloadFrom(filepath.Join(dir, "nope")) {
		t.Fatal("文件不存在不该换")
	}
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ts.reloadFrom(path) {
		t.Fatal("空文件不该换")
	}
	if err := os.WriteFile(path, []byte("tsa-cur\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ts.reloadFrom(path) {
		t.Fatal("内容没变不该算更新")
	}
	if err := os.WriteFile(path, []byte("  tsa-new \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ts.reloadFrom(path) {
		t.Fatal("新内容应返回 true")
	}
	if ts.get() != "tsa-new" {
		t.Fatalf("cur 应换成新 token: %q", ts.get())
	}
}

// tokenState.fallback：换发半途失败（本地已写新 token、服务端不认）时
// 退回上一个 token 自愈；prev 只退一次，没有 prev 返回 false。
func TestTokenStateFallback(t *testing.T) {
	ts := &tokenState{cur: "tsa-old"}
	ts.set("tsa-new") // 换发：prev=tsa-old, cur=tsa-new
	if ts.get() != "tsa-new" {
		t.Fatalf("set 后 cur 应为新 token: %q", ts.get())
	}
	if !ts.fallback() {
		t.Fatal("有 prev 应回退成功")
	}
	if ts.get() != "tsa-old" {
		t.Fatalf("回退后应拿旧 token: %q", ts.get())
	}
	if ts.fallback() {
		t.Fatal("prev 只退一次——再退该失败，不能在新旧间来回抖")
	}
	// 同值 set 不污染 prev（重试收到同一个新 token 不算再换一次）
	ts.set("tsa-old")
	if ts.fallback() {
		t.Fatal("cur 没变不该产生 prev")
	}
}
