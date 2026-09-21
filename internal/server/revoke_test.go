package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"ws2ssh/internal/accounts"
	"ws2ssh/internal/allow"
	"ws2ssh/internal/totp"
)

// TestTOTPAccountPasswordAttemptKeepsGuard 回归高危 1：TOTP 账号走纯密码通道
// 不能清零 OTP 的失败计数，否则攻击者拿泄露的密码可以无限重置限速。
func TestTOTPAccountPasswordAttemptKeepsGuard(t *testing.T) {
	dir := t.TempDir()
	users, err := accounts.Open(filepath.Join(dir, "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Close()
	if _, err := users.Add("alice", "alicepw123", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	secret, _ := totp.Generate("ws2ssh", "alice")
	if err := users.EnrollTOTP("alice", secret, 0); err != nil {
		t.Fatal(err)
	}
	ips, err := allow.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Users: users, AllowIPs: ips})
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5555}

	// 猜错 4 次 OTP
	for i := 0; i < 4; i++ {
		s.guard.fail("alice", "1.2.3.4")
	}
	// 用偷来的正确密码走 password 通道：必须被拒，且不能碰计数
	if s.sshAuthOK("alice", "alicepw123", addr) {
		t.Fatal("TOTP 账号不应通过纯密码")
	}
	// 再失败一次就到阈值：如果计数被清过，这里就不会锁
	s.guard.fail("alice", "1.2.3.4")
	if s.guard.allowed("alice", "1.2.3.4") {
		t.Fatal("密码尝试不应清零 OTP 失败计数（高危 1 回归）")
	}
	// 锁定后连正确密码的 kbd 通道也进不来
	if s.verifyPassword("alice", "alicepw123", addr, "test") {
		t.Fatal("锁定期内不应通过任何密码校验")
	}
}

// TestNormalAccountPasswordResetsGuard 普通账号保持原语义：登录成功清零。
func TestNormalAccountPasswordResetsGuard(t *testing.T) {
	dir := t.TempDir()
	users, err := accounts.Open(filepath.Join(dir, "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Close()
	if _, err := users.Add("bob", "bobpw12345", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	ips, err := allow.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Users: users, AllowIPs: ips})
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5555}

	for i := 0; i < 4; i++ {
		s.guard.fail("bob", "1.2.3.4")
	}
	if !s.sshAuthOK("bob", "bobpw12345", addr) {
		t.Fatal("正确密码应通过")
	}
	if !s.guard.allowed("bob", "1.2.3.4") {
		t.Fatal("成功登录应清零失败计数")
	}
}

// wsAttach 起一个把 WS 交给 hub 的测试服务器：每条连接按 query 里的
// name/token 注册，然后挂住直到被服务端关闭。返回客户端连接。
func wsAttach(t *testing.T, h *Hub) (*httptest.Server, func(name, token string) *websocket.Conn) {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		h.Attach(r.URL.Query().Get("name"), r.URL.Query().Get("token"), conn)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	dial := func(name, token string) *websocket.Conn {
		t.Helper()
		url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/?name=" + name + "&token=" + token
		c, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return srv, dial
}

func waitAgentCount(t *testing.T, h *Hub, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.Names()) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("hub 里 agent 数 = %d, want %d", len(h.Names()), want)
}

func TestPruneInvalid(t *testing.T) {
	h := NewHub(0)
	srv, dial := wsAttach(t, h)
	defer srv.Close()

	keep := dial("keep", "t1")
	defer keep.Close()
	gone := dial("gone", "t2")
	defer gone.Close()
	waitAgentCount(t, h, 2)

	if revoked := h.PruneInvalid(func(name, token string) bool { return name == "keep" && token == "t1" }); len(revoked) != 1 {
		t.Fatalf("应断开 1 台, got %d", len(revoked))
	}
	// 被吊销的那条应被服务端关闭
	_ = gone.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := gone.ReadMessage(); err == nil {
		t.Fatal("被吊销的连接应被关闭")
	}
	// 有效的那条不受影响
	if err := keep.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("有效连接被误伤: %v", err)
	}
	// hub 里 stale 那条最终会因 readLoop 退出被 Detach（这里手动确认逻辑层面：
	// PruneInvalid 之后 hub 里仍有一个 entry 指向已关闭的连接是正常的，
	// handleAgent 的 readLoop 会负责 Detach。此处只验证关闭行为。）
}

// TestRevokeStaleAgents 巡检端到端（单元级）：token 换掉后，下一次巡检断开旧连接。
func TestRevokeStaleAgents(t *testing.T) {
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

	srv, dial := wsAttach(t, s.Hub)
	defer srv.Close()
	c := dial("alice", acct.Token)
	defer c.Close()
	waitAgentCount(t, s.Hub, 1)

	if revoked := s.revokeStaleAgents(); len(revoked) != 0 {
		t.Fatalf("凭据有效不应断开, got %d", len(revoked))
	}
	if _, err := users.RegenToken("alice"); err != nil {
		t.Fatal(err)
	}
	if revoked := s.revokeStaleAgents(); len(revoked) != 1 {
		t.Fatalf("换 token 后应断开旧连接, got %d", len(revoked))
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("旧连接应被服务端关闭")
	}

	// 账号被删同理
	if _, err := users.Add("bob", "bobpw12345", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	b, ok := users.Get("bob")
	if !ok {
		t.Fatal("bob 不存在")
	}
	c2 := dial("bob", b.Token)
	defer c2.Close()
	waitAgentCount(t, s.Hub, 2) // alice 的连接还挂在 hub 里（已关闭但未 Detach），加 bob 共 2
	if err := users.Remove("bob"); err != nil {
		t.Fatal(err)
	}
	if revoked := s.revokeStaleAgents(); len(revoked) < 1 {
		t.Fatalf("删号后应断开对应连接, got %d", len(revoked))
	}
}
