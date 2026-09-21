package e2e

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ws2ssh/internal/accounts"
	"ws2ssh/internal/client"
	"ws2ssh/internal/server"
	"ws2ssh/internal/totp"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// startServer 起一个空账号表的服务器，测试里自己加账号。
func startServer(t *testing.T) (srv *server.Server, httpPort, sshPort int, users *accounts.Store) {
	t.Helper()
	return startServerOpt(t, server.Config{})
}

func startServerOpt(t *testing.T, opt server.Config) (srv *server.Server, httpPort, sshPort int, users *accounts.Store) {
	t.Helper()
	httpPort = freePort(t)
	sshPort = freePort(t)
	dir := t.TempDir()
	users, err := accounts.Open(filepath.Join(dir, "users.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	opt.HTTPAddr = fmt.Sprintf("127.0.0.1:%d", httpPort)
	opt.SSHAddr = fmt.Sprintf("127.0.0.1:%d", sshPort)
	opt.HostKeyPath = filepath.Join(dir, "host_key")
	opt.Users = users
	srv = server.New(opt)
	go func() { _ = srv.Run() }()

	scheme := "http"
	client := http.DefaultClient
	if opt.TLS {
		scheme = "https"
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("%s://127.0.0.1:%d/health", scheme, httpPort))
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return srv, httpPort, sshPort, users
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("server did not start")
	return
}

// startAgent 起一个 agent 并返回它的审计日志路径。测试环境一律 --quiet，
// 审计写进临时目录——别在跑测试的机器上弹通知。
func startAgent(t *testing.T, httpPort int, token, helloName string) string {
	t.Helper()
	audit := filepath.Join(t.TempDir(), "audit.log")
	go func() {
		_ = client.ConnectOnce(client.Config{
			ID:         helloName,
			Server:     fmt.Sprintf("ws://127.0.0.1:%d", httpPort),
			AgentToken: token,
			Shell:      "/bin/bash",
			Quiet:      true,
			AuditLog:   audit,
		})
	}()
	return audit
}

func waitAgent(t *testing.T, hub *server.Hub, username string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if hub.Has(username) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("agent %s did not connect", username)
}

func sshEcho(t *testing.T, sshPort int, user, password, cmd string) string {
	t.Helper()
	cfg := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.Password(password)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	return sshEchoAuth(t, sshPort, cfg, cmd)
}

// sshEchoAuth 同 sshEcho，但认证方式由调用方给（TOTP 的 keyboard-interactive 用）。
func sshEchoAuth(t *testing.T, sshPort int, cfg *gossh.ClientConfig, cmd string) string {
	t.Helper()
	c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)
	if _, err := stdin.Write([]byte(cmd + "\n")); err != nil {
		t.Fatal(err)
	}

	seen := make(chan string, 1)
	var out strings.Builder
	var mu sync.Mutex
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				mu.Lock()
				out.Write(buf[:n])
				got := out.String()
				mu.Unlock()
				if strings.Contains(got, "hello-") {
					select {
					case seen <- got:
					default:
					}
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case got := <-seen:
		return got
	case <-time.After(5 * time.Second):
		mu.Lock()
		got := out.String()
		mu.Unlock()
		t.Fatalf("did not see echo output: %q", got)
		return ""
	}
}

// kbdAuth 构造 keyboard-interactive 认证：问密码答密码，问验证码现算。
func kbdAuth(pw string, code func() string) gossh.AuthMethod {
	return gossh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i, q := range questions {
			if strings.Contains(q, "密码") {
				answers[i] = pw
			} else {
				answers[i] = code()
			}
		}
		return answers, nil
	})
}

func TestSSHWithOwnPassword(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = startAgent(t, httpPort, acct.Token, "whatever-hostname")
	waitAgent(t, srv.Hub, "alice")

	// 用户名密码是安装时自己设的
	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-alice")

	// 密码错、用户名错都进不来
	for _, bad := range [][2]string{{"alice", "wrongpw1"}, {"bob", "alicepw123"}} {
		cfg := &gossh.ClientConfig{
			User:            bad[0],
			Auth:            []gossh.AuthMethod{gossh.Password(bad[1])},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		}
		c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
		if err == nil {
			c.Close()
			t.Fatalf("错误凭据 %v 不应登录成功", bad)
		}
	}
}

// TestFromAndAudit 被控端感知：SSH 连入后，agent 的审计日志要记下
// 来源（登录账号@IP）和会话开始/结束——From 从服务器一路带到 agent。
func TestFromAndAudit(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	audit := startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")

	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-alice")

	// sshEcho 返回后测试客户端才断开，等 END 落盘
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(audit)
		got := string(raw)
		if strings.Contains(got, "START") &&
			strings.Contains(got, "from=alice@127.0.0.1") &&
			strings.Contains(got, "END") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	raw, _ := os.ReadFile(audit)
	t.Fatalf("审计日志应记录来源与开始/结束: %q", string(raw))
}

// TestBruteForceLockout 连续密码失败到阈值后锁死这个「账号|来源」，
// 正确密码也进不来；别的账号不受牵连。
func TestBruteForceLockout(t *testing.T) {
	_, _, sshPort, users := startServer(t)
	if _, err := users.Add("alice", "alicepw123", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := users.Add("bob", "bobpw12345", nil, "", nil); err != nil {
		t.Fatal(err)
	}

	authOK := func(user, pw string) bool {
		cfg := &gossh.ClientConfig{
			User:            user,
			Auth:            []gossh.AuthMethod{gossh.Password(pw)},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		}
		c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
		if err == nil {
			_ = c.Close()
			return true
		}
		return false
	}

	for i := 0; i < 5; i++ {
		if authOK("alice", "wrongpass1") {
			t.Fatal("错误密码不应登录")
		}
	}
	if authOK("alice", "alicepw123") {
		t.Fatal("连续失败到阈值后，正确密码也应被锁在外面")
	}
	if !authOK("bob", "bobpw12345") {
		t.Fatal("别的账号不应被牵连")
	}
}

func TestTwoUsersTwoMachines(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	alice, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := users.Add("bob", "bobpw12345", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = startAgent(t, httpPort, alice.Token, "h1")
	_ = startAgent(t, httpPort, bob.Token, "h2")
	waitAgent(t, srv.Hub, "alice")
	waitAgent(t, srv.Hub, "bob")

	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-alice")
	sshEcho(t, sshPort, "bob", "bobpw12345", "echo hello-bob")
}

func TestAgentTokenGate(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")

	// 无效 token 连不上
	_ = startAgent(t, httpPort, "w2s-not-a-real-token", "h2")
	time.Sleep(300 * time.Millisecond)
	if srv.Hub.Has("h2") {
		t.Fatal("无效 token 不应上线")
	}
	// 删号后 token 作废、SSH 拒绝。
	// 用另一个连接删（模拟 ws2ssh user remove），服务器直接查库，立刻可见。
	cli, err := accounts.Open(users.Path(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	cfg := &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{gossh.Password("alicepw123")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	if c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg); err == nil {
		c.Close()
		t.Fatal("删号后不应再能登录")
	}
}

func TestStatusNeedsToken(t *testing.T) {
	srv, httpPort, _, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/status", httpPort))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 token: status %d", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/status", httpPort), nil)
	req.Header.Set("X-Agent-Token", acct.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "alice") {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
}

// TestTOTPSecondFactor 绑了 TOTP 的账号：纯密码进不来，密码+验证码才行。
func TestTOTPSecondFactor(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")

	secret, _ := totp.Generate("ws2ssh", "alice")
	if err := users.EnrollTOTP("alice", secret, 0); err != nil {
		t.Fatal(err)
	}

	dialOK := func(auth gossh.AuthMethod) bool {
		cfg := &gossh.ClientConfig{
			User:            "alice",
			Auth:            []gossh.AuthMethod{auth},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		}
		c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
		if err == nil {
			_ = c.Close()
			return true
		}
		return false
	}
	codeNow := func() string { return totp.Code(secret, time.Now()) }
	wrongCode := func() string {
		c := codeNow()
		d := byte('0')
		if c[0] == '0' {
			d = '1'
		}
		return string(d) + c[1:]
	}

	if dialOK(gossh.Password("alicepw123")) {
		t.Fatal("绑了 TOTP 后纯密码不应登录")
	}
	if dialOK(kbdAuth("alicepw123", wrongCode)) {
		t.Fatal("错误验证码不应登录")
	}
	if dialOK(kbdAuth("错误的密码", codeNow)) {
		t.Fatal("错误密码不应登录")
	}
	out := sshEchoAuth(t, sshPort, &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{kbdAuth("alicepw123", codeNow)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}, "echo hello-2fa")
	if !strings.Contains(out, "hello-2fa") {
		t.Fatalf("密码+验证码应能干活: %q", out)
	}
}

// TestTOTPWrongCodeLocksOut 回归：kbd-interactive 通道「密码对 + 验证码错」
// 连续到阈值必须锁定——密码正确不能提前清零计数，否则验证码可以无限猜。
func TestTOTPWrongCodeLocksOut(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")

	secret, _ := totp.Generate("ws2ssh", "alice")
	if err := users.EnrollTOTP("alice", secret, 0); err != nil {
		t.Fatal(err)
	}

	dialOK := func(auth gossh.AuthMethod) bool {
		cfg := &gossh.ClientConfig{
			User:            "alice",
			Auth:            []gossh.AuthMethod{auth},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		}
		c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
		if err == nil {
			_ = c.Close()
			return true
		}
		return false
	}
	// 改第一位保证一定不是当前正确码，又不至于撞上相邻时间片的有效码
	wrongCode := func() string {
		c := totp.Code(secret, time.Now())
		d := byte('0')
		if c[0] == '0' {
			d = '1'
		}
		return string(d) + c[1:]
	}

	for i := 0; i < 5; i++ {
		if dialOK(kbdAuth("alicepw123", wrongCode)) {
			t.Fatalf("第 %d 次：错误验证码不应登录", i+1)
		}
	}
	// 阈值已到：正确密码 + 当前正确码也必须被锁在外面
	if dialOK(kbdAuth("alicepw123", func() string { return totp.Code(secret, time.Now()) })) {
		t.Fatal("连错 5 次验证码后应锁定，正确凭据也进不来")
	}
}

// waitStepBoundary 等到下一个 30 秒 TOTP 时间片：防重放意味着登录用掉的片
// 不能再用，测试里的重验必须等新片。
func waitStepBoundary(t *testing.T) {
	t.Helper()
	next := (time.Now().Unix()/30 + 1) * 30
	time.Sleep(time.Until(time.Unix(next, 0)) + 150*time.Millisecond)
}

// TestIdleReverifyTOTP 挂机超过阈值后再敲键，先要一个新的 TOTP 验证码。
func TestIdleReverifyTOTP(t *testing.T) {
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{
		IdleVerify: 1200 * time.Millisecond,
	})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")

	secret, _ := totp.Generate("ws2ssh", "alice")
	if err := users.EnrollTOTP("alice", secret, 0); err != nil {
		t.Fatal(err)
	}

	cfg := &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{kbdAuth("alicepw123", func() string { return totp.Code(secret, time.Now()) })},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	var mu sync.Mutex
	var out strings.Builder
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				mu.Lock()
				out.Write(buf[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	waitOut := func(sub string, d time.Duration) {
		t.Helper()
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			mu.Lock()
			got := out.String()
			mu.Unlock()
			if strings.Contains(got, sub) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		mu.Lock()
		got := out.String()
		mu.Unlock()
		t.Fatalf("没等到 %q: %q", sub, got)
	}
	send := func(s string) {
		t.Helper()
		if _, err := stdin.Write([]byte(s + "\n")); err != nil {
			t.Fatal(err)
		}
	}

	// 阈值内的输入不触发重验
	send("echo hello-idle1")
	waitOut("hello-idle1", 5*time.Second)

	// 登录已消费当前时间片，重验必须用更新的码——先等下一个片
	waitStepBoundary(t)

	// 挂机后再敲键：先弹验证码
	send("echo hello-idle2")
	waitOut("TOTP 验证码", 5*time.Second)
	send(totp.Code(secret, time.Now()))
	waitOut("验证通过", 5*time.Second)
	waitOut("hello-idle2", 5*time.Second)
}

// sshTry 拨上去把服务端返回的第一段文字读回来（不要求登录成功）。
func sshTry(t *testing.T, sshPort int, user, password string) string {
	t.Helper()
	cfg := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.Password(password)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		return "" // 服务端可能在开会话前就拒绝了
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
		return ""
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.Shell()
	b, _ := io.ReadAll(stdout) // 服务端 Exit 后管道 EOF
	return string(b)
}

// TestTokenRegenRevokesLiveAgent 回归高危 2：换 token 后，已经连着的旧 agent
// 立刻不能再接会话（撤权不能只挡新连接）。
func TestTokenRegenRevokesLiveAgent(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")
	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-before")

	// 换 token：旧 agent 的 WebSocket 还连着，但凭据已经失效
	newTok, err := users.RegenToken("alice")
	if err != nil {
		t.Fatal(err)
	}
	if msg := sshTry(t, sshPort, "alice", "alicepw123"); !strings.Contains(msg, "凭据已失效") {
		t.Fatalf("换 token 后新会话应被拒: %q", msg)
	}

	// 被控机用新 token 重连（会顶掉旧连接），服务恢复
	startAgent(t, httpPort, newTok, "h2")
	time.Sleep(500 * time.Millisecond)
	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-after")
}

// TestSessionLimit 每台机器的并发会话上限：超了要拒绝，而不是让一个账号
// 在被控机上 fork 出一堆 shell。
func TestSessionLimit(t *testing.T) {
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{MaxSessions: 2})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")

	// hold 占住一个会话并返回引用——必须保住引用，不然连接被 GC 回收，
	// 会话就掉了，上限也就无从触发。
	hold := func() (*gossh.Client, *gossh.Session) {
		t.Helper()
		cfg := &gossh.ClientConfig{
			User:            "alice",
			Auth:            []gossh.AuthMethod{gossh.Password("alicepw123")},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		}
		c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
			t.Fatal(err)
		}
		if err := sess.Shell(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(150 * time.Millisecond) // 等服务端把会话登记上
		return c, sess
	}
	c1, s1 := hold()
	defer c1.Close()
	defer s1.Close()
	c2, s2 := hold()
	defer c2.Close()
	defer s2.Close()

	if msg := sshTry(t, sshPort, "alice", "alicepw123"); !strings.Contains(msg, "并发会话数已达上限") {
		t.Fatalf("超过会话上限应被拒: %q", msg)
	}
}

// TestStatusScopeByCredential 账号 token 只能看到自己那条；全量看板要管理口令。
func TestStatusScopeByCredential(t *testing.T) {
	srv, httpPort, _, users := startServerOpt(t, server.Config{AdminToken: "admin-secret-1"})
	alice, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.Add("bob", "bobpw12345", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	// alice 的机器在线，OK 才是 200（离线时 503 是既有语义）
	startAgent(t, httpPort, alice.Token, "h1")
	waitAgent(t, srv.Hub, "alice")

	get := func(hdr, val string) string {
		t.Helper()
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/status", httpPort), nil)
		req.Header.Set(hdr, val)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("status %d: %s", resp.StatusCode, body)
		}
		return string(body)
	}

	// 账号 token：只看自己
	body := get("X-Agent-Token", alice.Token)
	if !strings.Contains(body, "alice") {
		t.Fatalf("应看到自己: %s", body)
	}
	if strings.Contains(body, "bob") {
		t.Fatalf("账号 token 不应看到别的账号（信息泄露）: %s", body)
	}

	// 管理口令：全量
	body = get("X-Admin-Token", "admin-secret-1")
	if !strings.Contains(body, "alice") || !strings.Contains(body, "bob") {
		t.Fatalf("管理口令应看到全量: %s", body)
	}
}

// TestServerAuditLog 服务器侧持久审计：认证成败、agent 上下线、会话开关都落盘。
func TestServerAuditLog(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "server-audit.log")
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{AuditLog: audit})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")

	// 一次失败 + 一次成功的登录
	if c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{gossh.Password("wrongpass99")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}); err == nil {
		c.Close()
	}
	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-audit")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(audit)
		got := string(raw)
		if strings.Contains(got, "AUTH-FAIL") &&
			strings.Contains(got, "AUTH-OK") &&
			strings.Contains(got, "AGENT-CONNECT") &&
			strings.Contains(got, "SESSION-START") &&
			strings.Contains(got, "SESSION-END") {
			if !strings.Contains(got, "reason=password") || !strings.Contains(got, "user=alice") {
				t.Fatalf("审计字段缺失: %q", got)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	raw, _ := os.ReadFile(audit)
	t.Fatalf("服务器审计事件不全: %q", string(raw))
}

// TestAgentSourceIPCheck agent 来源控制：白名单硬校验 + IP 变更只审计不拦。
func TestAgentSourceIPCheck(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "server-audit.log")
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{AuditLog: audit})
	acct, err := users.Add("alice", "alicepw123", nil, "", []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	// 白名单放行 127.0.0.1：正常上线干活
	startAgent(t, httpPort, acct.Token, "h1")
	waitAgent(t, srv.Hub, "alice")
	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-allow")

	// 白名单收紧到别的网段：新连接被拒（已连着的不受影响）
	if err := users.SetAgentAllow("alice", []string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Token, "h2")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !containsAudit(t, audit, "AGENT-DENY") {
		time.Sleep(50 * time.Millisecond)
	}
	if !containsAudit(t, audit, "AGENT-DENY") {
		t.Fatal("白名单外的 agent 连接应被拒并记 AGENT-DENY")
	}

	// 清空白名单（不限）+ 预置一个旧来源：换 IP 连接放行，但记 AGENT-IPCHANGE
	if err := users.SetAgentAllow("alice", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := users.CheckAgentIP("alice", &net.TCPAddr{IP: net.ParseIP("203.0.113.7")}); err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Token, "h3") // 127.0.0.1，与预置的不同
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !containsAudit(t, audit, "AGENT-IPCHANGE") {
		time.Sleep(50 * time.Millisecond)
	}
	if !containsAudit(t, audit, "AGENT-IPCHANGE") {
		t.Fatal("来源 IP 变更应记 AGENT-IPCHANGE")
	}
	// 机器仍能正常干活（变更不拦截）
	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-change")
}

func containsAudit(t *testing.T, path, sub string) bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(raw), sub)
}

// TestMinAgentVersion agent 版本门槛：自报版本过低拒绝接入并记审计，
// 门槛放行后正常上线且审计带版本号。
func TestMinAgentVersion(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "server-audit.log")
	srv, httpPort, _, users := startServerOpt(t, server.Config{
		AuditLog:        audit,
		MinAgentVersion: "99.0.0", // 比任何真版本都高
	})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Token, "h1")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !containsAudit(t, audit, "old-version") {
		time.Sleep(50 * time.Millisecond)
	}
	if srv.Hub.Has("alice") {
		t.Fatal("低于版本门槛的 agent 不应上线")
	}
	if !containsAudit(t, audit, "reason=old-version") {
		t.Fatal("应记 AGENT-DENY reason=old-version")
	}

	// 门槛放低：正常上线，AGENT-CONNECT 记录自报版本
	audit2 := filepath.Join(t.TempDir(), "server-audit.log")
	srv2, httpPort2, _, users2 := startServerOpt(t, server.Config{
		AuditLog:        audit2,
		MinAgentVersion: "0.1.0",
	})
	acct2, err := users2.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort2, acct2.Token, "h2")
	waitAgent(t, srv2.Hub, "alice")
	if !containsAudit(t, audit2, "version=0.2.0") {
		t.Fatal("AGENT-CONNECT 应记录自报版本")
	}
}
