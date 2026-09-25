package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/client"
	"github.com/towstrap/towstrap/internal/server"
	"github.com/towstrap/towstrap/internal/totp"
	"github.com/towstrap/towstrap/internal/version"
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
	if opt.HostKeyPath == "" {
		opt.HostKeyPath = filepath.Join(dir, "host_key")
	}
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
	return startAgentProtect(t, httpPort, token, helloName, nil)
}

// startAgentProtect 同 startAgent，额外带 hello 要上报的禁碰文件清单。
func startAgentProtect(t *testing.T, httpPort int, token, helloName string, protect []string) string {
	return startAgentOpt(t, httpPort, token, helloName, protect, "/bin/bash")
}

// startAgentOpt 同上，可指定 agent 的 shell（测 zsh 的 NoExpand 路径用）。
// mirror socket 放进临时目录（TOWSTRAP_MIRROR_SOCK）——免得测试去碰真实的
// ~/.towstrap/mirror.sock 或互相踩；测试里读该环境变量能拿到 socket 路径。
func startAgentOpt(t *testing.T, httpPort int, token, helloName string, protect []string, shell string) string {
	t.Helper()
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.log")
	t.Setenv("TOWSTRAP_MIRROR_SOCK", filepath.Join(dir, "mirror.sock"))
	go func() {
		_ = client.ConnectOnce(client.Config{
			ID:           helloName,
			Server:       fmt.Sprintf("ws://127.0.0.1:%d", httpPort),
			AgentToken:   token,
			Shell:        shell,
			Quiet:        true,
			AuditLog:     audit,
			ProtectPaths: protect,
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
	marker := strings.TrimPrefix(cmd, "echo ")
	if marker == cmd {
		marker = "hello-"
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				mu.Lock()
				out.Write(buf[:n])
				got := out.String()
				mu.Unlock()
				if strings.Contains(normTermOut(got), "\n"+marker) {
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

// normTermOut 归一化终端输出再匹配：剥 CSI 转义序列（各发行版 bash 的
// bracketed-paste \x1b[?2004h/l 会把回显和输出隔开），\r\n/\r 统一成 \n，
// 不然行首 marker 在开了 bracketed-paste 的机器上永远匹配不上。
var csiRe = regexp.MustCompile("\x1b\\[[0-9;:?>]*[ -/]*[@-~]")

func normTermOut(s string) string {
	s = csiRe.ReplaceAllString(s, "")
	return strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(s)
}

// kbdAuth 构造 keyboard-interactive 认证：问密码答密码，问验证码现算。
func kbdAuth(pw string, code func() string) gossh.AuthMethod {
	return gossh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i, q := range questions {
			if strings.Contains(q, "密码") || strings.Contains(strings.ToLower(q), "password") {
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
	_ = startAgent(t, httpPort, acct.Machines[0].Token, "whatever-hostname")
	waitAgent(t, srv.Hub, "alice+default")

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
	audit := startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

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
	_ = startAgent(t, httpPort, alice.Machines[0].Token, "h1")
	_ = startAgent(t, httpPort, bob.Machines[0].Token, "h2")
	waitAgent(t, srv.Hub, "alice+default")
	waitAgent(t, srv.Hub, "bob+default")

	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-alice")
	sshEcho(t, sshPort, "bob", "bobpw12345", "echo hello-bob")
}

func TestAgentTokenGate(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	// 无效 token 连不上
	_ = startAgent(t, httpPort, "tsa-not-a-real-token", "h2")
	time.Sleep(300 * time.Millisecond)
	if srv.Hub.Has("h2") {
		t.Fatal("无效 token 不应上线")
	}
	// 删号后 token 作废、SSH 拒绝。
	// 用另一个连接删（模拟 towstrap user remove），服务器直接查库，立刻可见。
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
	_ = startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

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
	req.Header.Set("X-Agent-Token", acct.Machines[0].Token)
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
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	secret, _ := totp.Generate("towstrap", "alice")
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
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	secret, _ := totp.Generate("towstrap", "alice")
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
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	secret, _ := totp.Generate("towstrap", "alice")
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
	time.Sleep(1400 * time.Millisecond)

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
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")
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
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

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
	startAgent(t, httpPort, alice.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

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
	body := get("X-Agent-Token", alice.Machines[0].Token)
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
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

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
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")
	sshEcho(t, sshPort, "alice", "alicepw123", "echo hello-allow")

	// 白名单收紧到别的网段：新连接被拒（已连着的不受影响）
	if err := users.SetAgentAllow("alice", []string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h2")
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
	if _, err := users.CheckAgentIP("alice", "default", &net.TCPAddr{IP: net.ParseIP("203.0.113.7")}); err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h3") // 127.0.0.1，与预置的不同
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
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !containsAudit(t, audit, "old-version") {
		time.Sleep(50 * time.Millisecond)
	}
	if srv.Hub.Has("alice+default") {
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
	startAgent(t, httpPort2, acct2.Machines[0].Token, "h2")
	waitAgent(t, srv2.Hub, "alice+default")
	if !containsAudit(t, audit2, "version="+version.String()) {
		t.Fatal("AGENT-CONNECT 应记录自报版本")
	}
}

// execDial 密码登录建客户端 + 开 session（不申请 PTY，走 exec 通道）。
func execDial(t *testing.T, sshPort int, auth gossh.AuthMethod) (*gossh.Client, *gossh.Session) {
	t.Helper()
	cfg := &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{auth},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return c, sess
}

// TestExecCommand 无 PTY 的命令执行：stdout/stderr 分开、退出码原样带回。
func TestExecCommand(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	_, sess := execDial(t, sshPort, gossh.Password("alicepw123"))
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	err = sess.Run("echo out; echo err 1>&2; exit 3")
	var ee *gossh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 3 {
		t.Fatalf("退出码应为 3, err=%v", err)
	}
	if stdout.String() != "out\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "out\n")
	}
	if stderr.String() != "err\n" {
		t.Fatalf("stderr = %q, want %q", stderr.String(), "err\n")
	}
}

// TestExecStdin exec 会话的 stdin EOF 要传到子进程：cat 读到 EOF 才退出。
func TestExecStdin(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	_, sess := execDial(t, sshPort, gossh.Password("alicepw123"))
	sess.Stdin = strings.NewReader("abc")
	type res struct {
		out []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		out, err := sess.Output("cat")
		done <- res{out, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("cat 应正常退出: %v", r.err)
		}
		if string(r.out) != "abc" {
			t.Fatalf("cat 应回显 stdin: %q", r.out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cat 没在 stdin EOF 后退出——EOF 没传到子进程")
	}
}

// TestExecNoPtyShell ssh -T 等价物：无 PTY、不给命令，起一个非交互 shell，
// stdin 写命令、关 stdin，shell 退出码要带回来。
func TestExecNoPtyShell(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	_, sess := execDial(t, sshPort, gossh.Password("alicepw123"))
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sess.Stdout = &out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte("echo hi\nexit 7\n")); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- sess.Wait() }()
	select {
	case err := <-waitErr:
		var ee *gossh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() != 7 {
			t.Fatalf("退出码应为 7, err=%v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shell 没在 stdin EOF 后退出")
	}
	if !strings.Contains(out.String(), "hi") {
		t.Fatalf("输出应有 echo 的结果: %q", out.String())
	}
}

// TestPublicKeyAuth 公钥登录：登记的钥匙能进，没登记的进不来；
// 账号绑了 TOTP 公钥仍能登录（公钥是给自动化用的，不走 TOTP）。
func TestPublicKeyAuth(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	newSigner := func() gossh.Signer {
		t.Helper()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := gossh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return signer
	}
	signer := newSigner()
	line := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := users.AddSSHKey("alice", line); err != nil {
		t.Fatal(err)
	}

	// 登记的钥匙能跑命令
	_, sess := execDial(t, sshPort, gossh.PublicKeys(signer))
	out, err := sess.Output("echo pubkey-ok")
	if err != nil {
		t.Fatalf("公钥登录执行命令失败: %v", err)
	}
	if strings.TrimSpace(string(out)) != "pubkey-ok" {
		t.Fatalf("输出不对: %q", out)
	}
	_ = sess.Close()

	// 没登记的钥匙进不来
	cfg := &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(newSigner())},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	if c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg); err == nil {
		_ = c.Close()
		t.Fatal("没登记的公钥不应登录")
	}

	// 绑了 TOTP 公钥仍能登录
	secret, _ := totp.Generate("towstrap", "alice")
	if err := users.EnrollTOTP("alice", secret, 0); err != nil {
		t.Fatal(err)
	}
	_, sess2 := execDial(t, sshPort, gossh.PublicKeys(signer))
	out, err = sess2.Output("echo still-ok")
	if err != nil {
		t.Fatalf("绑了 TOTP 后公钥登录失败: %v", err)
	}
	if strings.TrimSpace(string(out)) != "still-ok" {
		t.Fatalf("输出不对: %q", out)
	}
}

// TestExecLargeOutput 大输出端到端：agent 侧 32KB 切片、服务器关闭前排空
// 缓冲，1MB 输出一个字节不能丢不能改。
func TestExecLargeOutput(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	_, sess := execDial(t, sshPort, gossh.Password("alicepw123"))
	out, err := sess.Output(`head -c 1000000 /dev/zero | tr '\0' a`)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1000000 {
		t.Fatalf("应恰好 1000000 字节, got %d", len(out))
	}
	if !bytes.Equal(out, bytes.Repeat([]byte{'a'}, 1000000)) {
		t.Fatal("输出内容应全是 'a'，有字节被改或丢失")
	}
}
