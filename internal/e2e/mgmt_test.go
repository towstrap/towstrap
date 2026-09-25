package e2e

// @ 开头的 SSH 命令是服务器自己的管理命令（账号本人自助管理机器），
// 不发给 agent。这组测试覆盖自助加机器、公钥拒绝、TOTP 再验、
// token 换新、删机器、未知命令和带 +机器名 登录名。

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/towstrap/towstrap/internal/server"
	"github.com/towstrap/towstrap/internal/totp"
)

var tokenRe = regexp.MustCompile(`tsa-[0-9A-Za-z_-]+`)

// mgmtDial 建一个 SSH 客户端连接（登录名可以是 alice 或 alice+default）。
func mgmtDial(t *testing.T, sshPort int, user string, auth gossh.AuthMethod) *gossh.Client {
	t.Helper()
	cfg := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{auth},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// runMgmt 在同一个连接上开一个 exec 会话跑一条命令，返回 stdout/stderr/退出码。
// stdin 用于喂 TOTP 验证码这类会话内输入。
func runMgmt(t *testing.T, c *gossh.Client, cmd, stdin string) (string, string, int) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var so, se bytes.Buffer
	sess.Stdout = &so
	sess.Stderr = &se
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}
	err = sess.Run(cmd)
	code := 0
	if err != nil {
		var ee *gossh.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("执行 %q 出错: %v", cmd, err)
		}
		code = ee.ExitStatus()
	}
	return so.String(), se.String(), code
}

// TestMgmtMachineSelfService 密码账号（无 TOTP）自助加机器：@machine add
// 打印 token，拿着它能起 agent；@machine list 列全部机器且不显示 token。
func TestMgmtMachineSelfService(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "server-audit.log")
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{AuditLog: audit})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	c := mgmtDial(t, sshPort, "alice", gossh.Password("alicepw123"))
	out, se, code := runMgmt(t, c, "@machine add build --agent-allow-ip 127.0.0.1", "")
	if code != 0 {
		t.Fatalf("@machine add 应成功: code=%d stderr=%q", code, se)
	}
	if !strings.Contains(out, "alice+build") || !strings.Contains(out, "tsa-") {
		t.Fatalf("add 输出应有机器 ID 和 token: %q", out)
	}
	tok := tokenRe.FindString(out)
	if tok == "" {
		t.Fatalf("没找到 token: %q", out)
	}
	if _, ok := users.GetMachine("alice", "build"); !ok {
		t.Fatal("alice+build 应已建出来")
	}

	startAgent(t, httpPort, tok, "build-host")
	waitAgent(t, srv.Hub, "alice+build")

	out, se, code = runMgmt(t, c, "@machine list", "")
	if code != 0 {
		t.Fatalf("@machine list 应成功: code=%d stderr=%q", code, se)
	}
	for _, want := range []string{"alice+default", "alice+build", "在线", "127.0.0.1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list 输出缺 %q: %q", want, out)
		}
	}
	if strings.Contains(out, "tsa-") {
		t.Fatalf("list 不该显示 token: %q", out)
	}

	if !containsAudit(t, audit, "MACHINE-ADD") || !containsAudit(t, audit, "alice+build") {
		raw, _ := os.ReadFile(audit)
		t.Fatalf("审计应有 MACHINE-ADD alice+build:\n%s", raw)
	}
}

// TestMgmtPubkeyDenied 公钥登录不能跑管理命令（公钥是给自动化的）。
func TestMgmtPubkeyDenied(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "server-audit.log")
	_, _, sshPort, users := startServerOpt(t, server.Config{AuditLog: audit})
	if _, err := users.Add("alice", "alicepw123", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.AddSSHKey("alice", strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))); err != nil {
		t.Fatal(err)
	}

	c := mgmtDial(t, sshPort, "alice", gossh.PublicKeys(signer))
	_, se, code := runMgmt(t, c, "@machine add x", "")
	if code == 0 {
		t.Fatal("公钥登录跑 @machine add 应被拒")
	}
	if !strings.Contains(se, "公钥") {
		t.Fatalf("stderr 应说明公钥不行: %q", se)
	}
	if _, ok := users.GetMachine("alice", "x"); ok {
		t.Fatal("被拒的命令不应建出机器")
	}
	if !containsAudit(t, audit, "MGMT-DENY") || !containsAudit(t, audit, "reason=pubkey") {
		raw, _ := os.ReadFile(audit)
		t.Fatalf("审计应有 MGMT-DENY reason=pubkey:\n%s", raw)
	}
}

// TestMgmtTOTPRecheck 绑了 TOTP 的账号，管理命令要再要一个新验证码：
// 新的通过、登录/已用过的拒、连错三次拒且计进登录限速。
func TestMgmtTOTPRecheck(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "server-audit.log")
	_, _, sshPort, users := startServerOpt(t, server.Config{AuditLog: audit})
	if _, err := users.Add("alice", "alicepw123", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	secret, _ := totp.Generate("towstrap", "alice")
	if err := users.EnrollTOTP("alice", secret, 0); err != nil {
		t.Fatal(err)
	}
	codeNow := func() string { return totp.Code(secret, time.Now()) }
	wrong := func() string {
		c := codeNow()
		d := byte('0')
		if c[0] == '0' {
			d = '1'
		}
		return string(d) + c[1:]
	}

	// 登录先用掉一个时间片的码；管理命令重验要等下一个片。
	waitStepBoundary(t)
	c := mgmtDial(t, sshPort, "alice", kbdAuth("alicepw123", codeNow))
	waitStepBoundary(t)

	fresh := codeNow()
	out, se, code := runMgmt(t, c, "@machine add x", fresh+"\n")
	if code != 0 {
		t.Fatalf("新验证码应通过: code=%d stderr=%q", code, se)
	}
	if !strings.Contains(out, "tsa-") {
		t.Fatalf("add 应打印 token: %q", out)
	}
	if _, ok := users.GetMachine("alice", "x"); !ok {
		t.Fatal("alice+x 应已建出来")
	}

	// 同一个验证码不能再用（防重放）
	_, _, code = runMgmt(t, c, "@machine token x", fresh+"\n")
	if code == 0 {
		t.Fatal("已用过的验证码应被拒")
	}

	// 连错三次被拒，每次都记 MGMT-DENY reason=totp
	bad := wrong()
	_, se, code = runMgmt(t, c, "@machine list", bad+"\n"+bad+"\n"+bad+"\n")
	if code == 0 {
		t.Fatal("连错三次验证码应被拒")
	}
	if !strings.Contains(se, "验证码") {
		t.Fatalf("stderr 应有提示: %q", se)
	}
	raw, _ := os.ReadFile(audit)
	if n := strings.Count(string(raw), "reason=totp"); n != 4 {
		t.Fatalf("重放 1 次 + 连错 3 次应有 4 条 reason=totp，实际 %d:\n%s", n, raw)
	}
}

// TestMgmtTokenRegen @machine token 只保留回显：--regen 已移到 agent 侧
// 的 token refresh，SSH 里传 --regen 退出 2、token 不变、agent 不掉线。
func TestMgmtTokenRegen(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	if _, err := users.Add("alice", "alicepw123", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	build, err := users.AddMachine("alice", "build", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, build.Token, "build-host")
	waitAgent(t, srv.Hub, "alice+build")

	c := mgmtDial(t, sshPort, "alice", gossh.Password("alicepw123"))

	// 回显照旧
	out, se, code := runMgmt(t, c, "@machine token build", "")
	if code != 0 || !strings.Contains(out, build.Token) {
		t.Fatalf("回显应有当前 token: code=%d out=%q stderr=%q", code, out, se)
	}
	// --regen 拒绝并指路 token refresh
	_, se, code = runMgmt(t, c, "@machine token build --regen", "")
	if code != 2 {
		t.Fatalf("--regen 应退出 2: code=%d", code)
	}
	if !strings.Contains(se, "token refresh") {
		t.Fatalf("stderr 应指向 towstrap token refresh: %q", se)
	}
	m, _ := users.GetMachine("alice", "build")
	if m.Token != build.Token {
		t.Fatal("token 不该变")
	}
	if !srv.Hub.Has("alice+build") {
		t.Fatal("agent 不该掉线")
	}
}

// TestMgmtMachineRemove @machine remove 删机器后记录没了、在线 agent 掉线。
func TestMgmtMachineRemove(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	if _, err := users.Add("alice", "alicepw123", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	build, err := users.AddMachine("alice", "build", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, build.Token, "build-host")
	waitAgent(t, srv.Hub, "alice+build")

	c := mgmtDial(t, sshPort, "alice", gossh.Password("alicepw123"))
	out, se, code := runMgmt(t, c, "@machine remove build", "")
	if code != 0 {
		t.Fatalf("remove 应成功: code=%d stderr=%q", code, se)
	}
	if !strings.Contains(out, "alice+build") {
		t.Fatalf("输出应有机器 ID: %q", out)
	}
	if _, ok := users.GetMachine("alice", "build"); ok {
		t.Fatal("alice+build 应已删除")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && srv.Hub.Has("alice+build") {
		time.Sleep(50 * time.Millisecond)
	}
	if srv.Hub.Has("alice+build") {
		t.Fatal("删机器后在线 agent 应立即掉线")
	}
}

// TestMgmtUnknown @foo 这类未知管理命令退出码 2，不会发给 agent。
func TestMgmtUnknown(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	agentAudit := startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	c := mgmtDial(t, sshPort, "alice", gossh.Password("alicepw123"))
	_, se, code := runMgmt(t, c, "@foo", "")
	if code != 2 {
		t.Fatalf("未知管理命令应退出 2: code=%d", code)
	}
	if !strings.Contains(se, "未知管理命令") {
		t.Fatalf("stderr 应提示未知管理命令: %q", se)
	}
	// 给 agent 一点时间（如果真误发了），确认它没收到这条命令
	time.Sleep(300 * time.Millisecond)
	if containsAudit(t, agentAudit, "@foo") {
		raw, _ := os.ReadFile(agentAudit)
		t.Fatalf("@ 命令不应发给 agent:\n%s", raw)
	}
}

// TestMgmtMachineSuffixLogin 登录名带 +机器名 也能跑管理命令（按账号处理）。
func TestMgmtMachineSuffixLogin(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	c := mgmtDial(t, sshPort, "alice+default", gossh.Password("alicepw123"))
	out, se, code := runMgmt(t, c, "@machine list", "")
	if code != 0 {
		t.Fatalf("带后缀登录跑 @machine list 应成功: code=%d stderr=%q", code, se)
	}
	if !strings.Contains(out, "alice+default") {
		t.Fatalf("list 应列 default 机器: %q", out)
	}
}
