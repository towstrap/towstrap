package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"towstrap/internal/accounts"
	"towstrap/internal/allow"
	"towstrap/internal/totp"
)

// testSigner 生成一把测试用 ed25519 钥匙。
func testSigner(t *testing.T) gossh.Signer {
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

// TestSSHPubKeyOK 公钥登录的核心判定：登记过的钥匙 + 白名单内的来源才放行；
// 停用账号、陌生钥匙、白名单外来源都拒。绑了 TOTP 的账号公钥照样进——
// 公钥是给自动化用的第二种凭据。
func TestSSHPubKeyOK(t *testing.T) {
	dir := t.TempDir()
	users, err := accounts.Open(filepath.Join(dir, "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Close()
	if _, err := users.Add("alice", "alicepw123", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := users.Add("carol", "carolpw123", []string{"9.9.9.9"}, "", nil); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	line := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := users.AddSSHKey("alice", line); err != nil {
		t.Fatal(err)
	}
	if err := users.AddSSHKey("carol", line); err != nil {
		t.Fatal(err)
	}
	// alice 绑上 TOTP：公钥登录仍应放行
	secret, _ := totp.Generate("towstrap", "alice")
	if err := users.EnrollTOTP("alice", secret, 0); err != nil {
		t.Fatal(err)
	}

	ips, err := allow.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Users: users, AllowIPs: ips})
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5555}
	carolAddr := &net.TCPAddr{IP: net.ParseIP("9.9.9.9"), Port: 5555}

	if !s.sshPubKeyOK("alice", signer.PublicKey(), addr) {
		t.Fatal("登记过的公钥应通过（绑了 TOTP 也一样）")
	}
	if s.sshPubKeyOK("alice", testSigner(t).PublicKey(), addr) {
		t.Fatal("没登记的公钥不应通过")
	}
	if s.sshPubKeyOK("nobody", signer.PublicKey(), addr) {
		t.Fatal("不存在的账号不应通过")
	}
	if s.sshPubKeyOK("carol", signer.PublicKey(), addr) {
		t.Fatal("账号白名单外的来源不应通过")
	}
	if !s.sshPubKeyOK("carol", signer.PublicKey(), carolAddr) {
		t.Fatal("账号白名单内的来源应通过")
	}
	if err := users.SetDisabled("alice", true); err != nil {
		t.Fatal(err)
	}
	if s.sshPubKeyOK("alice", signer.PublicKey(), addr) {
		t.Fatal("停用账号不应通过")
	}
}

// TestAuditCmd 审计里的命令字段：空记 -，长的截断标记，普通原样。
func TestAuditCmd(t *testing.T) {
	if auditCmd("") != "-" {
		t.Fatal("空命令应记 -")
	}
	if auditCmd("echo hi") != "echo hi" {
		t.Fatal("普通命令应原样")
	}
	long := strings.Repeat("x", 600)
	got := auditCmd(long)
	if !strings.HasPrefix(got, strings.Repeat("x", 512)) || !strings.HasSuffix(got, "(truncated)") {
		t.Fatalf("长命令应截断并标记: %q...", got[:40])
	}
}
