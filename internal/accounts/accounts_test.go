package accounts

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"ws2ssh/internal/totp"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "users.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestOpenTightensDBPerms Open 会把账号库文件（含 WAL 侧文件）收到 0600。
func TestOpenTightensDBPerms(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.db")
	s, err := Open(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	st, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("账号库权限 = %o, want 600", st.Mode().Perm())
	}
	if _, err := s.Add("alice", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	// -wal 不一定已经建出来（取决于 SQLite 何时落盘），在就必须也是 0600
	if st, err := os.Stat(dbPath + "-wal"); err == nil && st.Mode().Perm() != 0o600 {
		t.Fatalf("wal 文件权限 = %o, want 600", st.Mode().Perm())
	}
}

func TestAddVerifyRemove(t *testing.T) {
	s := openTest(t)
	a, err := s.Add("alice", "password12", []string{"10.0.0.0/8"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Token == "" || !strings.HasPrefix(a.Token, "w2s-") {
		t.Fatalf("token = %q", a.Token)
	}

	if !s.Verify("alice", "password12") {
		t.Fatal("正确密码应通过")
	}
	if s.Verify("alice", "wrong") || s.Verify("bob", "password12") {
		t.Fatal("错误密码/不存在用户应拒绝")
	}

	if name, ok := s.UsernameByToken(a.Token); !ok || name != "alice" {
		t.Fatalf("token 应对应 alice: %q %v", name, ok)
	}
	if _, ok := s.UsernameByToken("w2s-bogus"); ok {
		t.Fatal("无效 token 应拒绝")
	}

	if err := s.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	if s.Verify("alice", "password12") {
		t.Fatal("删除后应拒绝")
	}
	if _, ok := s.UsernameByToken(a.Token); ok {
		t.Fatal("删除后 token 应失效")
	}
	if err := s.Remove("alice"); err == nil {
		t.Fatal("重复删除应报错")
	}
}

func TestAddValidation(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("bad name", "password12", nil, "", nil); err == nil {
		t.Fatal("非法用户名应报错")
	}
	if _, err := s.Add("alice", "123", nil, "", nil); err == nil {
		t.Fatal("过短密码应报错")
	}
	if _, err := s.Add("alice", "password12", []string{"10.0.0.0/99"}, "", nil); err == nil {
		t.Fatal("坏白名单应报错")
	}
	if _, err := s.Add("alice", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("alice", "password12", nil, "", nil); err == nil {
		t.Fatal("同名账号应报错")
	}
}

func TestTokensUnique(t *testing.T) {
	s := openTest(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		a, err := s.Add(fmt.Sprintf("u%02d", i), "password12", nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if seen[a.Token] {
			t.Fatalf("token 重复: %s", a.Token)
		}
		seen[a.Token] = true
	}
}

func TestTOTPFlow(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	secret, _ := totp.Generate("ws2ssh", "alice")

	// 未绑定：验证一律拒绝
	if s.VerifyTOTP("alice", totp.Code(secret, time.Now())) {
		t.Fatal("未绑定时应拒绝")
	}

	// 绑定后：码通过，同一个码不能吃第二次（防重放）
	if err := s.EnrollTOTP("alice", secret, 0); err != nil {
		t.Fatal(err)
	}
	code := totp.Code(secret, time.Now())
	if !s.VerifyTOTP("alice", code) {
		t.Fatal("绑定后当前码应通过")
	}
	if s.VerifyTOTP("alice", code) {
		t.Fatal("同一个码不能重放")
	}
	// 窗口外的码拒绝
	if s.VerifyTOTP("alice", totp.Code(secret, time.Now().Add(90*time.Second))) {
		t.Fatal("+3 片的码不应通过")
	}

	// Get/List 暴露绑定状态
	a, ok := s.Get("alice")
	if !ok || !a.TOTPEnabled {
		t.Fatal("Get 应显示已绑定")
	}

	// 解绑后退回纯密码
	if err := s.RemoveTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	a, _ = s.Get("alice")
	if a.TOTPEnabled {
		t.Fatal("解绑后应显示未绑定")
	}
	if s.VerifyTOTP("alice", totp.Code(secret, time.Now())) {
		t.Fatal("解绑后应拒绝")
	}
}

func TestContact(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "password12", nil, "ops@example.com", nil); err != nil {
		t.Fatal(err)
	}
	a, ok := s.Get("alice")
	if !ok || a.Contact != "ops@example.com" {
		t.Fatalf("contact = %q", a.Contact)
	}
	if err := s.SetContact("alice", "值班：张三"); err != nil {
		t.Fatal(err)
	}
	a, _ = s.Get("alice")
	if a.Contact != "值班：张三" {
		t.Fatalf("contact = %q", a.Contact)
	}
	if err := s.SetContact("ghost", "x"); err == nil {
		t.Fatal("不存在的账号应报错")
	}
	list := s.List()
	if len(list) != 1 || list[0].Contact != "值班：张三" {
		t.Fatalf("List 应带 contact: %+v", list)
	}
}

func TestRandomPassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		pw := RandomPassword()
		if len(pw) != 16 {
			t.Fatalf("长度 = %d, want 16", len(pw))
		}
		if seen[pw] {
			t.Fatalf("随机密码重复: %s", pw)
		}
		seen[pw] = true
		if err := validPassword(pw); err != nil {
			t.Fatalf("生成的密码应满足密码策略: %v", err)
		}
	}
}

func TestModify(t *testing.T) {
	s := openTest(t)
	a, _ := s.Add("alice", "password12", nil, "", nil)

	if err := s.SetPassword("alice", "newpass1234"); err != nil {
		t.Fatal(err)
	}
	if !s.Verify("alice", "newpass1234") || s.Verify("alice", "password12") {
		t.Fatal("改密码没生效")
	}
	// 改密码后哈希应换（bcrypt 盐也换了）
	got, _ := s.Get("alice")
	if got.Password == a.Password {
		t.Fatal("改密码后哈希没变")
	}

	if err := s.SetAllow("alice", []string{"1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get("alice")
	if len(got.AllowIPs) != 1 || got.AllowIPs[0] != "1.2.3.4" {
		t.Fatalf("%v", got.AllowIPs)
	}
	if err := s.SetAllow("alice", nil); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get("alice")
	if len(got.AllowIPs) != 0 {
		t.Fatalf("清空白名单失败: %v", got.AllowIPs)
	}

	if err := s.SetDisabled("alice", true); err != nil {
		t.Fatal(err)
	}
	if s.Verify("alice", "newpass1234") {
		t.Fatal("停用后 SSH 应拒绝")
	}
	if _, ok := s.UsernameByToken(a.Token); ok {
		t.Fatal("停用后 agent 应拒绝")
	}
	if err := s.SetDisabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if !s.Verify("alice", "newpass1234") {
		t.Fatal("重新启用后应通过")
	}

	if err := s.Rename("alice", "office"); err != nil {
		t.Fatal(err)
	}
	if !s.Verify("office", "newpass1234") {
		t.Fatal("改名后旧密码应仍有效")
	}
	if name, ok := s.UsernameByToken(a.Token); !ok || name != "office" {
		t.Fatal("改名后 token 应仍有效")
	}

	newTok, err := s.RegenToken("office")
	if err != nil {
		t.Fatal(err)
	}
	if newTok == a.Token {
		t.Fatal("新 token 不应与旧的相同")
	}
	if _, ok := s.UsernameByToken(a.Token); ok {
		t.Fatal("旧 token 应作废")
	}
	if name, ok := s.UsernameByToken(newTok); !ok || name != "office" {
		t.Fatal("新 token 应有效")
	}
}

// TestEncryptedAtRest 直接查库：token 不是明文，密码是 bcrypt 哈希，用户名明文存放。
func TestEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.db")
	s, err := Open(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.Add("alice", "password12", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var (
		username string
		hash     string
		tEnc     []byte
	)
	if err := raw.QueryRow(`SELECT username, password_hash, token_enc FROM users`).Scan(&username, &hash, &tEnc); err != nil {
		t.Fatal(err)
	}
	if username != "alice" {
		t.Fatalf("用户名应明文存放, got %q", username)
	}
	if strings.Contains(string(tEnc), a.Token) || strings.Contains(string(tEnc), "w2s-") {
		t.Fatal("token 在库里是明文")
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("密码应是 bcrypt 哈希, got %q", hash)
	}
	if strings.Contains(hash, "password12") {
		t.Fatal("密码明文出现在哈希里")
	}

	// key 文件存在且权限 0600
	st, err := os.Stat(filepath.Join(dir, "users.key"))
	if err != nil {
		t.Fatal("应自动生成密钥文件")
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("密钥文件权限 = %v", st.Mode().Perm())
	}
}

// TestWrongKeyRejected 换一把密钥打开同一个库，token 解不开（密钥文件要备份好）。
// 用户名明文、密码是 bcrypt 哈希，都不依赖密钥：换 key 后 SSH 密码登录仍然通过，
// 受密钥保护的只有 token——agent 认不出、token 也解不出。
func TestWrongKeyRejected(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.db")
	s, err := Open(dbPath, filepath.Join(dir, "users.key"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Add("alice", "password12", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	// 把密钥换掉再打开：token 解不开，agent 侧认证全部失效
	if err := os.Remove(filepath.Join(dir, "users.key")); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dbPath, filepath.Join(dir, "users.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if !s2.Verify("alice", "password12") {
		t.Fatal("用户名和密码不依赖密钥，登录不应受换 key 影响")
	}
	if _, ok := s2.UsernameByToken(a.Token); ok {
		t.Fatal("换了密钥后不应还能按 token 认出账号")
	}
	// 解密失败的行被跳过；只要不返回带 token 的账号即可
	for _, acc := range s2.List() {
		if acc.Token != "" {
			t.Fatal("换密钥后不应解出 token")
		}
	}
}

// TestTwoProcesses 一个库两个连接（CLI 和服务器各一个），改动互相可见。
func TestTwoProcesses(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.db")
	server, err := Open(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	cli, err := Open(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	a, err := cli.Add("alice", "password12", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !server.Verify("alice", "password12") {
		t.Fatal("服务器连接应立刻看到 CLI 建的号")
	}
	if _, ok := server.UsernameByToken(a.Token); !ok {
		t.Fatal("服务器连接应能按 token 查到")
	}
	if err := cli.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	if server.Verify("alice", "password12") {
		t.Fatal("CLI 删号后服务器连接应立刻看到")
	}
}

func TestCryptoDeterministicAndPurposeBound(t *testing.T) {
	dir := t.TempDir()
	k1, err := loadOrCreateKey(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := loadOrCreateKey(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}

	a1, err := k1.seal("token", []byte("w2s-aaa"))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := k2.seal("token", []byte("w2s-aaa"))
	if err != nil {
		t.Fatal(err)
	}
	if string(a1) != string(a2) {
		t.Fatal("同一密钥同一明文应是确定性加密")
	}
	b1, err := k1.seal("token", []byte("w2s-bbb"))
	if err != nil {
		t.Fatal(err)
	}
	if string(a1) == string(b1) {
		t.Fatal("不同明文密文不应相同")
	}

	// 用途绑定：一个用途的密文不能当另一个用途解
	c1, err := k1.seal("other", []byte("w2s-aaa"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k1.open("token", c1); err == nil {
		t.Fatal("跨用途挪密文应解密失败")
	}
	// 篡改
	a1[len(a1)-1] ^= 0xFF
	if _, err := k1.open("token", a1); err == nil {
		t.Fatal("篡改后的密文应解密失败")
	}
}

// TestVerifyTimingEqualized 不存在的账号也要付出一次 bcrypt 的耗时，
// 三条失败路径（不存在/停用/密码错）时间量级一致，按耗时枚举用户名不可行。
func TestVerifyTimingEqualized(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	// 建一个停用的账号
	if _, err := s.Add("bob", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled("bob", true); err != nil {
		t.Fatal(err)
	}

	check := func(label string, f func()) time.Duration {
		t.Helper()
		start := time.Now()
		f()
		return time.Since(start)
	}
	// bcrypt cost 10 单次 ~60-100ms；不存在的账号如果跳过 bcrypt 会 <5ms
	for i := 0; i < 2; i++ {
		if d := check("missing", func() { s.Verify("ghost-user", "wrongpass99") }); d < 20*time.Millisecond {
			t.Fatalf("不存在的账号也应做 bcrypt（第 %d 次，%s）", i, d)
		}
		if d := check("disabled", func() { s.Verify("bob", "wrongpass99") }); d < 20*time.Millisecond {
			t.Fatalf("停用的账号也应做 bcrypt（%s）", d)
		}
		if d := check("wrongpw", func() { s.Verify("alice", "wrongpass99") }); d < 20*time.Millisecond {
			t.Fatalf("密码错误路径耗时异常（%s）", d)
		}
	}
}

func TestContactCleaned(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "password12", nil, "ops@example.com\x1b]0;pwn\x07", nil); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Get("alice")
	if strings.Contains(a.Contact, "\x1b") || strings.Contains(a.Contact, "\x07") {
		t.Fatalf("建号时 contact 应清洗: %q", a.Contact)
	}
	if err := s.SetContact("alice", "值班：张三\nrm -rf /"); err != nil {
		t.Fatal(err)
	}
	a, _ = s.Get("alice")
	if strings.Contains(a.Contact, "\n") {
		t.Fatalf("改备注时应清洗换行: %q", a.Contact)
	}
	if !strings.Contains(a.Contact, "张三") {
		t.Fatalf("正常文字应保留: %q", a.Contact)
	}
}

func TestListBasic(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("bob", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("alice", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled("bob", true); err != nil {
		t.Fatal(err)
	}
	got := s.ListBasic()
	if len(got) != 2 || got[0].Username != "alice" || got[1].Username != "bob" || !got[1].Disabled {
		t.Fatalf("ListBasic = %+v", got)
	}
}

// TestAgentAllowAndIPCheck agent 来源白名单硬校验 + 来源变更可观测。
func TestAgentAllowAndIPCheck(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "password12", nil, "", []string{"10.0.0.0/8", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5}
	far := &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 5}

	// 白名单内放行；首次连接 prev 为空
	if prev, err := s.CheckAgentIP("alice", local); err != nil || prev != "" {
		t.Fatalf("白名单内应放行: prev=%q err=%v", prev, err)
	}
	// 同 IP 再连：prev 是它自己
	if prev, err := s.CheckAgentIP("alice", local); err != nil || prev != "127.0.0.1" {
		t.Fatalf("同 IP 再连 prev 应为 127.0.0.1: prev=%q err=%v", prev, err)
	}
	// 白名单外拒绝，且不挪动记录的 last_ip
	if _, err := s.CheckAgentIP("alice", far); err == nil {
		t.Fatal("白名单外应拒绝")
	}

	// 清空白名单 = 不限；换 IP 放行并返回旧值（供审计）
	if err := s.SetAgentAllow("alice", nil); err != nil {
		t.Fatal(err)
	}
	if prev, err := s.CheckAgentIP("alice", far); err != nil || prev != "127.0.0.1" {
		t.Fatalf("不限后换 IP 应放行并返回旧值: prev=%q err=%v", prev, err)
	}
	// 再连一次，prev 已是新值
	if prev, _ := s.CheckAgentIP("alice", far); prev != "8.8.8.8" {
		t.Fatalf("prev 应更新为新值: %q", prev)
	}

	// 配置了非法条目要在设置时就报错
	if err := s.SetAgentAllow("alice", []string{"10.0.0.0/99"}); err == nil {
		t.Fatal("非法白名单应报错")
	}
	if a, _ := s.Get("alice"); len(a.AgentAllowIPs) != 0 {
		t.Fatalf("AgentAllowIPs 应为空: %v", a.AgentAllowIPs)
	}
}
