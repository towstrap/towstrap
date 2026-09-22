package accounts

import (
	"database/sql"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestSplitMachineID(t *testing.T) {
	for _, tc := range []struct {
		in, user, machine string
	}{
		{"alice", "alice", ""},
		{"alice+office", "alice", "office"},
		{"alice+*", "alice", "*"},
		// 第一个 + 是分隔符；后面的内容原样（正常路径不会出现，
		// 因为用户名和机器名都不许带 +）
		{"alice+o+x", "alice", "o+x"},
		{"+x", "", "x"},
	} {
		u, m := SplitMachineID(tc.in)
		if u != tc.user || m != tc.machine {
			t.Fatalf("SplitMachineID(%q) = (%q,%q), want (%q,%q)", tc.in, u, m, tc.user, tc.machine)
		}
	}
}

func TestMachineCRUD(t *testing.T) {
	s := openTest(t)
	a, err := s.Add("alice", "password12", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}

	build, err := s.AddMachine("alice", "build", []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if build.ID() != "alice+build" || !strings.HasPrefix(build.Token, "tsa-") {
		t.Fatalf("新机器: %+v", build)
	}
	if build.Token == a.Machines[0].Token {
		t.Fatal("两台机器 token 不应相同")
	}

	// Machines 按名字排序，Get 出来的账号也带着
	ms := s.Machines("alice")
	if len(ms) != 2 || ms[0].Name != "build" || ms[1].Name != "default" {
		t.Fatalf("Machines = %+v", ms)
	}
	got, _ := s.Get("alice")
	if len(got.Machines) != 2 {
		t.Fatalf("Get 应带机器列表: %+v", got.Machines)
	}
	if m, ok := s.GetMachine("alice", "build"); !ok || len(m.AgentAllowIPs) != 1 {
		t.Fatalf("GetMachine: %+v %v", m, ok)
	}
	if _, ok := s.GetMachine("alice", "ghost"); ok {
		t.Fatal("不存在的机器应返回 false")
	}

	// 每台机器的 token 各自定位
	if m, ok := s.MachineByToken(build.Token); !ok || m.ID() != "alice+build" {
		t.Fatalf("MachineByToken(build): %+v %v", m, ok)
	}
	if m, ok := s.MachineByToken(a.Machines[0].Token); !ok || m.ID() != "alice+default" {
		t.Fatalf("MachineByToken(default): %+v %v", m, ok)
	}

	// 校验：坏名字、不存在账号、同名
	if _, err := s.AddMachine("alice", "bad name", nil); err == nil {
		t.Fatal("非法机器名应报错")
	}
	if _, err := s.AddMachine("alice", "a+b", nil); err == nil {
		t.Fatal("机器名带 + 应报错")
	}
	if _, err := s.AddMachine("ghost", "m1", nil); err == nil {
		t.Fatal("不存在的账号应报错")
	}
	if _, err := s.AddMachine("alice", "build", nil); err == nil {
		t.Fatal("同名机器应报错")
	}
	if _, err := s.AddMachine("alice", "m2", []string{"10.0.0.0/99"}); err == nil {
		t.Fatal("坏 agent 白名单应报错")
	}
}

func TestMachineRegenOnlyThatOne(t *testing.T) {
	s := openTest(t)
	a, _ := s.Add("alice", "password12", nil, "", nil)
	build, _ := s.AddMachine("alice", "build", nil)

	newTok, err := s.RegenMachineToken("alice", "build")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MachineByToken(build.Token); ok {
		t.Fatal("旧 token 应作废")
	}
	if m, ok := s.MachineByToken(newTok); !ok || m.ID() != "alice+build" {
		t.Fatal("新 token 应指向 build")
	}
	// default 那台不受影响
	if m, ok := s.MachineByToken(a.Machines[0].Token); !ok || m.ID() != "alice+default" {
		t.Fatal("regen build 不应影响 default")
	}
	if _, err := s.RegenMachineToken("alice", "ghost"); err == nil {
		t.Fatal("不存在的机器应报错")
	}
}

func TestMachineRemoveAndCascade(t *testing.T) {
	s := openTest(t)
	a, _ := s.Add("alice", "password12", nil, "", nil)
	build, _ := s.AddMachine("alice", "build", nil)

	if err := s.RemoveMachine("alice", "build"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MachineByToken(build.Token); ok {
		t.Fatal("删机器后其 token 应失效")
	}
	if err := s.RemoveMachine("alice", "build"); err == nil {
		t.Fatal("重复删应报错")
	}
	// default 还在
	if _, ok := s.MachineByToken(a.Machines[0].Token); !ok {
		t.Fatal("删 build 不应影响 default")
	}

	// 删账号级联删机器
	if _, err := s.AddMachine("alice", "b2", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	if len(s.Machines("alice")) != 0 {
		t.Fatal("删账号应级联删机器")
	}
}

func TestMachineRenameFollows(t *testing.T) {
	s := openTest(t)
	a, _ := s.Add("alice", "password12", nil, "", nil)
	build, _ := s.AddMachine("alice", "build", nil)

	if err := s.Rename("alice", "carol"); err != nil {
		t.Fatal(err)
	}
	if m, ok := s.MachineByToken(build.Token); !ok || m.ID() != "carol+build" {
		t.Fatalf("改名后 token 应跟到新账号: %+v %v", m, ok)
	}
	if _, ok := s.GetMachine("alice", "build"); ok {
		t.Fatal("旧账号名下不应再有机器")
	}
	ms := s.Machines("carol")
	if len(ms) != 2 || ms[0].ID() != "carol+build" || ms[1].ID() != "carol+default" {
		t.Fatalf("Machines(carol) = %+v", ms)
	}
	_ = a
}

func TestMachineByTokenDisabledAccount(t *testing.T) {
	s := openTest(t)
	a, _ := s.Add("alice", "password12", nil, "", nil)
	if err := s.SetDisabled("alice", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MachineByToken(a.Machines[0].Token); ok {
		t.Fatal("账号停用后其机器 token 应全部失效")
	}
	if err := s.SetDisabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MachineByToken(a.Machines[0].Token); !ok {
		t.Fatal("重新启用后 token 应恢复")
	}
}

// TestSoleMachineCompat 单台机器时老 API（SetAgentAllow/RegenToken）照常；
// 多台时报清楚错，让管理员去用 machine 子命令。
func TestSoleMachineCompat(t *testing.T) {
	s := openTest(t)
	a, _ := s.Add("alice", "password12", nil, "", nil)

	if err := s.SetAgentAllow("alice", []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.GetMachine("alice", DefaultMachine); len(m.AgentAllowIPs) != 1 {
		t.Fatalf("SetAgentAllow 应落到唯一机器上: %+v", m.AgentAllowIPs)
	}
	cur, err := s.RegenToken("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MachineByToken(a.Machines[0].Token); ok {
		t.Fatal("RegenToken 后旧 token 应作废")
	}

	if _, err := s.AddMachine("alice", "build", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAgentAllow("alice", nil); err == nil || !strings.Contains(err.Error(), "多台机器") {
		t.Fatalf("多台时 SetAgentAllow 应报「多台机器」: %v", err)
	}
	if _, err := s.RegenToken("alice"); err == nil || !strings.Contains(err.Error(), "多台机器") {
		t.Fatalf("多台时 RegenToken 应报「多台机器」: %v", err)
	}
	if _, ok := s.MachineByToken(cur); !ok {
		t.Fatal("报错的 RegenToken 不应改动 default 的 token")
	}
}

func TestMachinePerMachineAllowList(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "password12", nil, "", []string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddMachine("alice", "build", nil); err != nil {
		t.Fatal(err)
	}
	far := &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 5}

	// default 有白名单，build 没有：同一个 IP 一台拒一台放
	if _, err := s.CheckAgentIP("alice", DefaultMachine, far); err == nil {
		t.Fatal("default 应拒绝白名单外来源")
	}
	if _, err := s.CheckAgentIP("alice", "build", far); err != nil {
		t.Fatalf("build 没设白名单应放行: %v", err)
	}
	if err := s.SetMachineAgentAllow("alice", "build", []string{"8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckAgentIP("alice", "build", &net.TCPAddr{IP: net.ParseIP("9.9.9.9"), Port: 5}); err == nil {
		t.Fatal("build 设了白名单后应拒绝单外来源")
	}
}

func TestListMachinesBasic(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddMachine("alice", "build", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("bob", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled("bob", true); err != nil {
		t.Fatal(err)
	}
	got := s.ListMachinesBasic()
	if len(got) != 3 {
		t.Fatalf("ListMachinesBasic = %+v", got)
	}
	ids := []string{got[0].ID, got[1].ID, got[2].ID}
	want := []string{"alice+build", "alice+default", "bob+default"}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("排序 = %v, want %v", ids, want)
		}
	}
	if !got[2].Disabled || got[0].Disabled {
		t.Fatalf("停用标志不对: %+v", got)
	}
}

// oldUsersSchema 是迁移前的 users 表（HEAD 6b25d47 的 schema）：agent token
// 和来源白名单/最近 IP 都挂在账号上。
const oldUsersSchema = `CREATE TABLE users (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	username        TEXT    NOT NULL UNIQUE,
	password_hash   TEXT    NOT NULL,
	token_enc       BLOB    NOT NULL UNIQUE,
	contact         TEXT    NOT NULL DEFAULT '',
	totp_secret_enc BLOB,
	totp_last_step  INTEGER NOT NULL DEFAULT 0,
	agent_allow_ips TEXT    NOT NULL DEFAULT '',
	agent_last_ip   TEXT    NOT NULL DEFAULT '',
	allow_ips       TEXT    NOT NULL DEFAULT '',
	ssh_pubkeys     TEXT    NOT NULL DEFAULT '',
	disabled        INTEGER NOT NULL DEFAULT 0,
	created_at      TEXT    NOT NULL
);
CREATE INDEX idx_users_token ON users(token_enc);`

// TestMigrateMachinesFromOldDB 老库升级：每个账号得到一台 default 机器，
// 沿用原 token 和 agent 白名单/最近 IP；users 表不再有旧列。
func TestMigrateMachinesFromOldDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.db")
	keyPath := DefaultKeyPath(dbPath)

	// 先造密钥，再用它 seal 两个「老 token」插进旧 schema 的库
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(tok string) []byte {
		b, err := key.seal("token", []byte(tok))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	raw, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(oldUsersSchema); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := raw.Exec(
		`INSERT INTO users (username, password_hash, token_enc, contact, agent_allow_ips, agent_last_ip, allow_ips, created_at)
		 VALUES ('alice', 'hash1', ?, '', '["10.0.0.0/8"]', '1.2.3.4', '[]', ?)`, seal("tsa-aliceold"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`INSERT INTO users (username, password_hash, token_enc, allow_ips, created_at)
		 VALUES ('bob', 'hash2', ?, '[]', ?)`, seal("tsa-bobold"), now); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dbPath, "")
	if err != nil {
		t.Fatalf("老库 Open 应自动迁移: %v", err)
	}
	defer s.Close()

	// 每人一台 default 机器，旧 token 直接命中
	for _, tc := range []struct{ user, tok string }{
		{"alice", "tsa-aliceold"}, {"bob", "tsa-bobold"},
	} {
		ms := s.Machines(tc.user)
		if len(ms) != 1 || ms[0].Name != DefaultMachine || ms[0].Token != tc.tok {
			t.Fatalf("%s 的机器 = %+v", tc.user, ms)
		}
		if m, ok := s.MachineByToken(tc.tok); !ok || m.ID() != tc.user+"+default" {
			t.Fatalf("旧 token %s 应命中 %s+default: %+v %v", tc.tok, tc.user, m, ok)
		}
	}
	// 旧 agent 白名单和最近 IP 搬到了机器上
	m, _ := s.GetMachine("alice", DefaultMachine)
	if len(m.AgentAllowIPs) != 1 || m.AgentAllowIPs[0] != "10.0.0.0/8" || m.AgentLastIP != "1.2.3.4" {
		t.Fatalf("迁移后的 alice+default = %+v", m)
	}

	// users 表不再有旧列
	raw2, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw2.Close()
	for _, col := range []string{"token_enc", "agent_allow_ips", "agent_last_ip"} {
		rows, err := raw2.Query(`PRAGMA table_info(users)`)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for rows.Next() {
			var cid, notNull, pk int
			var name, typ string
			var dflt any
			if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
				t.Fatal(err)
			}
			if name == col {
				found = true
			}
		}
		rows.Close()
		if found {
			t.Fatalf("users 表不应再有 %s 列", col)
		}
	}
	// 老索引也跟着没了
	var cnt int
	if err := raw2.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'idx_users_token'`).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatal("idx_users_token 应被删掉")
	}

	// 迁移幂等：关掉再开不报错、机器不翻倍
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dbPath, "")
	if err != nil {
		t.Fatalf("二次 Open 应成功: %v", err)
	}
	defer s2.Close()
	if ms := s2.Machines("alice"); len(ms) != 1 {
		t.Fatalf("二次 Open 后机器不应翻倍: %+v", ms)
	}
}
