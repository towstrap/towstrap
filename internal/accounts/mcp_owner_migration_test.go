package accounts

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// 模拟老库：建一个没有 owner 列的 mcp_clients，塞进各种名字的行，
// 再用 Open 打开，验回填只认无歧义的那种。
func TestBackfillMCPOwnerMigration(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.db")
	keyPath := filepath.Join(dir, "users.key")

	// 先落一个合法密钥文件（老库本来就有 key，Open 的 fail-closed 校验要求）
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{7}, keyFileSize), 0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// 老版 schema（无 owner 列）
	if _, err := raw.Exec(`CREATE TABLE mcp_clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		token_enc BLOB NOT NULL UNIQUE,
		machines TEXT NOT NULL DEFAULT '',
		allow_ips TEXT NOT NULL DEFAULT '',
		disabled INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE users (username TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "alice.bob", "bob"} {
		if _, err := raw.Exec(`INSERT INTO users (username) VALUES (?)`, u); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct{ name, ownerWant string }{
		{"alice.laptop", "alice"}, // 恰好一个点 + 前半截是账号 → 回填
		{"alice.bob.laptop", ""},  // 两个点 → 认不准，留空
		{"admin-issued", ""},      // 无点 = 管理员签发 → 留空
		{"nobody.laptop", ""},     // 前半截不是账号 → 留空
		{"bob.laptop", "bob"},     // 正常自签
		{"alice.", ""},            // 点后为空 → 留空
		{".laptop", ""},           // 点前为空 → 留空
	}
	for i, r := range rows {
		if _, err := raw.Exec(`INSERT INTO mcp_clients (name, token_enc, machines, created_at)
			VALUES (?, ?, '["alice"]', '2026-01-01T00:00:00Z')`, r.name, []byte{byte(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	s, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("老库升级失败: %v", err)
	}
	defer s.Close()

	for _, r := range rows {
		var owner string
		if err := s.db.QueryRow(`SELECT owner FROM mcp_clients WHERE name = ?`, r.name).Scan(&owner); err != nil {
			t.Fatalf("%s: %v", r.name, err)
		}
		if owner != r.ownerWant {
			t.Errorf("%s 回填 owner=%q, 期望 %q", r.name, owner, r.ownerWant)
		}
	}
	// 幂等：再开一次不应改变结果
	s.Close()
	s2, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for _, r := range rows {
		var owner string
		s2.db.QueryRow(`SELECT owner FROM mcp_clients WHERE name = ?`, r.name).Scan(&owner)
		if owner != r.ownerWant {
			t.Errorf("二次打开后 %s owner=%q, 期望 %q", r.name, owner, r.ownerWant)
		}
	}
}

// 回填只能跑「补列那一趟」：列已存在后管理员新签发的单点名字
// （如 alice.laptop）owner 必须一直是空——每次 Open 都重扫的话，
// 它下次启动就会被收养给 alice，等于凭据易主。
func TestBackfillMCPOwnerDoesNotReclaim(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.db")
	keyPath := filepath.Join(dir, "users.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{7}, keyFileSize), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dbPath, keyPath) // 全新库：schema 自带 owner 列，回填本就该跳过
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("alice", "long-enough-password", nil, "", nil); err != nil { // 让 alice 存在
		t.Fatal(err)
	}
	s.Close()

	// 管理员签发 alice.laptop（owner 留空——@mcp 自助面碰不到的正常状态）
	s, err = Open(dbPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MCPAdd("alice.laptop", "", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// 重开：owner 列早已存在，绝不能再回填——alice.laptop 必须保持无归属
	s, err = Open(dbPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, ok := s.MCPGet("alice.laptop")
	if !ok {
		t.Fatal("alice.laptop 丢了")
	}
	if c.Owner != "" {
		t.Fatalf("管理员签发的客户端被收养给 %q——凭据易主", c.Owner)
	}
	// 顺带钉死：自助面按空 owner 永远查不到管理员名下的行
	if _, ok := s.MCPOwnedGet("", "alice.laptop"); ok {
		t.Fatal("空 owner 不该查到任何东西")
	}
	if len(s.MCPOwnedList("")) != 0 {
		t.Fatal("空 owner 不该列出任何东西")
	}
	if err := s.MCPOwnedRemove("", "alice.laptop"); err == nil {
		t.Fatal("空 owner 不该能删东西")
	}
}

// 管理员移交归属：MCPSetOwner 把客户端交给某账号时，必须同时把名字收敛
// 成「账号.短名」——@mcp 自助面按全名+owner 双条件寻址，只改 owner 用户
// 照样够不到。收回（owner=""）只清归属不动名字。
func TestMCPSetOwnerTransfer(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "long-enough-password", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MCPAdd("admin-issued", "", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}

	// 移交：owner=alice 且名字变成 alice.admin-issued——自助面两个条件齐了
	newName, err := s.MCPSetOwner("admin-issued", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if newName != "alice.admin-issued" {
		t.Fatalf("移交后名字应收敛成 alice.admin-issued: %q", newName)
	}
	if _, ok := s.MCPOwnedGet("alice", "alice.admin-issued"); !ok {
		t.Fatal("移交后 alice 应能经自助面取到")
	}
	if _, ok := s.MCPGet("admin-issued"); ok {
		t.Fatal("旧名字不该残留")
	}

	// 带点名字移交：取第一个点之后的部分当短名
	if _, _, err := s.MCPAdd("nobody.laptop", "", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MCPSetOwner("nobody.laptop", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MCPOwnedGet("alice", "alice.laptop"); !ok {
		t.Fatal("nobody.laptop 移交后应是 alice.laptop")
	}

	// 收回：只清 owner 不改名，自助面立刻够不到
	if _, err := s.MCPSetOwner("alice.laptop", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MCPOwnedGet("alice", "alice.laptop"); ok {
		t.Fatal("收回后 alice 不该再够到")
	}
	if c, ok := s.MCPGet("alice.laptop"); !ok || c.Owner != "" {
		t.Fatalf("收回后应保留原名、owner 清空: %+v", c)
	}

	// 防呆：账号不存在、客户端不存在、名字拆不出短名
	if _, err := s.MCPSetOwner("admin-issued", "ghost"); err == nil {
		t.Fatal("移交给不存在的账号该报错")
	}
	if _, err := s.MCPSetOwner("nope", "alice"); err == nil {
		t.Fatal("移交不存在的客户端该报错")
	}
	if _, err := s.MCPSetOwner("alice.laptop", "alice"); err != nil {
		t.Fatalf("同名移交应是幂等: %v", err)
	}
	// 冲突：alice 已有 alice.x，把 bob-issued 也收敛成 alice.x 要撞唯一约束
	if _, _, err := s.MCPAdd("alice.x", "alice", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MCPAdd("bob.x", "", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MCPSetOwner("bob.x", "alice"); err == nil {
		t.Fatal("目标名字已占用时移交该报错")
	}
}
