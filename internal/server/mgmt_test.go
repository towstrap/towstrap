package server

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/towstrap/towstrap/internal/accounts"
)

func testStore(t *testing.T) *accounts.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := accounts.Open(dir+"/accounts.db", dir+"/key")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// 自签 MCP token 的授权范围必须锁死在本账号——这是整个功能的安全边界：
// "*" 和别人账号一律拒，本账号的写法（裸机器名 / 账号+* / 账号+机器名）放行。
func TestMCPSelfMachines(t *testing.T) {
	store := testStore(t)
	if _, err := store.Add("alice", "password12", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("bob", "password34", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMachine("alice", "office", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMachine("bob", "office", nil); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{Users: store}}

	ok := map[string][]string{
		"":             {"alice"},        // 不带 --machine = 整个账号
		"alice":        {"alice"},        // 显式本账号
		"alice+*":      {"alice"},        // 本账号通配
		"alice+office": {"alice+office"}, // 本账号指定机器
		"alice/office": {"alice+office"}, // / 别名写法
		"office":       {"alice+office"}, // 裸机器名
	}
	for spec, want := range ok {
		var specs []string
		if spec != "" {
			specs = []string{spec}
		}
		got, err := s.mcpSelfMachines("alice", specs)
		if err != nil {
			t.Errorf("mcpSelfMachines(%q) 应放行: %v", spec, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("mcpSelfMachines(%q) = %v, want %v", spec, got, want)
		}
	}

	bad := []string{
		"*",          // 全局通配
		"bob",        // 别人账号
		"bob+office", // 别人账号的具体机器
		"bob/office",
		"*+office",
		"alice+x",  // 自己账号但不存在的机器
		"nonexist", // 裸名但机器不存在
	}
	for _, spec := range bad {
		if got, err := s.mcpSelfMachines("alice", []string{spec}); err == nil {
			t.Errorf("mcpSelfMachines(%q) 应拒绝, got %v", spec, got)
		}
	}
}

// 自签客户端的归属由库里的 owner 列判定，不靠「账号.名字」名字前缀——
// 账号名允许点号，前缀不是无歧义的名字空间（账号 alice 能拼出
// alice.bob.laptop 这种名字，那是账号 alice.bob 的客户端）。
func TestMCPSelfName(t *testing.T) {
	if got := mcpSelfName("alice", "laptop"); got != "alice.laptop" {
		t.Fatalf("mcpSelfName = %q", got)
	}
	store := testStore(t)
	for _, a := range []string{"alice", "bob", "alice.bob"} {
		if _, err := store.Add(a, "password12", nil, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	// alice 和 alice.bob 各签一个同短名的客户端；管理员再签一个无归属的。
	if _, _, err := store.MCPAdd(mcpSelfName("alice", "laptop"), "alice", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.MCPAdd(mcpSelfName("alice.bob", "laptop"), "alice.bob", []string{"alice.bob"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.MCPAdd("admin-issued", "", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}

	// 各自的只能命中自己 owner 下的那条。
	if _, ok := store.MCPOwnedGet("alice", mcpSelfName("alice", "laptop")); !ok {
		t.Fatal("alice 应能取到自己的 alice.laptop")
	}
	if _, ok := store.MCPOwnedGet("alice.bob", mcpSelfName("alice.bob", "laptop")); !ok {
		t.Fatal("alice.bob 应能取到自己的 alice.bob.laptop")
	}
	// 点号账号的客户端不能被短前缀账号捞走（这条就是漏洞本身）。
	if c, ok := store.MCPOwnedGet("alice", mcpSelfName("alice", "bob.laptop")); ok {
		t.Fatalf("alice 越权命中了 %q（owner=%q）", c.Name, c.Owner)
	}
	// 管理员签发的（owner 留空）自助面一律碰不到——包括把空 owner 直接
	// 传进来：自助面入口对空 owner 恒查无此人，管理路径走 MCPGet(name)。
	if _, ok := store.MCPOwnedGet("alice", mcpSelfName("alice", "admin-issued")); ok {
		t.Fatal("alice 不该碰到 admin 签发的凭据")
	}
	if _, ok := store.MCPOwnedGet("", "admin-issued"); ok {
		t.Fatal("空 owner 不该能穿透到管理员名下")
	}
	if _, ok := store.MCPGet("admin-issued"); !ok {
		t.Fatal("管理员 CLI 按名字应能取到 admin-issued")
	}

	// list 同理：alice 只看到自己那条，看不到 alice.bob 和 admin 的。
	var names []string
	for _, c := range store.MCPOwnedList("alice") {
		names = append(names, c.Name)
	}
	if len(names) != 1 || names[0] != "alice.laptop" {
		t.Fatalf("MCPOwnedList(alice) = %v, want [alice.laptop]", names)
	}
}

// 回归：@mcp 自助面的读写/改/删/换发都必须按 owner 圈住，账号名带点时
// 不得越到别人账号的客户端上（曾经靠名字前缀，alice 能读走 alice.bob 的
// 明文 token 并把它 regen 掉）。这里走 mcpSelfGet——@mcp 子命令的唯一入口。
func TestMCPSelfCommandsStayInOwner(t *testing.T) {
	store := testStore(t)
	for _, a := range []string{"alice", "alice.bob"} {
		if _, err := store.Add(a, "password12", nil, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{cfg: Config{Users: store}}
	victim := mcpSelfName("alice.bob", "laptop")
	_, victimTok, err := store.MCPAdd(victim, "alice.bob", []string{"alice.bob"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 攻击者 alice 用「bob.laptop」拼出的同一个库内名字来打。
	stolen := mcpSelfName("alice", "bob.laptop")
	if stolen != victim {
		t.Fatalf("前提不成立：%q != %q", stolen, victim)
	}

	if c, ok := s.mcpSelfGet("alice", "bob.laptop"); ok {
		t.Fatalf("token 泄露：alice 读到了 %q 的明文 token", c.Name)
	}
	if tok, err := store.MCPOwnedRegenToken("alice", stolen); err == nil {
		t.Fatalf("越权换发：alice 换发了受害者的 token %q", tok)
	}
	if err := store.MCPOwnedRemove("alice", stolen); err == nil {
		t.Fatal("越权删除：alice 删掉了受害者的客户端")
	}
	allow := []string{"10.0.0.9"}
	if err := store.MCPOwnedSet("alice", stolen, nil, &allow, nil); err == nil {
		t.Fatal("越权改白名单：alice 改写了受害者的 allow_ips")
	}
	// 受害者的 token 必须原封不动还能用。
	if _, ok := store.MCPClientByToken(victimTok); !ok {
		t.Fatal("受害者的 token 失效了")
	}
	// 受害者自己照常管得动。
	if c, ok := s.mcpSelfGet("alice.bob", "laptop"); !ok || c.Token != victimTok {
		t.Fatal("受害者应仍能管理自己的客户端")
	}
}

// 短名里带点会让「账号.短名」不再是单射：账号 alice 的 "bob.laptop" 拼出
// 的全名和账号 alice.bob 的 "laptop" 一样，抢注就能把对方的位置占死。
// 禁掉短名里的点，按最后一个点拆分才是唯一的。
func TestMCPClientShortNameNoDot(t *testing.T) {
	for _, bad := range []string{"", "bob.laptop", "a.b.c", "."} {
		if err := validMCPClientShort(bad); err == nil {
			t.Errorf("短名 %q 应被拒", bad)
		}
	}
	for _, ok := range []string{"laptop", "office-1", "my_client", "a1"} {
		if err := validMCPClientShort(ok); err != nil {
			t.Errorf("短名 %q 应放行: %v", ok, err)
		}
	}
	// 单射性：任意两个 (账号, 短名) 组合都不会拼出同一个全名。
	seen := map[string]string{}
	for _, a := range []string{"alice", "alice.bob", "a", "a.b.c"} {
		for _, n := range []string{"laptop", "office"} {
			full := mcpSelfName(a, n)
			if prev, dup := seen[full]; dup {
				t.Errorf("全名 %q 被 (%s,%s) 和 (%s,%s) 同时拼出", full, prev, n, a, n)
			}
			seen[full] = a + "+" + n
		}
	}
}

// ownPending 只回本账号机器的待批请求——approve --all 也只批这些，别人
// 账号的待批从用户视角不存在。
func TestOwnPending(t *testing.T) {
	dir := t.TempDir()
	write := func(id, machine string) {
		body := `{"id":"` + id + `","machine":"` + machine + `","kind":"command","detail":"ls","created":"2026-01-01T00:00:00Z"}`
		if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("p1", "alice+office")
	write("p2", "bob+laptop")
	write("p3", "alice+build")
	write("p4", "alice") // 账号级写法也算本账号

	s := &Server{cfg: Config{Users: testStore(t)}}
	got, err := s.ownPending("alice", dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range got {
		ids = append(ids, p.ID)
	}
	want := []string{"p1", "p3", "p4"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("ownPending(alice) = %v, want %v", ids, want)
	}
	if list, _ := s.ownPending("carol", dir); len(list) != 0 {
		t.Fatalf("ownPending(carol) 应为空, got %v", list)
	}
}
