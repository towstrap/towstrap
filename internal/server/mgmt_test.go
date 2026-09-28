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

// 自签客户端的名字归属是「账号.名字」前缀——alice 只能碰 alice.* 名下的，
// 管理员签的别的名字（不带前缀）和其他账号前缀都越不过去。
func TestMCPSelfName(t *testing.T) {
	if got := mcpSelfName("alice", "laptop"); got != "alice.laptop" {
		t.Fatalf("mcpSelfName = %q", got)
	}
	store := testStore(t)
	if _, _, err := store.MCPAdd("alice.laptop", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.MCPAdd("admin-issued", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.MCPAdd("bob.laptop", []string{"bob"}, nil); err != nil {
		t.Fatal(err)
	}
	// alice 视角：get 路径只能命中 alice.laptop
	if _, ok := store.MCPGet(mcpSelfName("alice", "laptop")); !ok {
		t.Fatal("alice.laptop 应存在")
	}
	if _, ok := store.MCPGet(mcpSelfName("alice", "admin-issued")); ok {
		t.Fatal("alice.admin-issued 不该存在——不能借别人的名字碰到 admin 签发的凭据")
	}
	if _, ok := store.MCPGet(mcpSelfName("alice", "bob.laptop")); ok {
		t.Fatal("alice.bob.laptop 不该存在")
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
