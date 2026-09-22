package accounts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPClientCRUD(t *testing.T) {
	s := openTest(t)

	// 空 machines 不批（fail-closed：不给「什么都不能看」的客户端）
	if _, _, err := s.MCPAdd("empty", nil, nil); err == nil {
		t.Fatal("空 machines 应该报错")
	}
	if _, _, err := s.MCPAdd("bad", []string{"../evil"}, nil); err == nil {
		t.Fatal("非法机器名应该报错")
	}
	if _, _, err := s.MCPAdd("bad name!", []string{"bot"}, nil); err == nil {
		t.Fatal("非法客户端名应该报错")
	}

	c, tok, err := s.MCPAdd("laptop", []string{"bot"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "tsm-") {
		t.Fatalf("token 前缀不对: %q", tok)
	}
	if !c.Grants("bot") || c.Grants("other") {
		t.Fatalf("Grants 结果不对: %+v", c.Machines)
	}

	// token 能换回客户端记录
	got, ok := s.MCPClientByToken(tok)
	if !ok || got.Name != "laptop" {
		t.Fatalf("MCPClientByToken 没找到: %v %+v", ok, got)
	}
	if _, ok := s.MCPClientByToken("tsm-不存在的"); ok {
		t.Fatal("假 token 居然过了")
	}

	// regen：旧的立刻失效，新的能用
	tok2, err := s.MCPRegenToken("laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MCPClientByToken(tok); ok {
		t.Fatal("旧 token regen 后还认")
	}
	if _, ok := s.MCPClientByToken(tok2); !ok {
		t.Fatal("新 token 不认")
	}

	// disable：ByToken 拒，但记录还在
	tru := true
	if err := s.MCPSet("laptop", nil, nil, &tru); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MCPClientByToken(tok2); ok {
		t.Fatal("停用客户端的 token 还认")
	}
	if _, ok := s.MCPGet("laptop"); !ok {
		t.Fatal("停用后记录不该消失")
	}
	fls := false
	if err := s.MCPSet("laptop", nil, nil, &fls); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MCPClientByToken(tok2); !ok {
		t.Fatal("重新启用后 token 不认")
	}

	// set machines
	m := []string{"other"}
	if err := s.MCPSet("laptop", &m, nil, nil); err != nil {
		t.Fatal(err)
	}
	c2, _ := s.MCPGet("laptop")
	if c2.Grants("bot") || !c2.Grants("other") {
		t.Fatalf("MCPSet machines 没生效: %+v", c2.Machines)
	}

	// remove
	if err := s.MCPRemove("laptop"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MCPGet("laptop"); ok {
		t.Fatal("删除后还能查到")
	}
	if _, ok := s.MCPClientByToken(tok2); ok {
		t.Fatal("删除后 token 还认")
	}
}

func TestMCPClientStar(t *testing.T) {
	s := openTest(t)
	_, tok, err := s.MCPAdd("all", []string{"*"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := s.MCPClientByToken(tok)
	if !ok {
		t.Fatal("token 查不到")
	}
	if !c.Grants("任何机器名") {
		t.Fatal("\"*\" 应该放行所有机器")
	}
}

func TestMCPClientAllowIPsAndList(t *testing.T) {
	s := openTest(t)
	if _, _, err := s.MCPAdd("x", []string{"bot"}, []string{"10.0.0.0/33"}); err == nil {
		t.Fatal("非法 allow_ips 应该报错")
	}
	if _, _, err := s.MCPAdd("x", []string{"bot"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	c, ok := s.MCPGet("x")
	if !ok || len(c.AllowIPs) != 1 {
		t.Fatalf("allow_ips 没存进去: %+v", c)
	}
	if n := len(s.MCPList()); n != 1 {
		t.Fatalf("MCPList 条数不对: %d", n)
	}
}

func TestMCPClientPersist(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "users.db")
	s, err := Open(db, "")
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := s.MCPAdd("laptop", []string{"bot"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s2, err := Open(db, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, ok := s2.MCPClientByToken(tok); !ok {
		t.Fatal("重开库后 token 不认")
	}
}

func TestMCPClientTokenEncrypted(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "users.db")
	s, err := Open(db, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, tok, err := s.MCPAdd("laptop", []string{"bot"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), tok) {
		t.Fatal("明文 token 落进了数据库")
	}
}
