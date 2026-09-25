package accounts

import (
	"testing"
	"time"
)

func TestOAuthBindLookupUnbind(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "alicepw12345", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.BindOAuthIdentity("alice", "https://idp.example.com", "sub-1", "a@x.com"); err != nil {
		t.Fatal(err)
	}
	// issuer 尾斜杠归一化
	owner, ok := s.OAuthLookup("https://idp.example.com/", "sub-1")
	if !ok || owner != "alice" {
		t.Fatalf("绑定后应能查到 alice，实际 %q ok=%v", owner, ok)
	}
	// 同一身份不能绑两个账号
	if _, err := s.Add("bob", "bobpw12345", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.BindOAuthIdentity("bob", "https://idp.example.com", "sub-1", ""); err == nil {
		t.Fatal("重复绑定必须报错")
	}
	if ids := s.OAuthIdentities("alice"); len(ids) != 1 || ids[0].Sub != "sub-1" {
		t.Fatalf("绑定列表不对: %+v", ids)
	}
	if err := s.UnbindOAuthIdentity("https://idp.example.com", "sub-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.OAuthLookup("https://idp.example.com", "sub-1"); ok {
		t.Fatal("解绑后不应再查到")
	}
}

func TestOAuthOnlyFlags(t *testing.T) {
	s := openTest(t)
	if _, err := s.Add("alice", "alicepw12345", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Get("alice")
	if a.OAuthOnly {
		t.Fatal("默认不应是 oauth_only")
	}
	if err := s.SetOAuthOnly("alice", true); err != nil {
		t.Fatal(err)
	}
	a, _ = s.Get("alice")
	if !a.OAuthOnly {
		t.Fatal("SetOAuthOnly 未生效")
	}
	m, _ := s.GetMachine("alice", "default")
	if m.OAuthOnly {
		t.Fatal("机器默认不应是 oauth_only")
	}
	if err := s.SetMachineOAuthOnly("alice", "default", true); err != nil {
		t.Fatal(err)
	}
	m, _ = s.GetMachine("alice", "default")
	if !m.OAuthOnly {
		t.Fatal("SetMachineOAuthOnly 未生效")
	}
}

func TestSSHGrantLifecycle(t *testing.T) {
	s := openTest(t)
	secret, err := s.CreateSSHGrant("alice+default", time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 20 || secret[:4] != "tso-" {
		t.Fatalf("凭据格式不对: %q", secret)
	}
	if !s.UseSSHGrant("alice+default", secret) {
		t.Fatal("第一次用应通过")
	}
	if !s.UseSSHGrant("alice+default", secret) {
		t.Fatal("第二次（uses=2）应通过")
	}
	if s.UseSSHGrant("alice+default", secret) {
		t.Fatal("次数用尽后必须拒")
	}
	// 错机器/错密钥都拒
	secret2, _ := s.CreateSSHGrant("alice+default", time.Minute, 1)
	if s.UseSSHGrant("alice+other", secret2) {
		t.Fatal("机器名不符必须拒")
	}
	if s.UseSSHGrant("alice+default", "tso-deadbeef.xxxx") {
		t.Fatal("乱猜必须拒")
	}
	// 过期即废
	secret3, _ := s.CreateSSHGrant("alice+default", -time.Minute, 5)
	if s.UseSSHGrant("alice+default", secret3) {
		t.Fatal("过期的凭据必须拒")
	}
	// 普通密码不会被当成凭据
	if s.UseSSHGrant("alice+default", "alicepw12345") {
		t.Fatal("非 tso- 前缀必须拒")
	}
}
