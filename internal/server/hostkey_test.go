package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestHostKeyGeneratedWhenMissing 密钥不存在时自动生成（0600），
// 再次调用读回同一把。
func TestHostKeyGeneratedWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_host_key")
	s1, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("主机密钥权限 = %o, want 600", st.Mode().Perm())
	}
	s2, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1.PublicKey().Marshal(), s2.PublicKey().Marshal()) {
		t.Fatal("第二次应读回同一把密钥")
	}
}

// TestHostKeyGarbageIsError 文件在但解析不了：报错退出，不能静默换新钥匙
// （主机密钥一变，所有客户端都会弹 host key 变更警告）。
func TestHostKeyGarbageIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_host_key")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateHostKey(path); err == nil {
		t.Fatal("垃圾内容应报错，而不是悄悄生成新密钥")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "not a key" {
		t.Fatal("解析失败不应改写原文件")
	}
}

// TestHostKeyUnreadableIsError 文件在但读不了（权限拒绝）同样报错退出。
func TestHostKeyUnreadableIsError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视文件权限位，没法模拟读不了")
	}
	path := filepath.Join(t.TempDir(), "ssh_host_key")
	if err := os.WriteFile(path, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateHostKey(path); err == nil {
		t.Fatal("读不了应报错，而不是悄悄生成新密钥")
	}
}
