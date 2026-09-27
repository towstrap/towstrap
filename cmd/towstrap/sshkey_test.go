package main

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestParsePosInterleaved flag 包遇到位置参数就停，交错解析要保证
// "remove <指纹> --password-stdin" 这种写法里旗标不被吞。
func TestParsePosInterleaved(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	b := fs.Bool("flag", false, "")
	pos := parsePosInterleaved(fs, []string{"k1", "--flag", "k2"})
	if !*b {
		t.Fatal("--flag 被位置参数吞了")
	}
	if !reflect.DeepEqual(pos, []string{"k1", "k2"}) {
		t.Fatalf("位置参数不对: %v", pos)
	}
}

// TestResolveAddKey add 的公钥来源优先级：--file > 位置参数 > 默认文件。
func TestResolveAddKey(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "k.pub")
	if err := os.WriteFile(kf, []byte("# 注释\n\nssh-ed25519 AAAATEST me@x\n"), 0600); err != nil {
		t.Fatal(err)
	}

	line, err := resolveAddKey(kf, nil)
	if err != nil || line != "ssh-ed25519 AAAATEST me@x" {
		t.Fatalf("--file 该读到首个有效行: %q %v", line, err)
	}

	line, err = resolveAddKey("", []string{"ssh-ed25519", "BBBB", "手机"})
	if err != nil || line != "ssh-ed25519 BBBB 手机" {
		t.Fatalf("位置参数该拼回完整行: %q %v", line, err)
	}

	if _, err = resolveAddKey(filepath.Join(dir, "nonexist"), nil); err == nil {
		t.Fatal("不存在的文件该报错")
	}
	// 无 --file 无位置参数：要么找到默认 key（本机有 ~/.ssh）要么报错，
	// 两个结果都合法——这里只验不 panic 且 err 文案说得清。
	if l, err := resolveAddKey("", nil); err == nil && l == "" {
		t.Fatal("找到默认 key 时 line 不应为空")
	}
}
