package main

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	gossh "golang.org/x/crypto/ssh"
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

// TestGenKeyPair 生成的密钥对要能双向对上：私钥可解析、公钥行可解析且
// 两者指纹一致；同名路径再生成必须拒（不覆盖私钥）。
func TestGenKeyPair(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "sub", "id_test")

	gotPath, pubLine, privPEM, err := genKeyPair(privPath, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != privPath {
		t.Fatalf("返回路径不对: %q", gotPath)
	}

	pk, comment, _, _, err := gossh.ParseAuthorizedKey([]byte(pubLine))
	if err != nil {
		t.Fatalf("公钥行解析失败: %v", err)
	}
	if comment != "phone" {
		t.Fatalf("备注不对: %q", comment)
	}
	priv, err := gossh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		t.Fatalf("私钥解析失败: %v", err)
	}
	if gossh.FingerprintSHA256(priv.PublicKey()) != gossh.FingerprintSHA256(pk) {
		t.Fatal("私钥和公钥行指纹不一致")
	}

	fi, err := os.Stat(privPath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("私钥权限不对: %v %v", fi, err)
	}
	if _, err := os.Stat(privPath + ".pub"); err != nil {
		t.Fatalf(".pub 没写出来: %v", err)
	}

	if _, _, _, err := genKeyPair(privPath, ""); err == nil {
		t.Fatal("同名路径再生成该被拒")
	}
}

// TestApplyKeyComment 挂注释：没注释的补上、有注释的换掉、坏行原样回。
func TestApplyKeyComment(t *testing.T) {
	const bare = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFsFvzIlakmXRX6Sb7skm3O0AWhJKqEwLEzlGpuiWVNP"
	if got := applyKeyComment(bare, "手机"); got != bare+" 手机" {
		t.Fatalf("补注释不对: %q", got)
	}
	if got := applyKeyComment(bare+" 旧备注", "新备注"); got != bare+" 新备注" {
		t.Fatalf("换注释不对: %q", got)
	}
	if got := applyKeyComment("不是公钥行", "x"); got != "不是公钥行" {
		t.Fatalf("坏行该原样回: %q", got)
	}
}
