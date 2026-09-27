package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestFingerprintFormat(t *testing.T) {
	fp := Fingerprint()
	if !hex64.MatchString(fp) {
		t.Fatalf("指纹应是 64 位小写十六进制，got %q", fp)
	}
	// 同机两次调用一致
	if Fingerprint() != fp {
		t.Fatal("两次调用指纹不一致")
	}
	// 域前缀哈希：结果不是裸 ID 的 sha256，原始值不出哈希外
	raw, err := Raw()
	if err != nil {
		t.Skip("无原始机器 ID", err)
	}
	bare := sha256.Sum256([]byte(raw))
	if fp == hex.EncodeToString(bare[:]) {
		t.Fatal("指纹等于裸 ID 的 sha256——域前缀没生效")
	}
}

func TestPlaceholderUUID(t *testing.T) {
	for _, s := range []string{
		"00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
		"03000200-0400-0500-0006-000700080009", // OEM 默认值
		"", "not-a-uuid",
	} {
		if !isPlaceholderUUID(s) {
			t.Errorf("应判占位: %q", s)
		}
	}
	for _, s := range []string{
		"4C4C4544-0056-4A10-804A-B8C04F343355",
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
	} {
		if isPlaceholderUUID(s) {
			t.Errorf("正常 UUID 不该判占位: %q", s)
		}
	}
}

func TestSourceTagged(t *testing.T) {
	// Source 非空且指纹确实带了来源标签（不是裸 ID 的 sha256）
	src := Source()
	if src == "" {
		t.Skip("无可用机器 ID 来源")
	}
	raw, _ := Raw()
	want := sha256.Sum256([]byte("towstrap-register\n" + src + "\n" + raw))
	if Fingerprint() != hex.EncodeToString(want[:]) {
		t.Fatal("指纹应等于 sha256(前缀+来源+原始值)")
	}
}

func TestPersistedIDRoundTrip(t *testing.T) {
	// persistedID 走 ConfDir()；把 HOME 挪到临时目录隔离（不污染真实配置）。
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	dir, err := ConfDir()
	if err != nil {
		t.Fatal(err)
	}
	id1, err := persistedID()
	if err != nil {
		t.Fatal(err)
	}
	if id1 == "" {
		t.Fatal("兜底 ID 为空")
	}
	id2, err := persistedID()
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("持久化 ID 不稳定: %q vs %q", id1, id2)
	}
	// 文件权限必须是 0600（机器身份不该被别的用户读）
	fi, err := os.Stat(dir + "/machine-id")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("machine-id 权限应为 0600, got %o", fi.Mode().Perm())
	}
}

// 审计项 H1：环境派生的配置目录必须是绝对路径。XDG_CONFIG_HOME 是相对值
// （含引号里没展开的 "~/.config"）时退回 ~/.config/towstrap；HOME 也没有时
// 报错——绝不能退回 cwd 相对路径（cwd 里预置的 agent.yaml 会被信任）。
func TestConfDirAbsoluteOnly(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("覆盖的是普通用户的 XDG/HOME 推导分支")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, ".config", "towstrap")
	for _, xdg := range []string{"relative/dir", ".", "./cfg", "cfg/../cfg2", "~/.config"} {
		t.Setenv("XDG_CONFIG_HOME", xdg)
		d, err := ConfDir()
		if err != nil {
			t.Fatalf("XDG=%q: %v", xdg, err)
		}
		if !filepath.IsAbs(d) || d != want {
			t.Fatalf("XDG=%q 应忽略并退回 %q，got %q", xdg, want, d)
		}
	}
	// 绝对路径的 XDG 生效
	abs := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", abs)
	if d, err := ConfDir(); err != nil || d != filepath.Join(abs, "towstrap") {
		t.Fatalf("绝对 XDG 应生效，got %q err=%v", d, err)
	}
	// HOME 也没了 → 报错，不给相对路径
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if d, err := ConfDir(); err == nil || (d != "" && filepath.IsAbs(d)) {
		t.Fatalf("HOME 未设置应报错，got dir=%q err=%v", d, err)
	}
}
