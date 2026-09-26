package main

// init 向导的可测部分：yaml Node 级改写（保注释/幂等/骨架/清键）和
// public_url 规整校验。交互问答层靠手工实测（需要真终端）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/towstrap/towstrap/internal/config"
)

func TestNormPublicURL(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":          "wss://example.com",
		"example.com:443":      "wss://example.com:443",
		"https://example.com":  "wss://example.com",
		"http://a.b:8080/":     "wss://a.b:8080",
		"wss://x.example.com":  "wss://x.example.com",
		"ws://127.0.0.1:7880":  "ws://127.0.0.1:7880",
		"  spaced.example.com": "wss://spaced.example.com",
	} {
		if got := normPublicURL(in); got != want {
			t.Errorf("normPublicURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidPublicURL(t *testing.T) {
	for _, ok := range []string{"wss://a.b", "wss://a.b:443", "ws://127.0.0.1:7880"} {
		if err := validPublicURL(ok); err != nil {
			t.Errorf("validPublicURL(%q) 不该报错: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ftp://x", "wss://", "notaurl"} {
		if err := validPublicURL(bad); err == nil {
			t.Errorf("validPublicURL(%q) 该报错却没报", bad)
		}
	}
}

func readYAMLServer(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		Server map[string]any `yaml:"server"`
	}
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatalf("写出的 yaml 解不开: %v\n%s", err, b)
	}
	return w.Server
}

// 新文件：骨架（http/ssh/users_db）+ init 键一起落下，权限 0600。
func TestWriteServerYAML_Fresh(t *testing.T) {
	p := filepath.Join(t.TempDir(), "server.yaml")
	inv := "code123"
	if !writeServerYAML(p, false, "wss://s.example.com", true, true, &inv) {
		t.Fatal("新文件居然没变化")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("配置权限 %o，要 0600", st.Mode().Perm())
	}
	got := readYAMLServer(t, p)
	want := map[string]any{
		"http":            "127.0.0.1:7880",
		"ssh":             ":7822",
		"users_db":        filepath.Join(filepath.Dir(p), "users.db"),
		"public_url":      "wss://s.example.com",
		"register":        true,
		"register_invite": "code123",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

// 已有文件：注释、无关字段（max_sessions）都得保住；同值重跑返回"没变化"。
func TestWriteServerYAML_Preserves(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.yaml")
	orig := `server:
    # 注释要保住
    ssh: :7822
    users_db: /x/users.db
    max_sessions: 50  # 无关字段也要保住
    register_invite: oldcode
`
	if err := os.WriteFile(p, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if !writeServerYAML(p, true, "wss://new.example.com", true, true, nil) {
		t.Fatal("改了 public_url/register 却报没变化")
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	for _, keep := range []string{"# 注释要保住", "max_sessions: 50", "无关字段也要保住", "oldcode"} {
		if !strings.Contains(s, keep) {
			t.Errorf("改完丢了 %q:\n%s", keep, s)
		}
	}
	got := readYAMLServer(t, p)
	if got["public_url"] != "wss://new.example.com" || got["register"] != true {
		t.Errorf("键没写进去: %v", got)
	}
	if got["register_invite"] != "oldcode" {
		t.Errorf("invite=nil 不该动 register_invite: %v", got["register_invite"])
	}
	// 幂等：同值再来一遍
	if writeServerYAML(p, true, "wss://new.example.com", true, true, nil) {
		t.Error("同值重跑应该返回没变化")
	}
}

// 扁平写法的老文件（键直接铺顶层）：新键必须也写顶层。往它追加
// server: 小节会让那些顶层键全部被 LoadServer 忽略（tls/allow_ips/
// admin_token 静默失效）。
func TestWriteServerYAML_Flat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.yaml")
	orig := `# 扁平写法
http: 127.0.0.1:7880
ssh: :7822
tls: true
allow_ips: [10.0.0.0/8]
`
	if err := os.WriteFile(p, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if !writeServerYAML(p, true, "wss://flat.example.com", true, true, nil) {
		t.Fatal("扁平文件应该写成功")
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	// 顶层键：原有保留 + 新键进顶层；不能长出 server: 小节
	var root map[string]any
	if err := yaml.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root["tls"] != true || root["http"] != "127.0.0.1:7880" {
		t.Fatalf("扁平键丢了: %v", root)
	}
	if root["public_url"] != "wss://flat.example.com" || root["register"] != true {
		t.Fatalf("新键没落到顶层: %v", root)
	}
	if _, hasServer := root["server"]; hasServer {
		t.Fatalf("扁平文件不该出现 server: 顶层键:\n%s", s)
	}
	// LoadServer 能读回全量（扁平+新键都在）
	cfg, err := config.LoadServer(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLS || cfg.PublicURL != "wss://flat.example.com" || !cfg.Register {
		t.Fatalf("LoadServer 读回不对: %+v", cfg)
	}
}

// invite 显式置空：键整个删掉而不是留个空标量。
func TestWriteServerYAML_ClearInvite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.yaml")
	os.WriteFile(p, []byte("server:\n    register_invite: oldcode\n"), 0o600)
	empty := ""
	if !writeServerYAML(p, true, "", false, false, &empty) {
		t.Fatal("清 invite 应该有变化")
	}
	if _, ok := readYAMLServer(t, p)["register_invite"]; ok {
		b, _ := os.ReadFile(p)
		t.Errorf("invite 该整键删掉:\n%s", b)
	}
}

// init 收尾必须把实际监听地址打出来——装完的人要靠这两行接着干活。
// 走 --yes 非交互路径（配置不动），截获 stdout 核对就绪段。
func TestRunInit_PrintsAccessInfo(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.yaml")
	os.WriteFile(p, []byte("server:\n    http: 0.0.0.0:9999\n    ssh: :8822\n    users_db: "+filepath.Join(dir, "users.db")+"\n"), 0o600)

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := runInit([]string{"--yes", "--config", p, "--no-restart"})
	w.Close()
	os.Stdout = old
	if code != 0 {
		t.Fatalf("runInit = %d", code)
	}
	buf := make([]byte, 64<<10)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	for _, want := range []string{
		"配置文件：  " + p,
		"HTTP 监听： 0.0.0.0:9999",
		"SSH 监听：  :8822",
		"对外地址：  没填",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("就绪段缺 %q:\n%s", want, out)
		}
	}
}

// ssh 端口拆分："​:7822" 和 "0.0.0.0:9999" 都要能拿出端口。
func TestSplitHostPort(t *testing.T) {
	for in, wantP := range map[string]string{
		":7822":         "7822",
		"0.0.0.0:9999":  "9999",
		"example.com:1": "1",
	} {
		if _, p, err := splitHostPort(in); err != nil || p != wantP {
			t.Errorf("splitHostPort(%q) = _,%q,%v want port %q", in, p, err, wantP)
		}
	}
	if _, _, err := splitHostPort("noport"); err == nil {
		t.Error("没端口的串该报错")
	}
}
