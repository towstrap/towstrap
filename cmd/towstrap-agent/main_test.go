package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAgentTokenPrecedence(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte("  tsa-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yamlFile := filepath.Join(dir, "yaml-token")
	if err := os.WriteFile(yamlFile, []byte("tsa-from-yaml-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name                                     string
		flagToken, flagFile, env, yamlTok, yamlF string
		want, wantSrc                            string
	}{
		{"显式旗标最高", "tsa-flag", tokFile, "tsa-env", "tsa-yaml", yamlFile, "tsa-flag", "旗标"},
		{"文件旗标次之（去空白）", "", tokFile, "tsa-env", "tsa-yaml", yamlFile, "tsa-from-file", "--agent-token-file"},
		{"环境变量再次", "", "", " tsa-env ", "tsa-yaml", yamlFile, "tsa-env", "环境变量"},
		{"yaml 直写优先于 yaml 文件", "", "", "", "tsa-yaml", yamlFile, "tsa-yaml", "配置 agent_token"},
		{"yaml 文件兜底", "", "", "", "", yamlFile, "tsa-from-yaml-file", "agent_token_file"},
	}
	for _, c := range cases {
		got, src, _, err := resolveAgentToken(c.flagToken, c.flagFile, c.env, c.yamlTok, c.yamlF)
		if err != nil || got != c.want {
			t.Fatalf("%s: got %q err=%v", c.name, got, err)
		}
		if !strings.Contains(src, c.wantSrc) {
			t.Fatalf("%s: 来源说明 %q 应包含 %q", c.name, src, c.wantSrc)
		}
	}

	if _, _, _, err := resolveAgentToken("", filepath.Join(dir, "nope"), "", "", ""); err == nil {
		t.Fatal("token 文件不存在应报错")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := resolveAgentToken("", empty, "", "", ""); err == nil {
		t.Fatal("空 token 文件应报错")
	}
	if _, _, _, err := resolveAgentToken("", "", "", "", filepath.Join(dir, "nope2")); err == nil {
		t.Fatal("yaml 指的 token 文件不存在应报错")
	}
	if _, _, _, err := resolveAgentToken("", "", "", "", ""); err == nil {
		t.Fatal("一个来源都没有应报错")
	}

	// 只有「从文件读」的来源才带出文件路径（远程换发/重连重读的前提）
	_, _, f1, _ := resolveAgentToken("tsa-x", tokFile, "", "", yamlFile)
	if f1 != "" {
		t.Fatalf("--agent-token 来源不该有文件路径: %q", f1)
	}
	_, _, f2, _ := resolveAgentToken("", tokFile, "", "", "")
	if f2 != tokFile {
		t.Fatalf("--agent-token-file 应带出路径: %q", f2)
	}
	_, _, f3, _ := resolveAgentToken("", "", "", "", yamlFile)
	if f3 != yamlFile {
		t.Fatalf("yaml agent_token_file 应带出路径: %q", f3)
	}
}

// refreshURL：ws(s) 换成 http(s)，拼上 /token/refresh；其他 scheme 报错。
func TestRefreshURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"wss://ssh.example.com:443", "https://ssh.example.com:443/token/refresh"},
		{"ws://127.0.0.1:8080", "http://127.0.0.1:8080/token/refresh"},
		{"https://ssh.example.com", "https://ssh.example.com/token/refresh"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080/token/refresh"},
	}
	for _, c := range cases {
		got, err := refreshURL(c.in)
		if err != nil || got != c.want {
			t.Errorf("refreshURL(%q) = %q err=%v, want %q", c.in, got, err, c.want)
		}
	}
	if _, err := refreshURL("ftp://x"); err == nil {
		t.Error("非法 scheme 应报错")
	}
}

// plainCheck：明文 ws:// 只放行回环地址；wss 都放行；--allow-plain 放行一切。
func TestPlainCheck(t *testing.T) {
	cases := []struct {
		server     string
		allowPlain bool
		wantErr    bool
	}{
		{"ws://127.0.0.1:8080", false, false},
		{"ws://localhost:8080", false, false},
		{"ws://[::1]:8080", false, false},
		{"ws://10.0.0.1:8080", false, true},
		{"ws://remote.example.com", false, true},
		{"ws://10.0.0.1:8080", true, false},
		{"wss://remote.example.com", false, false},
	}
	for _, c := range cases {
		err := plainCheck(c.server, c.allowPlain)
		if (err != nil) != c.wantErr {
			t.Errorf("plainCheck(%q, %v) err=%v, wantErr=%v", c.server, c.allowPlain, err, c.wantErr)
		}
	}
}
