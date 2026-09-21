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
	if err := os.WriteFile(tokFile, []byte("  w2s-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yamlFile := filepath.Join(dir, "yaml-token")
	if err := os.WriteFile(yamlFile, []byte("w2s-from-yaml-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name                                     string
		flagToken, flagFile, env, yamlTok, yamlF string
		want, wantSrc                            string
	}{
		{"显式旗标最高", "w2s-flag", tokFile, "w2s-env", "w2s-yaml", yamlFile, "w2s-flag", "旗标"},
		{"文件旗标次之（去空白）", "", tokFile, "w2s-env", "w2s-yaml", yamlFile, "w2s-from-file", "--agent-token-file"},
		{"环境变量再次", "", "", " w2s-env ", "w2s-yaml", yamlFile, "w2s-env", "环境变量"},
		{"yaml 直写优先于 yaml 文件", "", "", "", "w2s-yaml", yamlFile, "w2s-yaml", "配置 agent_token"},
		{"yaml 文件兜底", "", "", "", "", yamlFile, "w2s-from-yaml-file", "agent_token_file"},
	}
	for _, c := range cases {
		got, src, err := resolveAgentToken(c.flagToken, c.flagFile, c.env, c.yamlTok, c.yamlF)
		if err != nil || got != c.want {
			t.Fatalf("%s: got %q err=%v", c.name, got, err)
		}
		if !strings.Contains(src, c.wantSrc) {
			t.Fatalf("%s: 来源说明 %q 应包含 %q", c.name, src, c.wantSrc)
		}
	}

	if _, _, err := resolveAgentToken("", filepath.Join(dir, "nope"), "", "", ""); err == nil {
		t.Fatal("token 文件不存在应报错")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAgentToken("", empty, "", "", ""); err == nil {
		t.Fatal("空 token 文件应报错")
	}
	if _, _, err := resolveAgentToken("", "", "", "", filepath.Join(dir, "nope2")); err == nil {
		t.Fatal("yaml 指的 token 文件不存在应报错")
	}
	if _, _, err := resolveAgentToken("", "", "", "", ""); err == nil {
		t.Fatal("一个来源都没有应报错")
	}
}
