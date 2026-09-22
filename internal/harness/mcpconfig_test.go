package harness

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPSnippetsHTTP(t *testing.T) {
	r := MCPRequest{URL: "https://s.example.com:8080/mcp", Token: "tsm-secret"}
	snips := MCPSnippets(r)
	if len(snips) != 6 {
		t.Fatalf("snippets = %d，想要 6", len(snips))
	}
	var sawClaude bool
	for _, s := range snips {
		if s.Harness == "" || s.File == "" || s.Text == "" {
			t.Fatalf("片段字段不全: %+v", s)
		}
		if !strings.Contains(s.Text, r.URL) {
			t.Fatalf("%s 片段没有 url: %s", s.Harness, s.Text)
		}
		if !strings.Contains(s.Text, r.Token) {
			t.Fatalf("%s 片段没有 token: %s", s.Harness, s.Text)
		}
		switch s.Harness {
		case "Claude Code", "Cursor", "Gemini CLI", "OpenCode":
			if !json.Valid([]byte(s.Text)) {
				t.Fatalf("%s 片段不是合法 JSON: %s", s.Harness, s.Text)
			}
		}
		if s.Harness == "Claude Code" {
			sawClaude = true
			if !strings.Contains(s.Extra, "claude mcp add --transport http") {
				t.Fatalf("Claude 缺等价命令: %q", s.Extra)
			}
		}
		if s.Harness == "Codex" && !strings.Contains(s.Text, "http_headers") {
			t.Fatalf("Codex 片段应该用 http_headers 字段: %s", s.Text)
		}
		if s.Harness == "Gemini CLI" && !strings.Contains(s.Text, "httpUrl") {
			t.Fatalf("Gemini 片段应该用 httpUrl 字段: %s", s.Text)
		}
		if s.Harness == "OpenCode" && !strings.Contains(s.Text, `"remote"`) {
			t.Fatalf("OpenCode 片段应该是 type=remote: %s", s.Text)
		}
	}
	if !sawClaude {
		t.Fatal("没有 Claude Code 片段")
	}
}

func TestMCPSnippetsStdio(t *testing.T) {
	r := MCPRequest{Stdio: true, Command: "/usr/local/bin/towstrap-mcp", Config: "/home/u/.config/towstrap/mcp.yaml"}
	snips := MCPSnippets(r)
	if len(snips) != 6 {
		t.Fatalf("snippets = %d，想要 6", len(snips))
	}
	for _, s := range snips {
		if !strings.Contains(s.Text, r.Command) {
			t.Fatalf("%s 片段没有 command: %s", s.Harness, s.Text)
		}
		if !strings.Contains(s.Text, r.Config) {
			t.Fatalf("%s 片段没有 config 路径: %s", s.Harness, s.Text)
		}
		if strings.Contains(s.Text, "Bearer") {
			t.Fatalf("stdio 片段不该出现 token: %s", s.Text)
		}
		switch s.Harness {
		case "Claude Code", "Cursor", "Gemini CLI", "OpenCode":
			if !json.Valid([]byte(s.Text)) {
				t.Fatalf("%s stdio 片段不是合法 JSON: %s", s.Harness, s.Text)
			}
		}
		if s.Harness == "OpenCode" && !strings.Contains(s.Text, `"local"`) {
			t.Fatalf("OpenCode stdio 应该是 type=local: %s", s.Text)
		}
	}
}
