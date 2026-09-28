package harness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func reqHTTP() MCPRequest {
	return MCPRequest{URL: "https://s.example.com:7880/mcp", Token: "tsm-test"}
}

// 新装 Claude：建出 .claude.json，mcpServers.towstrap 是 http 条目，0600。
func TestWriteMCPClaudeNew(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := WriteMCP(home, reqHTTP(), nil, false)
	if len(res) != 1 || res[0].Target.ID != "claude" {
		t.Fatalf("应只写 claude：%+v", res)
	}
	if res[0].Status != MCPWritten {
		t.Fatalf("新写应 MCPWritten，得 %v", res[0].Status)
	}
	fi, err := os.Stat(res[0].File)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("含 token 的配置应 0600，得 %o", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(res[0].File)
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	entry := obj["mcpServers"].(map[string]any)["towstrap"].(map[string]any)
	if entry["url"] != reqHTTP().URL || entry["type"] != "http" {
		t.Fatalf("条目不对：%v", entry)
	}
	if entry["headers"].(map[string]any)["Authorization"] != "Bearer tsm-test" {
		t.Fatal("Authorization 头不对")
	}
}

// 已有别的键的 JSON：合并且不碰别的；重跑同样参数 → MCPSame；换 token →
// MCPUpdated 且留 .bak。
func TestWriteMCPMergeAndIdempotent(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "mcp.json")
	orig := `{"mcpServers":{"other":{"command":"x"}},"theme":"dark"}`
	if err := os.WriteFile(f, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	res := WriteMCP(home, reqHTTP(), []string{"cursor"}, false)
	if res[0].Status != MCPWritten {
		t.Fatalf("merge 应 MCPWritten：%v", res[0].Status)
	}
	b, _ := os.ReadFile(f)
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["theme"] != "dark" {
		t.Fatal("原有 theme 键丢了")
	}
	if _, ok := obj["mcpServers"].(map[string]any)["other"]; !ok {
		t.Fatal("原有 other 服务器丢了")
	}

	// 同参重跑 → Same
	res = WriteMCP(home, reqHTTP(), []string{"cursor"}, false)
	if res[0].Status != MCPSame {
		t.Fatalf("同参重跑应 MCPSame：%v", res[0].Status)
	}
	// 换 token → Updated + .bak
	res = WriteMCP(home, MCPRequest{URL: reqHTTP().URL, Token: "tsm-new"}, []string{"cursor"}, false)
	if res[0].Status != MCPUpdated {
		t.Fatalf("换 token 应 MCPUpdated：%v", res[0].Status)
	}
	if _, err := os.Stat(f + ".bak"); err != nil {
		t.Fatal("更新已有文件应留 .bak")
	}
}

// 解析不了的 JSON（如带注释）→ Manual + 片段，文件原样不动。
func TestWriteMCPManualOnUnparseable(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "devin"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(home, ".config", "devin", "mcp_config.json")
	orig := "// 注释\n{\"mcpServers\":{}}\n"
	if err := os.WriteFile(f, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	res := WriteMCP(home, reqHTTP(), []string{"devin"}, false)
	if res[0].Status != MCPManual {
		t.Fatalf("解析失败应 MCPManual：%v", res[0].Status)
	}
	if res[0].Snippet == "" || !strings.Contains(res[0].Snippet, "towstrap") {
		t.Fatal("Manual 应给出可手工合并的片段")
	}
	b, _ := os.ReadFile(f)
	if string(b) != orig {
		t.Fatal("解析不了的文件不该被动")
	}
}

// Codex：TOML 追加 → 替换 → 幂等。
func TestWriteMCPTOML(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(f, []byte("model = \"o4\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := WriteMCP(home, reqHTTP(), []string{"codex"}, false)
	if res[0].Status != MCPWritten {
		t.Fatalf("首写应 MCPWritten：%v", res[0].Status)
	}
	b, _ := os.ReadFile(f)
	body := string(b)
	if !strings.Contains(body, "[mcp_servers.towstrap]") || !strings.Contains(body, `http_headers = { "Authorization" = "Bearer tsm-test" }`) {
		t.Fatalf("TOML 块不对：\n%s", body)
	}
	if !strings.Contains(body, `model = "o4"`) {
		t.Fatal("原有内容丢了")
	}
	// 换 token 重跑 → 替换同节段，文件里只剩一份
	res = WriteMCP(home, MCPRequest{URL: reqHTTP().URL, Token: "tsm-v2"}, []string{"codex"}, false)
	if res[0].Status != MCPUpdated {
		t.Fatalf("换 token 应 MCPUpdated：%v", res[0].Status)
	}
	b, _ = os.ReadFile(f)
	if strings.Count(string(b), "[mcp_servers.towstrap]") != 1 || !strings.Contains(string(b), "tsm-v2") {
		t.Fatalf("替换后应有且只有一份 towstrap 节段：\n%s", b)
	}
	// 同参再跑 → Same
	res = WriteMCP(home, MCPRequest{URL: reqHTTP().URL, Token: "tsm-v2"}, []string{"codex"}, false)
	if res[0].Status != MCPSame {
		t.Fatalf("同参应 MCPSame：%v", res[0].Status)
	}
}

// 检测机制：--harness 点名的无视 DetectDir；不认识的 id 报出来。
func TestWriteMCPHarnessFilter(t *testing.T) {
	home := t.TempDir() // 什么目录都不建
	res := WriteMCP(home, reqHTTP(), nil, false)
	if len(res) != 0 {
		t.Fatalf("没检测到任何 harness 应空：%+v", res)
	}
	res = WriteMCP(home, reqHTTP(), []string{"pi"}, false)
	if len(res) != 1 || res[0].Status != MCPWritten {
		t.Fatalf("--harness pi 应无视检测写 pi：%+v", res)
	}
	res = WriteMCP(home, reqHTTP(), []string{"bogus"}, false)
	if len(res) != 1 || res[0].Status != MCPFailed {
		t.Fatalf("不认识的 id 应失败：%+v", res)
	}
}

// stdio 方式：OpenCode 要写 type=local + command 数组。
func TestWriteMCPStdio(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "opencode"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := MCPRequest{Stdio: true, Command: "/usr/local/bin/towstrap-mcp", Config: "/home/u/.config/towstrap/mcp.yaml"}
	res := WriteMCP(home, r, []string{"opencode"}, false)
	if res[0].Status != MCPWritten {
		t.Fatalf("stdio 应 MCPWritten：%v", res[0].Status)
	}
	b, _ := os.ReadFile(res[0].File)
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	e := obj["mcp"].(map[string]any)["towstrap"].(map[string]any)
	if e["type"] != "local" {
		t.Fatalf("opencode stdio 应 type=local：%v", e)
	}
	cmd, _ := e["command"].([]any)
	if len(cmd) != 3 || cmd[0] != r.Command {
		t.Fatalf("command 数组不对：%v", e["command"])
	}
}
