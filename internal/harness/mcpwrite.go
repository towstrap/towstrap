package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// mcpwrite.go 把 towstrap 的 MCP 接入真正写进各家 harness 的配置文件
// ——connect print-mcp 只打印片段，connect mcp 用这里的写入器直接落盘。
// 每家的条目形状和 print-mcp 输出的保持一致（同一份 entryFor 产物）。

// MCPTarget 是一家的 MCP 配置文件：DetectDir 存在视为装了该 harness，
// File 是要写入的配置文件，Format 决定走 JSON 合并还是 TOML 节段替换。
type MCPTarget struct {
	ID        string   // 小写短名，--harness 过滤用（如 "claude"）
	Name      string   // 显示名（如 "Claude Code"）
	DetectDir string   // home 下的目录
	File      string   // home 下的配置文件
	Format    string   // "json" | "toml"
	KeyPath   []string // json：服务器条目挂在哪层 map 下（mcpServers / mcp）
	Note      string   // 写完给用户看的附加提示（如 Pi 需要 MCP 扩展）
}

// MCPTable 返回全部可写入的 harness 目标；home 是用户主目录，测试注入临时目录。
func MCPTable(home string) []MCPTarget {
	j := func(elem ...string) string {
		return filepath.Join(append([]string{home}, elem...)...)
	}
	return []MCPTarget{
		{ID: "claude", Name: "Claude Code", DetectDir: j(".claude"), File: j(".claude.json"),
			Format: "json", KeyPath: []string{"mcpServers"}},
		{ID: "codex", Name: "Codex", DetectDir: j(".codex"), File: j(".codex", "config.toml"),
			Format: "toml"},
		{ID: "grok", Name: "Grok Build", DetectDir: j(".grok"), File: j(".grok", "config.toml"),
			Format: "toml"},
		{ID: "cursor", Name: "Cursor", DetectDir: j(".cursor"), File: j(".cursor", "mcp.json"),
			Format: "json", KeyPath: []string{"mcpServers"}},
		{ID: "gemini", Name: "Gemini CLI", DetectDir: j(".gemini"), File: j(".gemini", "settings.json"),
			Format: "json", KeyPath: []string{"mcpServers"}},
		{ID: "opencode", Name: "OpenCode", DetectDir: j(".config", "opencode"), File: j(".config", "opencode", "opencode.json"),
			Format: "json", KeyPath: []string{"mcp"}},
		{ID: "copilot", Name: "GitHub Copilot CLI", DetectDir: j(".copilot"), File: j(".copilot", "mcp-config.json"),
			Format: "json", KeyPath: []string{"mcpServers"}},
		{ID: "devin", Name: "Devin CLI", DetectDir: j(".config", "devin"), File: j(".config", "devin", "mcp_config.json"),
			Format: "json", KeyPath: []string{"mcpServers"}},
		{ID: "pi", Name: "Pi", DetectDir: j(".pi"), File: j(".pi", "agent", "mcp.json"),
			Format: "json", KeyPath: []string{"mcpServers"},
			Note: "Pi 需要 MCP 扩展才加载该文件：pi install npm:pi-mcp-extension"},
	}
}

// MCPStatus 是单个目标的写入结果。
type MCPStatus int

const (
	MCPWritten MCPStatus = iota // 新写入
	MCPUpdated                  // 已有 towstrap 条目，内容不同已替换
	MCPSame                     // 已有条目内容一致，没动
	MCPManual                   // 文件存在但解析不了（可能含注释），改手工合并
	MCPFailed                   // 写入失败
)

func (s MCPStatus) Line() string {
	switch s {
	case MCPWritten:
		return "已写入"
	case MCPUpdated:
		return "已更新"
	case MCPSame:
		return "已有相同配置"
	case MCPManual:
		return "需手工合并"
	default:
		return "失败"
	}
}

// MCPResult 是一个目标的写入结果；Manual 时 Snippet 带手工合并的片段文本。
type MCPResult struct {
	Target  MCPTarget
	Status  MCPStatus
	File    string // 实际写入的文件（~ 展开后的绝对路径）
	Snippet string
	Err     error
}

// WriteMCP 把 towstrap 条目写进选中的 harness 配置文件。
// only 为空 → 写所有 DetectDir 存在的目标；给了就按 ID 写（不管检测）。
func WriteMCP(home string, r MCPRequest, only []string, dry bool) []MCPResult {
	wanted := map[string]bool{}
	for _, id := range only {
		wanted[strings.ToLower(strings.TrimSpace(id))] = true
	}
	var out []MCPResult
	for _, t := range MCPTable(home) {
		if len(wanted) > 0 {
			if !wanted[t.ID] && !wanted[strings.ToLower(t.Name)] {
				continue
			}
		} else if !CheckDir(t.DetectDir) {
			continue
		}
		out = append(out, writeOne(t, r, dry))
	}
	// 用户点名了不认识的 id 要让他知道，别静默吞掉
	if len(wanted) > 0 {
		seen := map[string]bool{}
		for _, res := range out {
			seen[res.Target.ID] = true
			seen[strings.ToLower(res.Target.Name)] = true
		}
		var unknown []string
		for id := range wanted {
			if !seen[id] {
				unknown = append(unknown, id)
			}
		}
		sort.Strings(unknown)
		for _, id := range unknown {
			out = append(out, MCPResult{
				Target: MCPTarget{ID: id, Name: id},
				Status: MCPFailed,
				Err:    fmt.Errorf("不认识的 harness %q（可选：%s）", id, MCPIDs()),
			})
		}
	}
	return out
}

// MCPIDs 返回可 --harness 指定的 id 列表（错误提示里用）。
func MCPIDs() string {
	var ids []string
	for _, t := range MCPTable("~") {
		ids = append(ids, t.ID)
	}
	return strings.Join(ids, ",")
}

func writeOne(t MCPTarget, r MCPRequest, dry bool) MCPResult {
	res := MCPResult{Target: t, File: t.File}
	entry := mcpEntry(t.ID, r)
	if t.Format == "toml" {
		res.Status, res.Snippet, res.Err = writeTOMLSection(t.File, tomlBlock(t.ID, r), dry)
		return res
	}
	// JSON 归一化：文件里读回来的是 map[string]any，和 Go 侧手写的
	// map[string]string 之类直接 DeepEqual 不相等——先走一遍 marshal/
	// unmarshal 让两边同构，幂等比较才可靠。
	if norm, err := normalizeJSON(entry); err == nil {
		entry = norm
	}
	res.Status, res.Snippet, res.Err = writeJSONEntry(t.File, t.KeyPath, entry, dry)
	return res
}

func normalizeJSON(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// mcpEntry 生成某家的 JSON 条目对象（和 print-mcp 的片段形状一一对应）。
func mcpEntry(id string, r MCPRequest) map[string]any {
	auth := map[string]string{"Authorization": "Bearer " + r.Token}
	stdioArgs := []string{r.Command, "--config", r.Config}
	switch id {
	case "claude":
		if r.Stdio {
			return map[string]any{"command": r.Command, "args": []string{"--config", r.Config}}
		}
		return map[string]any{"type": "http", "url": r.URL, "headers": auth}
	case "cursor", "devin":
		if r.Stdio {
			return map[string]any{"command": r.Command, "args": []string{"--config", r.Config}}
		}
		return map[string]any{"url": r.URL, "headers": auth}
	case "gemini":
		if r.Stdio {
			return map[string]any{"command": r.Command, "args": []string{"--config", r.Config}}
		}
		return map[string]any{"httpUrl": r.URL, "headers": auth}
	case "opencode":
		if r.Stdio {
			return map[string]any{"type": "local", "command": stdioArgs, "enabled": true}
		}
		return map[string]any{"type": "remote", "url": r.URL, "headers": auth, "enabled": true}
	case "copilot":
		if r.Stdio {
			return map[string]any{"type": "local", "command": r.Command, "args": []string{"--config", r.Config}, "tools": []string{"*"}}
		}
		return map[string]any{"type": "http", "url": r.URL, "headers": auth, "tools": []string{"*"}}
	case "pi":
		if r.Stdio {
			return map[string]any{"transport": "stdio", "command": r.Command, "args": []string{"--config", r.Config}, "lifecycle": "eager"}
		}
		return map[string]any{"transport": "streamable-http", "url": r.URL, "headers": auth, "lifecycle": "eager"}
	default: // claude 已在上头；兜底当 claude 处理
		if r.Stdio {
			return map[string]any{"command": r.Command, "args": []string{"--config", r.Config}}
		}
		return map[string]any{"type": "http", "url": r.URL, "headers": auth}
	}
}

// tomlBlock 生成 TOML 节段文本（Codex/Grok）；serverID 区分 http_headers
// 和 headers 两种字段名。
func tomlBlock(serverID string, r MCPRequest) string {
	if r.Stdio {
		return fmt.Sprintf("[mcp_servers.towstrap]\ncommand = %q\nargs = [%q, %q]\n",
			r.Command, "--config", r.Config)
	}
	hk := "http_headers"
	if serverID == "grok" {
		hk = "headers"
	}
	return fmt.Sprintf("[mcp_servers.towstrap]\nurl = %q\n%s = { \"Authorization\" = \"Bearer %s\" }\n",
		r.URL, hk, r.Token)
}

// writeJSONEntry 把条目合并进 JSON 配置文件的 keyPath 下（key=towstrap）。
// 文件不存在就新建；存在但解析失败返回 Manual + 片段，绝不覆写看不懂的文件。
func writeJSONEntry(path string, keyPath []string, entry map[string]any, dry bool) (MCPStatus, string, error) {
	obj := map[string]any{}
	existed := false
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		existed = true
		if err := json.Unmarshal(b, &obj); err != nil {
			snip, _ := json.MarshalIndent(map[string]any{keyPath[0]: map[string]any{"towstrap": entry}}, "", "  ")
			return MCPManual, string(snip), nil
		}
	} else if err != nil && !os.IsNotExist(err) {
		return MCPFailed, "", err
	}

	// 沿 keyPath 找到/创建服务器 map
	m := obj
	for _, k := range keyPath {
		next, _ := m[k].(map[string]any)
		if next == nil {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	if old, ok := m["towstrap"]; ok && reflect.DeepEqual(old, entry) {
		return MCPSame, "", nil
	}
	st := MCPWritten
	if _, ok := m["towstrap"]; ok {
		st = MCPUpdated
	}
	m["towstrap"] = entry
	if dry {
		return st, "", nil
	}
	if existed {
		if err := backupFile(path); err != nil {
			return MCPFailed, "", err
		}
	}
	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return MCPFailed, "", err
	}
	mode := os.FileMode(0o600) // 新文件：里面有 token
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm() // 旧文件沿用原权限
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return MCPFailed, "", err
	}
	if err := os.WriteFile(path, append(out, '\n'), mode); err != nil {
		return MCPFailed, "", err
	}
	return st, "", nil
}

// writeTOMLSection 追加或替换 [mcp_servers.towstrap] 节段：
// 同名节段在就先整段抠掉再追新块——幂等，token 换了重跑也干净。
func writeTOMLSection(path, block string, dry bool) (MCPStatus, string, error) {
	const head = "[mcp_servers.towstrap]"
	var body string
	existed := false
	if b, err := os.ReadFile(path); err == nil {
		existed = true
		body = string(b)
	} else if !os.IsNotExist(err) {
		return MCPFailed, "", err
	}

	lines := strings.Split(body, "\n")
	var kept []string
	removed := false
	inSec := false
	for _, ln := range lines {
		trim := strings.TrimSpace(ln)
		switch {
		case trim == head:
			inSec, removed = true, true
		case inSec && strings.HasPrefix(trim, "["):
			inSec = false
			kept = append(kept, ln)
		case inSec:
			// 节段内的行丢弃
		default:
			kept = append(kept, ln)
		}
	}
	if removed {
		// 抠掉节段尾巴上的连续空行，避免越跑越多的空行
		for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
			kept = kept[:len(kept)-1]
		}
		kept = append(kept, "")
	}
	newBody := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if newBody != "" {
		newBody += "\n\n"
	}
	newBody += block

	if strings.TrimSpace(newBody) == strings.TrimSpace(body) {
		return MCPSame, "", nil
	}
	st := MCPWritten
	if removed {
		st = MCPUpdated
	}
	if dry {
		return st, "", nil
	}
	if existed {
		if err := backupFile(path); err != nil {
			return MCPFailed, "", err
		}
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return MCPFailed, "", err
	}
	if err := os.WriteFile(path, []byte(newBody), mode); err != nil {
		return MCPFailed, "", err
	}
	return st, "", nil
}

// backupFile 在改动前留一份 <file>.bak——改坏了能一把找回。
func backupFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path+".bak", b, 0o600)
}
