package harness

import (
	"encoding/json"
	"fmt"
)

// MCPRequest 描述要为各家 harness 生成哪种接入方式的 MCP 配置片段。
// HTTP 方式填 URL+Token；Stdio 方式置 Stdio 并填 Command/Config。
type MCPRequest struct {
	URL     string // 服务器内嵌 MCP 地址，如 https://S:8080/mcp
	Token   string // w2m- token，进 Authorization: Bearer 头
	Stdio   bool   // true → 本机 ws2ssh-mcp 的 stdio 片段
	Command string // stdio：ws2ssh-mcp 可执行文件绝对路径
	Config  string // stdio：mcp.yaml 路径
}

// Snippet 是一家的配置片段：标题、该写进哪个文件、片段本体、附加说明。
type Snippet struct {
	Harness string
	File    string // 配置文件位置（~ 缩写，仅提示用）
	Extra   string // 额外说明，可空（如等价的 CLI 命令）
	Text    string // 片段本体
}

// MCPSnippets 为各家支持 MCP 的 harness 各生成一段配置。纯函数，可测。
func MCPSnippets(r MCPRequest) []Snippet {
	return []Snippet{
		claude(r), codex(r), grok(r), cursor(r), gemini(r), opencode(r),
	}
}

func jsonSnippet(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func authHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// Claude Code：~/.claude.json（或项目 .mcp.json）的 mcpServers。
// HTTP 片段带 "type":"http"；stdio 是 command/args。
func claude(r MCPRequest) Snippet {
	s := Snippet{Harness: "Claude Code", File: "~/.claude.json（或项目 .mcp.json）"}
	if r.Stdio {
		s.Text = jsonSnippet(map[string]any{
			"mcpServers": map[string]any{
				"ws2ssh": map[string]any{
					"command": r.Command,
					"args":    []string{"--config", r.Config},
				},
			},
		})
		return s
	}
	s.Text = jsonSnippet(map[string]any{
		"mcpServers": map[string]any{
			"ws2ssh": map[string]any{
				"type":    "http",
				"url":     r.URL,
				"headers": authHeader(r.Token),
			},
		},
	})
	s.Extra = "也可以直接跑：claude mcp add --transport http ws2ssh " + r.URL +
		" --header \"Authorization: Bearer " + r.Token + "\""
	return s
}

// Codex：~/.codex/config.toml 的 [mcp_servers.<id>]。
// 远程 streamable HTTP 用 url + http_headers（静态请求头）。
// 字段名来源：https://developers.openai.com/codex/config-reference
// （mcp_servers.<id>.url / mcp_servers.<id>.http_headers）
func codex(r MCPRequest) Snippet {
	s := Snippet{Harness: "Codex", File: "~/.codex/config.toml"}
	if r.Stdio {
		s.Text = fmt.Sprintf("[mcp_servers.ws2ssh]\ncommand = %q\nargs = [%q, %q]\n",
			r.Command, "--config", r.Config)
		return s
	}
	s.Text = fmt.Sprintf("[mcp_servers.ws2ssh]\nurl = %q\nhttp_headers = { \"Authorization\" = \"Bearer %s\" }\n",
		r.URL, r.Token)
	return s
}

// Grok Build：~/.grok/config.toml 的 [mcp_servers.<id>]。
// 远程用 url + headers 内联表。字段名来源（本机已核实）：
// ~/.grok/docs/user-guide/07-mcp-servers.md
func grok(r MCPRequest) Snippet {
	s := Snippet{Harness: "Grok Build", File: "~/.grok/config.toml"}
	if r.Stdio {
		s.Text = fmt.Sprintf("[mcp_servers.ws2ssh]\ncommand = %q\nargs = [%q, %q]\n",
			r.Command, "--config", r.Config)
		return s
	}
	s.Text = fmt.Sprintf("[mcp_servers.ws2ssh]\nurl = %q\nheaders = { \"Authorization\" = \"Bearer %s\" }\n",
		r.URL, r.Token)
	return s
}

// Cursor：~/.cursor/mcp.json 的 mcpServers。远程 url + headers；stdio command/args。
func cursor(r MCPRequest) Snippet {
	s := Snippet{Harness: "Cursor", File: "~/.cursor/mcp.json"}
	entry := map[string]any{}
	if r.Stdio {
		entry["command"] = r.Command
		entry["args"] = []string{"--config", r.Config}
	} else {
		entry["url"] = r.URL
		entry["headers"] = authHeader(r.Token)
	}
	s.Text = jsonSnippet(map[string]any{"mcpServers": map[string]any{"ws2ssh": entry}})
	return s
}

// Gemini CLI：~/.gemini/settings.json 的 mcpServers。
// 远程 streamable HTTP 用 httpUrl + headers（url 是 SSE 传输，别用错）；
// stdio command/args。字段名来源：
// https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md
func gemini(r MCPRequest) Snippet {
	s := Snippet{Harness: "Gemini CLI", File: "~/.gemini/settings.json"}
	entry := map[string]any{}
	if r.Stdio {
		entry["command"] = r.Command
		entry["args"] = []string{"--config", r.Config}
	} else {
		entry["httpUrl"] = r.URL
		entry["headers"] = authHeader(r.Token)
	}
	s.Text = jsonSnippet(map[string]any{"mcpServers": map[string]any{"ws2ssh": entry}})
	return s
}

// OpenCode：~/.config/opencode/opencode.json 的 mcp.<name>。
// 远程 {"type":"remote","url","headers"}；本地 {"type":"local","command":[…]}
// （command 是含参数的整数组，没有单独 args 字段）。字段名来源：
// https://opencode.ai/docs/mcp-servers/
func opencode(r MCPRequest) Snippet {
	s := Snippet{Harness: "OpenCode", File: "~/.config/opencode/opencode.json"}
	entry := map[string]any{"enabled": true}
	if r.Stdio {
		entry["type"] = "local"
		entry["command"] = []string{r.Command, "--config", r.Config}
	} else {
		entry["type"] = "remote"
		entry["url"] = r.URL
		entry["headers"] = authHeader(r.Token)
	}
	s.Text = jsonSnippet(map[string]any{"mcp": map[string]any{"ws2ssh": entry}})
	return s
}
