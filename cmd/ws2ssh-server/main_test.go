package main

import "testing"

// mcpEndpointURL 的 public_url 是 ws/wss scheme，打印给 MCP 客户端前
// 要换成 http/https；其他形式原样保留。
func TestMCPEndpointURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"wss://ssh.example.com:443", "https://ssh.example.com:443/mcp"},
		{"ws://127.0.0.1:8080", "http://127.0.0.1:8080/mcp"},
		{"https://ssh.example.com", "https://ssh.example.com/mcp"},
		{"wss://host/", "https://host/mcp"}, // 尾部斜杠去掉再拼
		{"", "https://<服务器>:<HTTP端口>/mcp"},  // 没配 public_url 留占位
	}
	for _, c := range cases {
		if got := mcpEndpointURL(c.in, ""); got != c.want {
			t.Errorf("mcpEndpointURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
