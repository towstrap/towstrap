package server

import (
	"strings"
	"testing"
)

// MCP 走明文 HTTP 时 Bearer token 会裸奔：只允许 TLS、显式放行、或回环监听。
func TestMCPPlainHTTPAllowed(t *testing.T) {
	cases := []struct {
		addr       string
		tls, allow bool
		wantErr    bool
	}{
		{"0.0.0.0:8080", true, false, false},    // TLS 开了就行
		{"0.0.0.0:8080", false, true, false},    // 显式放行
		{"127.0.0.1:8080", false, false, false}, // 回环：本机调试
		{"[::1]:8080", false, false, false},
		{"localhost:8080", false, false, false},
		{":8080", false, false, true}, // 空 host = 全网卡
		{"0.0.0.0:8080", false, false, true},
		{"10.0.0.1:8080", false, false, true},
		{"192.168.1.5:8080", false, false, true},
	}
	for _, c := range cases {
		err := mcpPlainHTTPAllowed(c.addr, c.tls, c.allow)
		if (err != nil) != c.wantErr {
			t.Errorf("mcpPlainHTTPAllowed(%q, tls=%v, allow=%v) err=%v, wantErr=%v",
				c.addr, c.tls, c.allow, err, c.wantErr)
		}
	}
}

// cleanHost 只放行主机名/IPv6 字符集：客户端能控制的 Host 头/absolute-form
// 请求行不许带进 $()、< >、%、空白这类能污染安装脚本和落地页的东西。
func TestCleanHost(t *testing.T) {
	good := []string{
		"example.com", "Example.COM:8443", "10.0.0.1", "10.0.0.1:7880",
		"[::1]", "[::1]:8443", "my-host.example.com", "a_b.example.com",
		"localhost:7880",
	}
	for _, h := range good {
		if got := cleanHost(h); got != h {
			t.Errorf("cleanHost(%q) = %q，合法主机名不该被洗掉", h, got)
		}
	}
	bad := []string{
		"", "evil.example$(id)", "evil.example;id", "evil.example<b>x</b>",
		"evil.example%3Cscript%3E", "evil example", "a`id`", `a"id"`,
		"a'b", "a/b", `a\b`, "a|b", "a&b", "a{b}", "a*b", "a?b",
		strings.Repeat("a", 300),
	}
	for _, h := range bad {
		if got := cleanHost(h); got != "" {
			t.Errorf("cleanHost(%q) = %q，带怪字符的 Host 应判脏", h, got)
		}
	}
}
