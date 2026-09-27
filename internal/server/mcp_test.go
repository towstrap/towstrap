package server

import (
	"strings"
	"testing"
)

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
