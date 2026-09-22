package server

import "testing"

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
