package server

import "testing"

func TestMonitorURLAllowed(t *testing.T) {
	cases := []struct {
		name       string
		url        string
		allowPlain bool
		wantErr    bool
	}{
		{"空地址=关闭", "", false, false},
		{"ws 回环 IP", "ws://127.0.0.1:9090/mon", false, false},
		{"ws localhost", "ws://localhost:9090/mon", false, false},
		{"ws 非回环拒绝", "ws://10.0.0.5:9090/mon", false, true},
		{"ws 域名拒绝", "ws://mon.internal/mon", false, true},
		{"wss 任意放行", "wss://mon.internal/mon", false, false},
		{"allow_plain 放行明文", "ws://10.0.0.5:9090/mon", true, false},
		{"坏 URL 报错", "://bad", false, true},
	}
	for _, c := range cases {
		err := monitorURLAllowed(c.url, c.allowPlain)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

func TestAuditSinkCountsAuth(t *testing.T) {
	s := New(Config{})
	s.audit.Log("AUTH-OK", "user", "a+b")
	s.audit.Log("AUTH-FAIL", "user", "a+b")
	s.audit.Log("SESSION-START", "id", "s1")
	if s.authOK.Load() != 1 || s.authFail.Load() != 1 {
		t.Fatalf("认证计数不对: ok=%d fail=%d", s.authOK.Load(), s.authFail.Load())
	}
	if got := s.metricsSnapshot()["auth_ok"]; got != int64(1) {
		t.Fatalf("metrics 快照没带认证计数: %v", got)
	}
}
