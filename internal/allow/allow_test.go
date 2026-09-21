package allow

import (
	"net"
	"testing"
)

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad ip %q", s)
	}
	return ip
}

func TestEmptyAllowsAll(t *testing.T) {
	var l *List
	if !l.AllowsIP(mustIP(t, "1.2.3.4")) {
		t.Fatal("空名单应放行")
	}
	if !l.AllowsName("anything") {
		t.Fatal("空名单应放行")
	}
	l2, err := Parse(nil)
	if err != nil || !l2.Empty() {
		t.Fatalf("%v %v", l2, err)
	}
}

func TestAllowsIP(t *testing.T) {
	l, err := Parse([]string{"10.0.0.0/8", "192.168.1.5", "127.0.0.1:2222"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ok := range []string{"10.1.2.3", "192.168.1.5", "127.0.0.1"} {
		if !l.AllowsIP(mustIP(t, ok)) {
			t.Errorf("%s 应放行", ok)
		}
	}
	for _, no := range []string{"11.0.0.1", "192.168.1.6"} {
		if l.AllowsIP(mustIP(t, no)) {
			t.Errorf("%s 应拦截", no)
		}
	}
}

func TestAllowsName(t *testing.T) {
	l, err := Parse([]string{"office", "home"})
	if err != nil {
		t.Fatal(err)
	}
	if !l.AllowsName("office") || !l.AllowsName("home") {
		t.Fatal("名单内的名字应放行")
	}
	if l.AllowsName("evil") {
		t.Fatal("名单外的名字应拦截")
	}
}

func TestAllowsRemoteAndAddr(t *testing.T) {
	l, err := Parse([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if !l.AllowsRemote("10.1.2.3:55555") {
		t.Fatal("应放行")
	}
	if l.AllowsRemote("8.8.8.8:22") {
		t.Fatal("应拦截")
	}
	ta := &net.TCPAddr{IP: mustIP(t, "10.9.9.9"), Port: 1}
	if !l.AllowsAddr(ta) {
		t.Fatal("应放行")
	}
}

func TestParseError(t *testing.T) {
	if _, err := Parse([]string{"10.0.0.0/99"}); err == nil {
		t.Fatal("坏网段应报错")
	}
}
