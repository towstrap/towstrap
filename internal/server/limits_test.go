package server

import (
	"net"
	"testing"
	"time"
)

// startCapListener 起一个带 connCap 的监听器，把 accept 到的连接交给 channel。
func startCapListener(t *testing.T, maxTotal, maxPerIP int) (net.Listener, string, chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	capped := newConnCap(ln, maxTotal, maxPerIP)
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := capped.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	return ln, ln.Addr().String(), accepted
}

func waitAccepted(t *testing.T, accepted chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c := <-accepted:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("没等到 accept")
		return nil
	}
}

func dialCap(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestConnCapPerIP 同一个 IP 超过每 IP 上限的连接应被监听器直接关闭，
// 关闭一条已接入的连接后名额恢复。
func TestConnCapPerIP(t *testing.T) {
	_, addr, accepted := startCapListener(t, 100, 2)

	dialCap(t, addr)
	dialCap(t, addr)
	s1 := waitAccepted(t, accepted)
	waitAccepted(t, accepted)

	// 第三条（同一 IP）应被直接关闭：读得到 EOF，也不会出现在 accept 里
	c3 := dialCap(t, addr)
	_ = c3.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := c3.Read(buf); err == nil {
		t.Fatal("超过每 IP 上限的连接应被关闭")
	}
	select {
	case <-accepted:
		t.Fatal("超限连接不应进入 accept")
	case <-time.After(300 * time.Millisecond):
	}

	// 释放一条：新连接又能进
	_ = s1.Close()
	dialCap(t, addr)
	waitAccepted(t, accepted)
}

// TestConnCapTotal 全局上限生效。
func TestConnCapTotal(t *testing.T) {
	_, addr, accepted := startCapListener(t, 1, 0)

	dialCap(t, addr)
	waitAccepted(t, accepted)

	c2 := dialCap(t, addr)
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("超过全局上限的连接应被关闭")
	}
}
