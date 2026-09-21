package server

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

// connCap 给监听器加并发连接上限：全局 + 每来源 IP，超了直接关闭新连接。
// fail-closed：宁可拒绝新连接，也不让连接洪水把文件描述符和内存吃光
// （默认 ulimit 只有 1024）。每 IP 上限只用在 SSH 端口上：HTTP 端口上多台
// agent 常共用一个出口 IP（NAT），卡每 IP 会把正常机群拒之门外。
type connCap struct {
	net.Listener
	maxTotal int
	maxPerIP int

	mu         sync.Mutex
	total      int
	perIP      map[string]int
	lastLog    time.Time
	suppressed int
}

func newConnCap(l net.Listener, maxTotal, maxPerIP int) *connCap {
	return &connCap{Listener: l, maxTotal: maxTotal, maxPerIP: maxPerIP, perIP: make(map[string]int)}
}

func (l *connCap) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := hostOnly(c.RemoteAddr().String())
		if !l.acquire(ip) {
			l.logReject(ip)
			_ = c.Close()
			continue
		}
		return &cappedConn{Conn: c, release: func() { l.release(ip) }}, nil
	}
}

func (l *connCap) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.maxTotal > 0 && l.total >= l.maxTotal {
		return false
	}
	if l.maxPerIP > 0 && l.perIP[ip] >= l.maxPerIP {
		return false
	}
	l.total++
	l.perIP[ip]++
	return true
}

func (l *connCap) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total > 0 {
		l.total--
	}
	if n := l.perIP[ip] - 1; n <= 0 {
		delete(l.perIP, ip)
	} else {
		l.perIP[ip] = n
	}
}

// logReject 拒绝日志限速：攻击下不能每个连接打一行。
func (l *connCap) logReject(ip string) {
	l.mu.Lock()
	now := time.Now()
	if now.Sub(l.lastLog) < time.Second {
		l.suppressed++
		l.mu.Unlock()
		return
	}
	n := l.suppressed
	l.suppressed = 0
	l.lastLog = now
	l.mu.Unlock()
	slog.Warn("连接数达上限，拒绝新连接", "ip", ip, "rejected_since_last", n,
		"max_total", l.maxTotal, "max_per_ip", l.maxPerIP)
}

// cappedConn 在连接关闭时归还名额（只归还一次）。
type cappedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *cappedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}
