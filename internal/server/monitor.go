// 旁路监控接线：auditSink 把每条审计事件双写一份给 monitor 推送器，
// metricsSnapshot 供 monitor 周期抓取。监控链路的一切故障都烂在
// monitor 包里——这里的 Emit 永不阻塞，主流程零感知。
package server

import (
	"fmt"
	"net"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/monitor"
)

// auditSink 替代裸 *auditlog.Writer：Log 先写本地审计文件（保底），
// 再旁路复制一份给监控推送。调用点不用改——签名和 Writer.Log 一样。
type auditSink struct {
	w *auditlog.Writer
	m *monitor.Monitor
	// ok/fail 顺手记认证成败计数，metrics 快照用；免得改 ssh.go 里
	// 七八个 AUTH-OK/FAIL 调用点。
	ok, fail *atomic.Int64
}

func (a *auditSink) Log(event string, kv ...string) {
	a.w.Log(event, kv...)
	switch event {
	case "AUTH-OK":
		a.ok.Add(1)
	case "AUTH-FAIL":
		a.fail.Add(1)
	}
	if a.m != nil {
		a.m.Emit(event, kv...)
	}
}

// metricsSnapshot 是注册给 monitor 的指标提供者：全是无锁读/原子量/
// 一次 Hub 遍历，推送周期里调，必须快。
func (s *Server) metricsSnapshot() map[string]any {
	return map[string]any{
		"uptime_s":         int64(time.Since(s.started) / time.Second),
		"agents_online":    len(s.Hub.Names()),
		"sessions_active":  s.Hub.SessionCount(),
		"relay_to_agent":   s.Hub.BytesToAgent(),
		"relay_from_agent": s.Hub.BytesFromAgent(),
		"auth_ok":          s.authOK.Load(),
		"auth_fail":        s.authFail.Load(),
	}
}

// monitorURLAllowed 拦截明文推送出公网：事件里有用户名、机器名、来源
// IP，ws:// 非回环地址必须显式 monitor.allow_plain 确认（和
// mcp.allow_plain_http 同一套思路）。
func monitorURLAllowed(rawURL string, allowPlain bool) error {
	if rawURL == "" || allowPlain {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("monitor.url 解析失败: %w", err)
	}
	if u.Scheme != "ws" {
		return nil // wss 或不认识的 scheme（让拨号时报错）
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if host == "localhost" {
		return nil
	}
	return fmt.Errorf("monitor.url 是明文 ws:// 且指向非回环地址：监控事件含账号和来源 IP，" +
		"请用 wss://，或确认只在内网/隧道里用并设置 monitor.allow_plain: true")
}
