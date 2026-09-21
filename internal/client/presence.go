package client

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"ws2ssh/internal/auditlog"
)

// presence 让被控机的用户能感知到远程会话——ws2ssh 本质是远程控制，
// 默认必须「睁眼能看到」：
//   - 每个会话的开始/结束都追加写审计日志（谁、什么时候连入、何时结束）；
//   - 活跃会话数从 0 变 1、从 1 归 0 时各发一次桌面通知 + wall 广播
//     （多个会话并发不刷屏，只在头一个开始和最后一个结束时各说一次）。
//
// --quiet 只关通知，审计日志照写——想安静是显式动作，不是默认。
type presence struct {
	quiet  bool
	server string
	// notify 默认是 systemNotify；测试里换成记录函数。
	notify func(title, body string)

	path  string
	audit *auditlog.Writer

	mu    sync.Mutex
	count int
	froms map[string]string
}

// DefaultAuditPath 审计日志默认位置：root 服务装法在 /var/lib/ws2ssh，
// 普通用户装法在 ~/.ws2ssh。
func DefaultAuditPath() string {
	if os.Geteuid() == 0 {
		return "/var/lib/ws2ssh/audit.log"
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "ws2ssh-audit.log"
	}
	return filepath.Join(home, ".ws2ssh", "audit.log")
}

func newPresence(cfg Config) *presence {
	path := cfg.AuditLog
	if path == "" {
		path = DefaultAuditPath()
	}
	return &presence{
		quiet:  cfg.Quiet,
		server: cfg.Server,
		notify: systemNotify,
		path:   path,
		audit:  auditlog.Open(path, 0),
	}
}

// fromRe 是 From 字段（「SSH 登录账号@来源 IP/主机」）的白名单：
// 用户名沿用 proto.ValidName 的字符集，主机允许 IPv4/IPv6/主机名。
// agent 不盲信服务器下发的文本——格式对不上就脱敏，纵深防御，
// 即使服务器被攻破也借不了通知渠道注入任意内容。
var fromRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}@[0-9A-Za-z.:-]{1,75}$`)

func safeFrom(from string) string {
	if fromRe.MatchString(from) {
		return from
	}
	slog.Warn("服务器下发的 from 字段格式异常，已脱敏", "len", len(from))
	return "未知来源"
}

func (p *presence) sessionStart(id, from string) {
	from = safeFrom(from)
	var fire bool
	var body string
	p.mu.Lock()
	p.count++
	if p.froms == nil {
		p.froms = make(map[string]string)
	}
	p.froms[id] = from
	if p.count == 1 && !p.quiet {
		fire = true
		body = fmt.Sprintf("%s 正在通过 %s 远程连入本机", from, p.server)
	}
	p.mu.Unlock()
	p.audit.Log("START", "id", id, "from", from)
	if fire && p.notify != nil {
		p.notify("ws2ssh 远程会话开始", body)
	}
}

func (p *presence) sessionEnd(id string) {
	var fire bool
	p.mu.Lock()
	from := p.froms[id]
	delete(p.froms, id)
	if p.count > 0 {
		p.count--
	}
	if p.count == 0 && !p.quiet {
		fire = true
	}
	p.mu.Unlock()
	p.audit.Log("END", "id", id, "from", from)
	if fire && p.notify != nil {
		p.notify("ws2ssh 远程会话结束", "本机已无活跃的远程会话")
	}
}

// Startup 记一条 AGENT-START：agent 进程每次启动连哪台服务器、带什么参数，
// 供事后审计。值里的控制字符由审计器清洗，配置里混进了也弄不脏日志。
func (p *presence) Startup(id, server, shell string, insecure, quiet bool, ver string) {
	p.audit.Log("AGENT-START",
		"version", ver, "id", id, "server", server, "shell", shell,
		"insecure", fmt.Sprintf("%t", insecure), "quiet", fmt.Sprintf("%t", quiet),
		"audit", p.path)
}
