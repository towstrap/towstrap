package client

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"ws2ssh/internal/auditlog"
)

// presence 让被控机的用户能感知到远程会话——ws2ssh 本质是远程控制，
// 默认必须「睁眼能看到」：
//   - 每个会话的开始/结束都追加写审计日志（谁、什么时候、跑什么命令、
//     何时结束）；
//   - 活跃会话数从 0 变 1、从 1 归 0 时各发一次桌面通知 + wall 广播
//     （多个会话并发不刷屏，只在头一个开始和最后一个结束时各说一次）；
//   - 同一来源的通知有冷却（默认 10 分钟）：LLM/自动化会一分钟连几十次
//     执行命令，逐条弹通知就是风暴——通知压住，审计照样一条不落。
//
// --quiet 只关通知，审计日志照写——想安静是显式动作，不是默认。
type presence struct {
	quiet  bool
	server string
	// notify 默认是 systemNotify；测试里换成记录函数。
	notify func(title, body string)

	path  string
	audit *auditlog.Writer

	mu         sync.Mutex
	count      int
	froms      map[string]string
	cooldown   time.Duration        // 同一来源两次「开始」通知的最小间隔
	lastNotify map[string]time.Time // 按来源记上次通知时间
	announced  bool                 // 本轮 0→1 的开始通知确实发过（结束通知要跟它配对）
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
		quiet:    cfg.Quiet,
		server:   cfg.Server,
		notify:   systemNotify,
		path:     path,
		audit:    auditlog.Open(path, 0),
		cooldown: 10 * time.Minute,
	}
}

// fromRe 是 From 字段（「来源@IP/主机」）的白名单：
// 用户名沿用 proto.ValidName 的字符集，另允许冒号——服务器内嵌 MCP 的
// 来源形如「mcp:客户端名@IP」。主机允许 IPv4/IPv6/主机名。
// agent 不盲信服务器下发的文本——格式对不上就脱敏，纵深防御，
// 即使服务器被攻破也借不了通知渠道注入任意内容。
var fromRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}@[0-9A-Za-z.:-]{1,75}$`)

func safeFrom(from string) string {
	if fromRe.MatchString(from) {
		return from
	}
	slog.Warn("服务器下发的 from 字段格式异常，已脱敏", "len", len(from))
	return "未知来源"
}

// auditCmd 把会话命令压成审计字段：空命令记 "-"，超过 512 字节截断标记——
// 每条命令都要进审计，但一行不能无限长。
func auditCmd(cmd string) string {
	if cmd == "" {
		return "-"
	}
	if len(cmd) > 512 {
		return cmd[:512] + "…(truncated)"
	}
	return cmd
}

func (p *presence) sessionStart(id, from, mode, cmd string) {
	from = safeFrom(from)
	var fire bool
	var body string
	now := time.Now()
	p.mu.Lock()
	p.count++
	if p.froms == nil {
		p.froms = make(map[string]string)
	}
	p.froms[id] = from
	if p.count == 1 && !p.quiet && now.Sub(p.lastNotify[from]) >= p.cooldown {
		fire = true
		if p.lastNotify == nil {
			p.lastNotify = make(map[string]time.Time)
		}
		p.lastNotify[from] = now
		p.announced = true
		if cmd != "" {
			body = fmt.Sprintf("%s 正在通过 %s 在本机执行命令", from, p.server)
		} else {
			body = fmt.Sprintf("%s 正在通过 %s 远程连入本机", from, p.server)
		}
	}
	p.mu.Unlock()
	p.audit.Log("START", "id", id, "from", from, "mode", mode, "cmd", auditCmd(cmd))
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
	// 结束通知只跟「确实弹过开始通知」的那一轮配对：被冷却压住的会话
	// 不补结束通知，不然通知和内容对不上。
	if p.count == 0 && !p.quiet && p.announced {
		fire = true
		p.announced = false
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
		"uid", fmt.Sprintf("%d", os.Geteuid()),
		"audit", p.path)
}
