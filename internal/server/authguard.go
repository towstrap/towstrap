package server

import (
	"log/slog"
	"sync"
	"time"
)

// authGuard 给 SSH 密码认证加限速：按「账号|来源 IP」记失败次数，连到阈值
// 就锁定，阈值之上每多失败一次锁定时长翻倍（指数退避）——在线爆破每多试
// 一轮，等待时间成本翻着涨。按账号和来源 IP 双维度记，攻击者刷失败锁不了
// 别人的正常登录。只在内存里：重启清零，爆破者也要从头来。
type authGuard struct {
	threshold int           // 连续失败多少次开始锁
	base      time.Duration // 首次锁定时长，此后翻倍
	window    time.Duration // 失败计数的有效窗口，超过则从头计
	maxLock   time.Duration
	// maxEntries 是失败记录表的条目上限：乱喷用户名的分布式爆破在窗口内
	// 也能把表撑大，到顶就先清过期的、再淘汰最旧的。
	maxEntries int

	mu        sync.Mutex
	entries   map[string]*authEntry
	lastSweep time.Time
}

type authEntry struct {
	fails      int
	lastFail   time.Time
	lockedTill time.Time
}

func newAuthGuard() *authGuard {
	return &authGuard{
		threshold:  5,
		base:       time.Minute,
		window:     15 * time.Minute,
		maxLock:    time.Hour,
		maxEntries: 65536,
		entries:    make(map[string]*authEntry),
	}
}

func (g *authGuard) allowed(user, ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.entries[user+"|"+ip]
	if !ok {
		return true
	}
	return time.Now().After(e.lockedTill)
}

func (g *authGuard) fail(user, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := user + "|" + ip
	now := time.Now()
	e := g.entries[key]
	if e == nil || now.Sub(e.lastFail) > g.window {
		e = &authEntry{}
		g.entries[key] = e
	}
	e.fails++
	e.lastFail = now
	if e.fails >= g.threshold && now.After(e.lockedTill) {
		backoff := g.base << min(e.fails-g.threshold, 6) // 最多翻 6 倍
		if backoff <= 0 || backoff > g.maxLock {
			backoff = g.maxLock
		}
		e.lockedTill = now.Add(backoff)
		slog.Warn("ssh auth locked", "user", user, "ip", ip, "till", e.lockedTill.Format(time.RFC3339))
	}
	if g.maxEntries > 0 && len(g.entries) >= g.maxEntries {
		g.evictLocked(now)
	}
	g.sweepLocked(now)
}

func (g *authGuard) pass(user, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entries, user+"|"+ip)
}

// sweepLocked 顺手清掉早过期的条目：乱喷用户名的爆破撑不大内存。
func (g *authGuard) sweepLocked(now time.Time) {
	if now.Sub(g.lastSweep) < time.Minute {
		return
	}
	g.lastSweep = now
	for k, e := range g.entries {
		if now.After(e.lockedTill) && now.Sub(e.lastFail) > g.window {
			delete(g.entries, k)
		}
	}
}

// evictLocked 表到顶了：先清过期条目，还超就按 lastFail 淘汰最旧的。
// 被淘汰的可能包括正锁着的条目——攻击把表撑到 6 万条时，牺牲个别锁定
// 换内存上限是值得的。
func (g *authGuard) evictLocked(now time.Time) {
	for k, e := range g.entries {
		if now.After(e.lockedTill) && now.Sub(e.lastFail) > g.window {
			delete(g.entries, k)
		}
	}
	for len(g.entries) >= g.maxEntries {
		oldestKey := ""
		var oldest time.Time
		first := true
		for k, e := range g.entries {
			if first || e.lastFail.Before(oldest) {
				oldestKey, oldest, first = k, e.lastFail, false
			}
		}
		if first {
			return
		}
		delete(g.entries, oldestKey)
	}
}
