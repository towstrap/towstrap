package server

import (
	"log/slog"
	"sync"
	"time"
)

// authGuard 给 SSH 密码认证加限速：按「账号|来源 IP」记失败次数，连到阈值
// 就锁定，阈值之上每多失败一次锁定时长翻倍（指数退避）——在线爆破每多试
// 一轮，等待时间成本翻着涨。按账号和来源 IP 双维度记，攻击者刷失败锁不了
// 别人的正常登录。另按账号汇总一个更宽松的阈值（50 次），换着 IP 打同一
// 账号也会被锁；代价是攻击者能故意刷失败让某个账号暂时（1 分钟起）登不上，
// 但他本来也进不来。只在内存里：重启清零，爆破者也要从头来。
type authGuard struct {
	threshold     int           // 「账号|IP」连续失败多少次开始锁
	userThreshold int           // 按账号汇总的阈值（换 IP 打同一账号也累计）
	base          time.Duration // 首次锁定时长，此后翻倍
	window        time.Duration // 失败计数的有效窗口，超过则从头计
	maxLock       time.Duration
	// maxEntries 是失败记录表的条目上限（两张表分别算）：乱喷用户名的分布式
	// 爆破在窗口内也能把表撑大，到顶就先清过期的、再淘汰最旧的。
	maxEntries int

	mu          sync.Mutex
	entries     map[string]*authEntry // 键 "user|ip"
	userEntries map[string]*authEntry // 键 user
	lastSweep   time.Time
}

type authEntry struct {
	fails      int
	lastFail   time.Time
	lockedTill time.Time
}

func newAuthGuard() *authGuard {
	return &authGuard{
		threshold:     5,
		userThreshold: 50,
		base:          time.Minute,
		window:        15 * time.Minute,
		maxLock:       time.Hour,
		maxEntries:    65536,
		entries:       make(map[string]*authEntry),
		userEntries:   make(map[string]*authEntry),
	}
}

func (g *authGuard) allowed(user, ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if e, ok := g.entries[user+"|"+ip]; ok && !now.After(e.lockedTill) {
		return false
	}
	if e, ok := g.userEntries[user]; ok && !now.After(e.lockedTill) {
		return false
	}
	return true
}

func (g *authGuard) fail(user, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	g.failLocked(g.entries, user+"|"+ip, "user+ip", g.threshold, now)
	g.failLocked(g.userEntries, user, "user", g.userThreshold, now)
	if g.maxEntries > 0 {
		if len(g.entries) >= g.maxEntries {
			g.evictLocked(g.entries, now)
		}
		if len(g.userEntries) >= g.maxEntries {
			g.evictLocked(g.userEntries, now)
		}
	}
	g.sweepLocked(now)
}

// failLocked 在一张表里记一次失败（调用方持锁）：取/建条目、计数、到阈值
// 就算退避并设 lockedTill、打日志。scope 区分日志里是哪张表触发的锁。
func (g *authGuard) failLocked(m map[string]*authEntry, key, scope string, threshold int, now time.Time) *authEntry {
	e := m[key]
	if e == nil || now.Sub(e.lastFail) > g.window {
		e = &authEntry{}
		m[key] = e
	}
	e.fails++
	e.lastFail = now
	if e.fails >= threshold && now.After(e.lockedTill) {
		backoff := g.base << min(e.fails-threshold, 6) // 最多翻 6 倍
		if backoff <= 0 || backoff > g.maxLock {
			backoff = g.maxLock
		}
		e.lockedTill = now.Add(backoff)
		slog.Warn("ssh auth locked", "scope", scope, "key", key, "till", e.lockedTill.Format(time.RFC3339))
	}
	return e
}

func (g *authGuard) pass(user, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entries, user+"|"+ip)
	delete(g.userEntries, user)
}

// sweepLocked 顺手清掉早过期的条目：乱喷用户名的爆破撑不大内存。
func (g *authGuard) sweepLocked(now time.Time) {
	if now.Sub(g.lastSweep) < time.Minute {
		return
	}
	g.lastSweep = now
	sweepMap(g.entries, now, g.window)
	sweepMap(g.userEntries, now, g.window)
}

func sweepMap(m map[string]*authEntry, now time.Time, window time.Duration) {
	for k, e := range m {
		if now.After(e.lockedTill) && now.Sub(e.lastFail) > window {
			delete(m, k)
		}
	}
}

// evictLocked 表到顶了：先清过期条目，还超就按 lastFail 淘汰最旧的。
// 被淘汰的可能包括正锁着的条目——攻击把表撑到 6 万条时，牺牲个别锁定
// 换内存上限是值得的。
func (g *authGuard) evictLocked(m map[string]*authEntry, now time.Time) {
	sweepMap(m, now, g.window)
	for len(m) >= g.maxEntries {
		oldestKey := ""
		var oldest time.Time
		first := true
		for k, e := range m {
			if first || e.lastFail.Before(oldest) {
				oldestKey, oldest, first = k, e.lastFail, false
			}
		}
		if first {
			return
		}
		delete(m, oldestKey)
	}
}
