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
//
// 第三张表按裸来源 IP 记（阈值 60）：堵住「固定一个 IP、不停换用户名喷
// 密码」的空隙——前两张表按用户名分桶，这种打法永远不触发。登录成功
// 不清 IP 表（成功只能说明这个来源里有一个真人，不能把前面的失败抹掉）。
type authGuard struct {
	threshold     int           // 「账号|IP」连续失败多少次开始锁
	userThreshold int           // 按账号汇总的阈值（换 IP 打同一账号也累计）
	ipThreshold   int           // 按裸来源 IP 的阈值（换用户名刷也累计）
	base          time.Duration // 首次锁定时长，此后翻倍
	window        time.Duration // 失败计数的有效窗口，超过则从头计
	maxLock       time.Duration
	// maxEntries 是失败记录表的条目上限（三张表分别算）：乱喷用户名的分布式
	// 爆破在窗口内也能把表撑大，到顶就先清过期的、再淘汰最旧的。
	maxEntries int

	mu          sync.Mutex
	entries     map[string]*authEntry // 键 "user|ip"
	userEntries map[string]*authEntry // 键 user
	ipEntries   map[string]*authEntry // 键 ip
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
		ipThreshold:   60,
		base:          time.Minute,
		window:        15 * time.Minute,
		maxLock:       time.Hour,
		maxEntries:    65536,
		entries:       make(map[string]*authEntry),
		userEntries:   make(map[string]*authEntry),
		ipEntries:     make(map[string]*authEntry),
	}
}

// ensureMaps 惰性建表：测试里直接字面量构造的零值 guard 也能跑。
// 调用方持锁。
func (g *authGuard) ensureMaps() {
	if g.entries == nil {
		g.entries = map[string]*authEntry{}
	}
	if g.userEntries == nil {
		g.userEntries = map[string]*authEntry{}
	}
	if g.ipEntries == nil {
		g.ipEntries = map[string]*authEntry{}
	}
}

func (g *authGuard) allowed(user, ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ensureMaps()
	now := time.Now()
	if e, ok := g.entries[user+"|"+ip]; ok && !now.After(e.lockedTill) {
		return false
	}
	if e, ok := g.userEntries[user]; ok && !now.After(e.lockedTill) {
		return false
	}
	if e, ok := g.ipEntries[ip]; ok && !now.After(e.lockedTill) {
		return false
	}
	return true
}

// ipAllowed 只查来源 IP 维度的锁：用在「没有可信账号名可核」的路径上
// （比如 TOTP 账号的密码燃烧检查）——用户名是攻击者自己填的，不能信。
func (g *authGuard) ipAllowed(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.ipEntries[ip]; ok && !time.Now().After(e.lockedTill) {
		return false
	}
	return true
}

func (g *authGuard) fail(user, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ensureMaps()
	now := time.Now()
	g.failLocked(g.entries, user+"|"+ip, "user+ip", g.threshold, now)
	g.failLocked(g.userEntries, user, "user", g.userThreshold, now)
	g.failLocked(g.ipEntries, ip, "ip", g.ipThreshold, now)
	g.budgetLocked(now)
	g.sweepLocked(now)
}

// failIP 只记来源 IP 一次失败：认证名可疑/不存在时用（TOTP 账号的密码
// 燃烧、管理口令试错等），不往某个具体账号头上记。
func (g *authGuard) failIP(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ensureMaps()
	now := time.Now()
	g.failLocked(g.ipEntries, ip, "ip", g.ipThreshold, now)
	g.budgetLocked(now)
	g.sweepLocked(now)
}

// budgetLocked 是三张表的容量兜底（调用方持锁）。
func (g *authGuard) budgetLocked(now time.Time) {
	if g.maxEntries <= 0 {
		return
	}
	if len(g.entries) >= g.maxEntries {
		g.evictLocked(g.entries, now)
	}
	if len(g.userEntries) >= g.maxEntries {
		g.evictLocked(g.userEntries, now)
	}
	if len(g.ipEntries) >= g.maxEntries {
		g.evictLocked(g.ipEntries, now)
	}
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
	g.ensureMaps()
	delete(g.entries, user+"|"+ip)
	delete(g.userEntries, user)
	// ipEntries 不清：一次成功只能说明这个来源里有人是本人，前面攒的
	// 失败照样算数——不然「每成功一次就刷新 IP 预算」等于白送重试。
}

// sweepLocked 顺手清掉早过期的条目：乱喷用户名的爆破撑不大内存。
func (g *authGuard) sweepLocked(now time.Time) {
	if now.Sub(g.lastSweep) < time.Minute {
		return
	}
	g.lastSweep = now
	sweepMap(g.entries, now, g.window)
	sweepMap(g.userEntries, now, g.window)
	sweepMap(g.ipEntries, now, g.window)
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
