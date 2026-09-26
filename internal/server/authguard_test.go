package server

import (
	"fmt"
	"testing"
	"time"
)

func TestAuthGuardLockAndEscalate(t *testing.T) {
	g := &authGuard{
		threshold:     3,
		base:          20 * time.Millisecond,
		window:        time.Minute,
		maxLock:       time.Hour,
		userThreshold: 100,
		ipThreshold:   100, // 只考「账号|IP」这道，IP 维度抬高别先触发
		entries:       make(map[string]*authEntry),
		userEntries:   make(map[string]*authEntry),
	}
	for i := 0; i < 2; i++ {
		g.fail("alice", "1.2.3.4")
		if !g.allowed("alice", "1.2.3.4") {
			t.Fatal("未到阈值不应锁定")
		}
	}
	g.fail("alice", "1.2.3.4")
	if g.allowed("alice", "1.2.3.4") {
		t.Fatal("连到阈值应锁定")
	}
	// 按「账号|IP」记：别人的账号、同账号别的来源都不受牵连
	if !g.allowed("alice", "5.6.7.8") || !g.allowed("bob", "1.2.3.4") {
		t.Fatal("不应牵连别的账号或来源")
	}

	time.Sleep(25 * time.Millisecond)
	if !g.allowed("alice", "1.2.3.4") {
		t.Fatal("锁到期应放行")
	}
	// 解锁后再失败：fails=4，锁定时长翻倍，仍然要锁
	g.fail("alice", "1.2.3.4")
	if g.allowed("alice", "1.2.3.4") {
		t.Fatal("解锁后再失败应再次锁定（时长翻倍）")
	}
}

func TestAuthGuardPassResets(t *testing.T) {
	g := &authGuard{
		threshold:     3,
		base:          time.Hour,
		window:        time.Minute,
		maxLock:       time.Hour,
		userThreshold: 100,
		ipThreshold:   100,
		entries:       make(map[string]*authEntry),
		userEntries:   make(map[string]*authEntry),
	}
	g.fail("alice", "1.2.3.4")
	g.fail("alice", "1.2.3.4")
	g.pass("alice", "1.2.3.4")
	g.fail("alice", "1.2.3.4") // 成功登录清零后从头计数
	if !g.allowed("alice", "1.2.3.4") {
		t.Fatal("成功登录应清零失败计数")
	}
}

func TestAuthGuardWindowDecay(t *testing.T) {
	g := &authGuard{
		threshold:     2,
		base:          time.Hour,
		window:        30 * time.Millisecond,
		maxLock:       time.Hour,
		userThreshold: 100,
		ipThreshold:   100,
		entries:       make(map[string]*authEntry),
		userEntries:   make(map[string]*authEntry),
	}
	g.fail("alice", "1.2.3.4")
	time.Sleep(40 * time.Millisecond)
	g.fail("alice", "1.2.3.4") // 窗口外的失败不累计
	if !g.allowed("alice", "1.2.3.4") {
		t.Fatal("窗口外的失败不应累计锁定")
	}
}

// TestAuthGuardEntryCap 分布式乱喷用户名时失败表有条目上限，内存撑不大。
func TestAuthGuardEntryCap(t *testing.T) {
	g := &authGuard{
		threshold:     100, // 别锁，只看表大小
		base:          time.Hour,
		window:        time.Hour,
		maxLock:       time.Hour,
		maxEntries:    5,
		userThreshold: 1000,
		ipThreshold:   1000,
		entries:       make(map[string]*authEntry),
		userEntries:   make(map[string]*authEntry),
	}
	for i := 0; i < 50; i++ {
		g.fail(fmt.Sprintf("spray-user-%02d", i), "1.2.3.4")
	}
	g.mu.Lock()
	n := len(g.entries)
	g.mu.Unlock()
	if n > g.maxEntries {
		t.Fatalf("失败表应被压到上限以内: %d > %d", n, g.maxEntries)
	}
}

// TestAuthGuardPerUserLock 第二道按账号汇总的门：换着 IP 打同一个账号，
// 累计到 userThreshold 也锁定（挡只对单账号下手的分布式爆破）。
func TestAuthGuardPerUserLock(t *testing.T) {
	g := &authGuard{
		threshold:     100, // 「账号|IP」这道别先触发，只看按账号那道
		userThreshold: 50,
		ipThreshold:   1000, // 每个 IP 只失败一次，IP 道抬高别触发
		base:          time.Hour,
		window:        time.Hour,
		maxLock:       time.Hour,
		entries:       make(map[string]*authEntry),
		userEntries:   make(map[string]*authEntry),
	}
	for i := 1; i <= 50; i++ {
		g.fail("alice", fmt.Sprintf("10.0.0.%d", i))
	}
	if g.allowed("alice", "10.0.0.99") {
		t.Fatal("同一账号换 IP 累计 50 次失败应锁定")
	}
	if !g.allowed("other", "10.0.0.1") {
		t.Fatal("别的账号不应被牵连")
	}
	g.pass("alice", "10.0.0.1")
	if !g.allowed("alice", "10.0.0.99") {
		t.Fatal("成功登录后按账号的锁也应清掉")
	}
}

// TestAuthGuardPerIPLock 第三道按裸来源 IP 的门：换着用户名从一个 IP 刷，
// 每个「账号|IP」对都只失败一次、按账号的表也摊薄了，但 IP 道累计到
// ipThreshold 照样锁——挡「每换个名就重开预算」的绕过；新用户名从这个
// IP 来也被拒，别的 IP 不受影响。pass 不清 IP 计数（一次成功不等于
// 前面攒的失败是假的）。
func TestAuthGuardPerIPLock(t *testing.T) {
	g := &authGuard{
		threshold:     100,  // 「账号|IP」别触发——每对只失败一次
		userThreshold: 1000, // 账号道也别触发——每个用户名只用一次
		ipThreshold:   10,
		base:          time.Hour,
		window:        time.Hour,
		maxLock:       time.Hour,
	}
	for i := 0; i < 10; i++ {
		g.fail(fmt.Sprintf("spray-%02d", i), "9.9.9.9")
	}
	if g.allowed("never-seen", "9.9.9.9") {
		t.Fatal("这个 IP 换了 10 个用户名试错，新名字来也该拒")
	}
	if !g.allowed("never-seen", "8.8.8.8") {
		t.Fatal("别的 IP 不应被牵连")
	}
	g.pass("alice", "9.9.9.9")
	if g.allowed("alice", "9.9.9.9") {
		t.Fatal("pass 不该清 IP 计数——一次成功抹不掉攒下的失败")
	}
}
