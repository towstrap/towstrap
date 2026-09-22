package client

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"towstrap/internal/auditlog"
)

// TestPresenceNotifyTransitions 通知只在活跃数 0→1 和 1→0 的边沿发，
// 并发会话不刷屏；全部结束后再来会话要再通知。
func TestPresenceNotifyTransitions(t *testing.T) {
	var mu sync.Mutex
	var notes []string
	p := &presence{
		server: "wss://srv:443",
		notify: func(title, body string) {
			mu.Lock()
			defer mu.Unlock()
			notes = append(notes, title+" | "+body)
		},
	}

	p.sessionStart("s1", "alice@1.2.3.4", "pty", "")
	p.sessionStart("s2", "bob@5.6.7.8", "pty", "")
	if len(notes) != 1 {
		t.Fatalf("两个并发会话只应通知一次开始, got %d: %v", len(notes), notes)
	}
	if !strings.Contains(notes[0], "alice@1.2.3.4") || !strings.Contains(notes[0], "wss://srv:443") {
		t.Fatalf("开始通知应带来源和服务器: %q", notes[0])
	}

	p.sessionEnd("s1")
	if len(notes) != 1 {
		t.Fatalf("还有活跃会话时不应发结束通知, got %d: %v", len(notes), notes)
	}
	p.sessionEnd("s2")
	if len(notes) != 2 {
		t.Fatalf("最后一个会话结束应通知, got %d: %v", len(notes), notes)
	}

	p.sessionStart("s3", "carol@9.9.9.9", "pty", "")
	if len(notes) != 3 {
		t.Fatalf("清零后再来会话应再次通知, got %d: %v", len(notes), notes)
	}
}

// TestSafeFrom From 白名单：合法来源放行，注入尝试一律脱敏。
func TestSafeFrom(t *testing.T) {
	for _, ok := range []string{"alice@1.2.3.4", "office@::1", "a.b_c@host.example.com", "mcp:laptop@127.0.0.1"} {
		if got := safeFrom(ok); got != ok {
			t.Fatalf("%q 应放行, got %q", ok, got)
		}
	}
	for _, bad := range []string{
		`alice"@(display dialog "pwned")`, // AppleScript 注入
		"alice@1.2.3.4\n第二行",              // 换行 smuggling
		`$(reboot)@1.2.3.4`,               // shell 注入
		"-u critical x@1.2.3.4",           // 旗标注入（notify-send）
		"",
	} {
		if got := safeFrom(bad); got != "未知来源" {
			t.Fatalf("%q 应脱敏, got %q", bad, got)
		}
	}
}

// TestPresenceSanitizesFrom 通知和审计里都拿不到未过白名单的 From。
func TestPresenceSanitizesFrom(t *testing.T) {
	var mu sync.Mutex
	var notes []string
	path := filepath.Join(t.TempDir(), "audit.log")
	p := &presence{
		server: "wss://srv:443",
		path:   path,
		audit:  auditlog.Open(path, 0),
		notify: func(title, body string) {
			mu.Lock()
			defer mu.Unlock()
			notes = append(notes, title+" | "+body)
		},
	}
	p.sessionStart("s1", `alice"@(display dialog "pwned")`, "pty", "")
	p.sessionEnd("s1")

	if len(notes) != 2 {
		t.Fatalf("应有一条开始一条结束通知: %v", notes)
	}
	for _, n := range notes {
		if strings.Contains(n, "pwned") || strings.Contains(n, `display dialog`) {
			t.Fatalf("通知里不应出现注入内容: %q", n)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "pwned") {
		t.Fatalf("审计日志不应出现注入内容: %q", raw)
	}
	if !strings.Contains(string(raw), "from=未知来源") {
		t.Fatalf("审计应记录脱敏后的来源: %q", raw)
	}
}

// TestPresenceStartup 启动审计：AGENT-START 一行记全服务器和参数，
// 配置值里的控制字符清掉，日志行数不被撑爆。
func TestPresenceStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	p := &presence{server: "s", path: path, audit: auditlog.Open(path, 0), notify: func(string, string) {}}
	p.Startup("box", "wss://srv:443", "/bin/bash\nrm -rf /", true, false, "0.3.0")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "AGENT-START version=0.3.0 id=box server=wss://srv:443") {
		t.Fatalf("缺启动记录: %q", got)
	}
	if !strings.Contains(got, "shell=/bin/bashrm -rf /") {
		t.Fatalf("shell 参数应去掉换行: %q", got)
	}
	if !strings.Contains(got, "insecure=true quiet=false") {
		t.Fatalf("应记录 insecure/quiet: %q", got)
	}
	if n := strings.Count(got, "\n"); n != 1 {
		t.Fatalf("启动记录应恰好一行, got %d: %q", n, got)
	}
}

func TestPresenceQuiet(t *testing.T) {
	p := &presence{
		quiet:  true,
		notify: func(title, body string) { t.Errorf("quiet 下不应通知: %s %s", title, body) },
	}
	p.sessionStart("s1", "alice@1.2.3.4", "pty", "")
	p.sessionEnd("s1")
}

func TestPresenceAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	p := &presence{
		server: "wss://srv:443",
		path:   path,
		audit:  auditlog.Open(path, 0),
		notify: func(string, string) {},
	}
	p.sessionStart("s1", "alice@1.2.3.4", "pty", "")
	p.sessionEnd("s1")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "START id=s1 from=alice@1.2.3.4") {
		t.Fatalf("缺 START 记录: %q", got)
	}
	if !strings.Contains(got, "END id=s1 from=alice@1.2.3.4") {
		t.Fatalf("缺 END 记录: %q", got)
	}

	// 追加写：第二条会话不能覆盖第一条
	p2 := &presence{server: "s", path: path, notify: func(string, string) {}}
	p2.sessionStart("s9", "bob@1.1.1.1", "pty", "")
	p2.sessionEnd("s9")
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), "alice@1.2.3.4") {
		t.Fatalf("追加打开后旧记录没了: %q", raw)
	}
}

// TestPresenceBadPath 打不开的路径只报一次错、不 panic、不影响计数。
func TestPresenceBadPath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &presence{
		path:   filepath.Join(blocker, "audit.log"), // blocker 是文件，建目录必失败
		audit:  auditlog.Open(filepath.Join(blocker, "audit.log"), 0),
		notify: func(string, string) {},
	}
	p.sessionStart("s1", "alice@1.2.3.4", "pty", "")
	p.sessionEnd("s1")
	p.sessionStart("s2", "bob@1.1.1.1", "pty", "")
	p.sessionEnd("s2")
}

// TestPresenceNotifyCooldown 同一来源在冷却期内的连续短会话只弹一对通知
// （LLM/自动化会一分钟连几十次，逐条弹就是通知风暴）；冷却设 0 恢复逐对弹。
func TestPresenceNotifyCooldown(t *testing.T) {
	var mu sync.Mutex
	var notes []string
	p := &presence{
		server:   "wss://srv:443",
		cooldown: 10 * time.Minute,
		notify: func(title, body string) {
			mu.Lock()
			defer mu.Unlock()
			notes = append(notes, title+" | "+body)
		},
	}

	// 同一来源连续 3 个短会话：只应弹第一对开始/结束
	for i := 0; i < 3; i++ {
		p.sessionStart(fmt.Sprintf("s%d", i), "alice@1.2.3.4", "exec", "echo hi")
		p.sessionEnd(fmt.Sprintf("s%d", i))
	}
	if len(notes) != 2 {
		t.Fatalf("冷却期内 3 个短会话只应弹一对通知, got %d: %v", len(notes), notes)
	}
	if !strings.Contains(notes[0], "执行命令") {
		t.Fatalf("带命令的会话通知应说明在执行命令: %q", notes[0])
	}

	// 冷却关掉后恢复每对都弹
	p.cooldown = 0
	p.sessionStart("s9", "alice@1.2.3.4", "pty", "")
	p.sessionEnd("s9")
	if len(notes) != 4 {
		t.Fatalf("冷却为 0 时应每对都弹, got %d: %v", len(notes), notes)
	}
}
