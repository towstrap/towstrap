package auditlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.log")
	w := Open(path, 0)
	w.Log("AGENT-START", "id", "box", "server", "wss://s:443")
	w.Log("START", "id", "s1", "from", "alice@1.2.3.4")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "AGENT-START id=box server=wss://s:443") {
		t.Fatalf("缺第一行: %q", got)
	}
	if !strings.Contains(got, "START id=s1 from=alice@1.2.3.4") {
		t.Fatalf("缺第二行: %q", got)
	}
	if n := strings.Count(got, "\n"); n != 2 {
		t.Fatalf("应两行, got %d", n)
	}
	// 每行以时间戳开头
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if len(line) < 25 || line[4] != '-' || line[7] != '-' {
			t.Fatalf("行没有时间戳前缀: %q", line)
		}
	}
}

func TestCleanValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.log")
	w := Open(path, 0)
	w.Log("EVIL", "v", "a\x1b]0;x\x07b\nc")
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "\x1b") || strings.Contains(string(raw), "\x07") ||
		strings.Count(string(raw), "\n") != 1 {
		t.Fatalf("控制字符应被清掉: %q", raw)
	}
	// ESC 后面的 ]0;x 是可打印字符，保留无害（没有 ESC 就是普通文本）
	if !strings.Contains(string(raw), "v=a]0;xbc") {
		t.Fatalf("清洗后应保留正常字符: %q", raw)
	}
}

func TestRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.log")
	w := Open(path, 50)
	w.Log("E1", "n", "1")   // ~33 字节，放得下
	w.Log("E2", "n", "222") // 累计超限 → 轮转：E1 进 .1，E2 写新文件

	raw1, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal("轮转文件应存在", err)
	}
	if !strings.Contains(string(raw1), "E1") {
		t.Fatalf(".1 应有第一行: %q", raw1)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "E1") || !strings.Contains(string(raw), "E2") {
		t.Fatalf("新文件应有 E2 不应有 E1: %q", raw)
	}
}

func TestEmptyPathNoop(t *testing.T) {
	w := Open("", 0)
	w.Log("X", "k", "v") // 不应 panic
	if w.Path() != "" {
		t.Fatal("空路径应保持空")
	}
	var nilW *Writer
	nilW.Log("X") // nil 接收者也不应 panic
}

func TestBadPathFailsOnce(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := Open(filepath.Join(blocker, "a.log"), 0)
	w.Log("E1", "k", "v")
	w.Log("E2", "k", "v") // 第二次静默放弃
}
