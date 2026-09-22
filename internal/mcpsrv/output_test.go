package mcpsrv

import (
	"strings"
	"testing"
)

func TestCapWriterUnderLimit(t *testing.T) {
	w := newCapWriter(100)
	in := "hello, 世界"
	if _, err := w.Write([]byte(in)); err != nil {
		t.Fatal(err)
	}
	if w.String() != in {
		t.Fatalf("got %q, want %q", w.String(), in)
	}
	if w.Truncated() {
		t.Error("没超上限不该标记截断")
	}
}

func TestCapWriterOverLimit(t *testing.T) {
	w := newCapWriter(100)
	// 300 字节：'a'*150 + 'b'*150，超过 100，应留头 50 + 尾 50。
	in := strings.Repeat("a", 150) + strings.Repeat("b", 150)
	if _, err := w.Write([]byte(in)); err != nil {
		t.Fatal(err)
	}
	if !w.Truncated() {
		t.Fatal("超上限应标记截断")
	}
	got := w.String()
	if !strings.HasPrefix(got, strings.Repeat("a", 50)) {
		t.Error("头部应保留前 50 字节")
	}
	if !strings.HasSuffix(got, strings.Repeat("b", 50)) {
		t.Error("尾部应保留后 50 字节")
	}
	if !strings.Contains(got, "省略 200 字节") {
		t.Errorf("应有省略标记且字数正确，got %q", got[40:80])
	}
}

func TestCapWriterSplitWrites(t *testing.T) {
	w := newCapWriter(10)
	_, _ = w.Write([]byte("0123456789")) // 恰好满
	if w.Truncated() {
		t.Error("恰好等于上限不算截断")
	}
	_, _ = w.Write([]byte("ab"))
	if !w.Truncated() || w.String() == "" {
		t.Error("超过上限应截断")
	}
	if !strings.Contains(w.String(), "省略") {
		t.Error("应有省略标记")
	}
}
