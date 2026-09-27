package qrcode

import (
	"strings"
	"testing"
)

func TestTerminalShape(t *testing.T) {
	out, err := Terminal("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 5 {
		t.Fatalf("二维码行数太少: %d", len(lines))
	}
	// 上下是空白边框行，中间行含半块字符。块字符是多字节 UTF-8，
	// 行宽要按 rune 数比。
	width := len([]rune(lines[0]))
	if strings.TrimSpace(lines[0]) != "" || strings.TrimSpace(lines[len(lines)-1]) != "" {
		t.Fatal("上下边框应是空白行")
	}
	var blocks int
	for _, l := range lines {
		if w := len([]rune(l)); w != width {
			t.Fatalf("行宽不齐: %d != %d", w, width)
		}
		blocks += strings.Count(l, "█") + strings.Count(l, "▀") + strings.Count(l, "▄")
	}
	if blocks == 0 {
		t.Fatal("没有任何模块字符")
	}
}

func TestTerminalTooLong(t *testing.T) {
	// 超过 Medium 容错容量的输入要报错而不是静默截断。
	if _, err := Terminal(strings.Repeat("x", 5000)); err == nil {
		t.Fatal("超长输入应报错")
	}
}
