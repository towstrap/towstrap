package client

import (
	"strings"
	"testing"
)

func TestAltScreenFeed(t *testing.T) {
	var a AltScreen
	a.Feed([]byte("plain"))
	if a.On() {
		t.Fatal("没见到序列不该算开")
	}
	// 序列被切在两片之间
	a.Feed([]byte("xx\x1b[?10"))
	a.Feed([]byte("49hvim screen"))
	if !a.On() {
		t.Fatal("跨片的进入序列应识别")
	}
	a.Feed([]byte("\x1b[?1049l\x1b[?1049h\x1b[?1049l bye"))
	if a.On() {
		t.Fatal("以最后一条为准：已退出备用屏幕")
	}
	if !strings.HasPrefix(TermReset(true), "\x1b[?1049l") || strings.Contains(TermReset(false), "1049") {
		t.Fatal("只有在备用屏幕里才发退出备用屏幕")
	}
}
