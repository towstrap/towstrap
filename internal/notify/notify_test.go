package notify

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	cases := []struct{ in, want string }{
		{"普通文本 ok", "普通文本 ok"},
		{"保留\n换行\t和制表", "保留\n换行\t和制表"},
		{"ESC\x1b[31m染色", "ESC[31m染色"},         // CSI 序列只剩可见字符
		{"回\r车覆盖", "回车覆盖"},                     // CR 剥掉
		{"退\b格", "退格"},                         // BS 剥掉
		{"C1\u0085起点", "C1起点"},                 // U+0085 是 C1 控制符
		{"行分\u0080\u009f隔", "行分隔"},             // C1 区间整段剥
		{"Unicode\u2028分\u2029隔", "Unicode分隔"}, // U+2028/2029 剥掉
		{"DEL\x7f符", "DEL符"},
	}
	for _, c := range cases {
		if got := Clean(c.in); got != c.want {
			t.Errorf("Clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanKeepsMultiline(t *testing.T) {
	in := "第一行\n第二行\n第三行"
	if Clean(in) != in {
		t.Fatal("纯换行排版不应被破坏")
	}
}

func TestQuoteApple(t *testing.T) {
	if got := quoteApple(`he said "hi"`); got != `"he said \"hi\""` {
		t.Errorf("双引号没转义: %s", got)
	}
	if got := quoteApple(`a\b`); got != `"a\\b"` {
		t.Errorf("反斜杠没转义: %s", got)
	}
	if got := quoteApple("一\n二"); got != `"一\n二"` {
		t.Errorf("换行应转成 \\n 字面量: %s", got)
	}
	if !strings.HasPrefix(quoteApple("x"), `"`) || !strings.HasSuffix(quoteApple("x"), `"`) {
		t.Error("结果应是带引号的字面量")
	}
}
