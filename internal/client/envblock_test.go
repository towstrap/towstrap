package client

import (
	"reflect"
	"testing"
	"unicode/utf16"
)

// envBlock 编的是 NUL 分隔的 UTF-16 环境块——曾经用 windows.UTF16FromString
// 编，它拒收内嵌 NUL 直接 EINVAL，startPty 在 Windows 上从没跑通过。
// 钉住块的结构：条目按名不区分大小写升序、各 NUL 分隔、整体双 NUL 收尾。
func TestEnvBlock(t *testing.T) {
	u := envBlock([]string{"Path=C:\\x", "B=2", "a=1"})

	// 逐字节钉死：排序（a 在 B 前，不区分大小写）、条目间单 NUL、
	// 块尾双 NUL——缺一个都是 CreateProcess 拒收的环境块。
	want := utf16.Encode([]rune("a=1\x00B=2\x00Path=C:\\x\x00\x00"))
	if !reflect.DeepEqual(u, want) {
		t.Fatalf("环境块编码不对：%v", u)
	}
}
