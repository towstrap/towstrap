package client

import (
	"reflect"
	"testing"
	"unicode/utf16"
	"unsafe"
)

// envBlock 编的是 NUL 分隔的 UTF-16 环境块——曾经用 windows.UTF16FromString
// 编，它拒收内嵌 NUL 直接 EINVAL，startPty 在 Windows 上从没跑通过。
// 钉住块的结构：条目按名不区分大小写升序、各 NUL 分隔、整体双 NUL 收尾。
func TestEnvBlock(t *testing.T) {
	p := envBlock([]string{"Path=C:\\x", "B=2", "a=1"})
	u := unsafe.Slice(p, 64) // 这个块远短于 64 个 UTF-16 单元

	var segs []string
	for i := 0; ; {
		if u[i] == 0 && u[i+1] == 0 {
			break // 双 NUL 收尾
		}
		j := i
		for u[j] != 0 {
			j++
		}
		segs = append(segs, string(utf16.Decode(u[i:j])))
		i = j + 1
	}
	want := []string{"a=1", "B=2", "Path=C:\\x"}
	if !reflect.DeepEqual(segs, want) {
		t.Fatalf("环境块条目不对：%v", segs)
	}
}
