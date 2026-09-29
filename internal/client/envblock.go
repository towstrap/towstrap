package client

import (
	"sort"
	"strings"
	"unicode/utf16"
)

// envBlock 把 KEY=VAL 列表编成 CreateProcess 要的 UTF-16 环境块：每条
// NUL 分隔、双 NUL 收尾、按变量名（不区分大小写）排序——
// CREATE_UNICODE_ENVIRONMENT 的要求。
//
// 不能用 windows.UTF16FromString 编：它拒收内嵌 NUL 的字符串（返
// EINVAL），而环境块恰恰就是一堆 NUL 拼的——用它会让 startPty 永远
// 挂（真实报错过：invalid argument）。utf16.Encode 不查 NUL 也不补
// 结尾，结尾靠块里的双 NUL。
func envBlock(env []string) []uint16 {
	sorted := append([]string(nil), env...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return strings.ToUpper(envKey(sorted[i])) < strings.ToUpper(envKey(sorted[j]))
	})
	var b strings.Builder
	for _, kv := range sorted {
		b.WriteString(kv)
		b.WriteByte(0)
	}
	b.WriteByte(0)
	return utf16.Encode([]rune(b.String()))
}

func envKey(kv string) string {
	if i := strings.IndexByte(kv, '='); i >= 0 {
		return kv[:i]
	}
	return kv
}
