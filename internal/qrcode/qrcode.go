// Package qrcode 把文本（比如 otpauth:// URI）渲染成终端里能扫的二维码：
// 用 ▀▄█ 半块字符两行点阵挤一行，黑白是反转的（终端黑底上黑块是模块）。
package qrcode

import (
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// Terminal 返回终端可显示的二维码字符串（带上下留白边框）。
// level 用 Medium——URI 这种长度正好，容错够扫就行。
func Terminal(text string) (string, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return "", err
	}
	b := q.Bitmap()
	var sb strings.Builder
	width := len(b[0])
	border := strings.Repeat(" ", width+8) + "\n"
	sb.WriteString(border)
	for y := 0; y < len(b); y += 2 {
		sb.WriteString("    ")
		for x := 0; x < width; x++ {
			top := b[y][x]
			bot := y+1 < len(b) && b[y+1][x]
			switch {
			case top && bot:
				sb.WriteString("█")
			case top:
				sb.WriteString("▀")
			case bot:
				sb.WriteString("▄")
			default:
				sb.WriteString(" ")
			}
		}
		sb.WriteString("    \n")
	}
	sb.WriteString(border)
	return sb.String(), nil
}
