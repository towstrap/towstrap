package client

import "bytes"

// AltScreen 从终端输出流里跟踪「备用屏幕」（vim、top、less 这类全屏程序
// 进入的那块屏幕）开没开着。转义序列可能被切在两片输出之间，留一小截
// 尾巴和下一片拼着找。
type AltScreen struct {
	on   bool
	tail []byte
}

var (
	altOnSeqs  = [][]byte{[]byte("\x1b[?1049h"), []byte("\x1b[?1047h"), []byte("\x1b[?47h")}
	altOffSeqs = [][]byte{[]byte("\x1b[?1049l"), []byte("\x1b[?1047l"), []byte("\x1b[?47l")}
)

const altSeqMax = 8 // 最长的序列 \x1b[?1049h 是 8 字节

// Feed 喂一片输出，按其中最后出现的开/关序列更新状态。
func (a *AltScreen) Feed(b []byte) {
	buf := make([]byte, 0, len(a.tail)+len(b))
	buf = append(append(buf, a.tail...), b...)
	lastOn, lastOff := -1, -1
	for _, s := range altOnSeqs {
		lastOn = max(lastOn, bytes.LastIndex(buf, s))
	}
	for _, s := range altOffSeqs {
		lastOff = max(lastOff, bytes.LastIndex(buf, s))
	}
	switch {
	case lastOn > lastOff:
		a.on = true
	case lastOff > lastOn:
		a.on = false
	}
	a.tail = append(a.tail[:0], buf[max(0, len(buf)-(altSeqMax-1)):]...)
}

// On 最后一次看到的是「进入备用屏幕」。
func (a *AltScreen) On() bool { return a.on }

// EnterAltScreen 接入时补发：程序早就进了备用屏幕、那段输出却已经滚出
// 重放留档，新接入方的终端得先切过去，重画才画在对的屏幕上。
const EnterAltScreen = "\x1b[?1049h"

// TermReset 脱离/断开后把本地终端从远端程序设的模式里拉回来：关鼠标上报、
// 关括号粘贴、光标键和小键盘回普通模式、显示光标、清颜色属性；alt 为真
// 时再退出备用屏幕（不在备用屏幕时不发——那条序列会顺带把光标挪回旧位置）。
func TermReset(alt bool) string {
	s := "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\x1b[?2004l\x1b[?1l\x1b>\x1b[?25h\x1b[0m"
	if alt {
		s = "\x1b[?1049l" + s
	}
	return s
}

// seqEnd 返回 b[i] 处（b[i] 必须是 \x1b）那条转义序列的结束下标。
// 认三种长序列：CSI（\x1b[ 参数 终字节）、OSC（\x1b] 内容 BEL 或 ST）、
// DCS（\x1bP 内容 ST）；其余 \x1b 加一字节的两字节序列按 i+2 算。
// 序列畸形或没走完时返回保守值，调用方按「不是完整序列」处理即可。
func seqEnd(b []byte, i int) int {
	if i+1 >= len(b) {
		return i + 1
	}
	switch b[i+1] {
	case '[': // CSI：参数/中间字节 0x20-0x3f，终字节 0x40-0x7e
		for j := i + 2; j < len(b); j++ {
			c := b[j]
			switch {
			case c >= 0x40 && c <= 0x7e:
				return j + 1
			case c < 0x20 || c > 0x3f:
				return j
			}
		}
		return len(b)
	case ']': // OSC：内容直到 BEL 或 \x1b\\
		for j := i + 2; j < len(b); j++ {
			if b[j] == 0x07 {
				return j + 1
			}
			if b[j] == 0x1b && j+1 < len(b) && b[j+1] == '\\' {
				return j + 2
			}
		}
		return len(b)
	case 'P': // DCS：内容直到 \x1b\\
		for j := i + 2; j+1 < len(b); j++ {
			if b[j] == 0x1b && b[j+1] == '\\' {
				return j + 2
			}
		}
		return len(b)
	default:
		return i + 2
	}
}

// seqStartBefore 判断 pos 是否落在一条转义序列的中间：是则返回那条序列
// 的起点。回扫最多 1KB 找最近的 \x1b——更长的序列（图片传输这类巨型
// DCS）认不出来，那种情况按普通截断处理。
func seqStartBefore(b []byte, pos int) (int, bool) {
	if pos <= 0 {
		return 0, false
	}
	from := max(0, pos-1024)
	j := bytes.LastIndexByte(b[from:pos], 0x1b)
	if j < 0 {
		return 0, false
	}
	start := from + j
	if seqEnd(b, start) > pos {
		return start, true
	}
	return 0, false
}

// stripTermQueries 剥掉输出流里的「终端查询」序列——终端收到这类序列会
// 自动应答（光标位置、设备属性、模式状态、颜色值…）。实时输出不能动
// （程序的真查询必须到达终端才有应答）；只有重放时才剥——回放的查询
// 只会骗新接入方的终端把应答打进共享 PTY 输入，变成别人的幽灵输入。
func stripTermQueries(b []byte) []byte {
	out := b[:0] // 原地压缩：写下标永远不超过读下标
	for i := 0; i < len(b); {
		if b[i] != 0x1b || i+1 >= len(b) {
			out = append(out, b[i])
			i++
			continue
		}
		end, drop := -1, false
		switch b[i+1] {
		case '[':
			end, drop = csiQueryEnd(b, i)
		case ']':
			end, drop = oscQueryEnd(b, i)
		case 'P':
			end, drop = dcsQueryEnd(b, i)
		case 'Z': // DECID：询问设备类型
			end, drop = i+2, true
		default:
			end = i + 2
		}
		if end < 0 { // 序列在尾巴上没走完：原样留
			out = append(out, b[i:]...)
			break
		}
		if !drop {
			out = append(out, b[i:end]...)
		}
		i = end
	}
	return out
}

// csiQueryEnd 走完一条 CSI，返回结束下标和「是否查询」。
// 查询类：DSR \x1b[<数字>n、DA \x1b[[>]c、DECRQM \x1b[?<数字>$p、
// kitty 键盘协议询问 \x1b[?[<数字>]u。
func csiQueryEnd(b []byte, i int) (int, bool) {
	for j := i + 2; j < len(b); j++ {
		c := b[j]
		switch {
		case c >= 0x40 && c <= 0x7e:
			p := b[i+2 : j]
			switch c {
			case 'n':
				return j + 1, allDigits(p)
			case 'c':
				return j + 1, allIn(p, "0123456789>=")
			case 'p':
				return j + 1, len(p) >= 2 && p[0] == '?' && p[len(p)-1] == '$' && allDigits(p[1:len(p)-1])
			case 'u':
				return j + 1, len(p) >= 1 && p[0] == '?' && allDigits(p[1:])
			}
			return j + 1, false
		case c < 0x20 || c > 0x3f:
			return j, false
		}
	}
	return -1, false
}

// oscQueryEnd 走完一条 OSC，返回结束下标和「是否询问」。
// OSC 询问的参数都是 ?（\x1b]4;0;? 问调色板、\x1b]10;? 问前景色、
// \x1b]52;;? 读剪贴板），设置类不会以 ? 结尾。
func oscQueryEnd(b []byte, i int) (int, bool) {
	for j := i + 2; j < len(b); j++ {
		if b[j] == 0x07 {
			return j + 1, len(b[i+2:j]) > 0 && b[j-1] == '?'
		}
		if b[j] == 0x1b && j+1 < len(b) && b[j+1] == '\\' {
			return j + 2, len(b[i+2:j]) > 0 && b[j-1] == '?'
		}
	}
	return -1, false
}

// dcsQueryEnd 走完一条 DCS，返回结束下标和「是否请求」。
// $q 是 DECRQSS（问设置）、+q 是 XTGETTCAP（问 terminfo 能力）。
func dcsQueryEnd(b []byte, i int) (int, bool) {
	for j := i + 2; j+1 < len(b); j++ {
		if b[j] == 0x1b && b[j+1] == '\\' {
			body := b[i+2 : j]
			return j + 2, bytes.HasPrefix(body, []byte("$q")) || bytes.HasPrefix(body, []byte("+q"))
		}
	}
	return -1, false
}

func allDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func allIn(b []byte, set string) bool {
	for _, c := range b {
		if !bytes.ContainsRune([]byte(set), rune(c)) {
			return false
		}
	}
	return true
}
