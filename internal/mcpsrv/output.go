package mcpsrv

import "fmt"

// capWriter 是有上限的输出收集器：总量超过 max 时保留前一半和后一半，
// 中间换成省略标记。stdout 和 stderr 各用各的，互不挤占。
type capWriter struct {
	max   int
	head  []byte // 前 max/2 字节
	tail  []byte // 后 max/2 字节（滚动保留末尾）
	total int    // 一共写过多少字节
}

func newCapWriter(max int) *capWriter { return &capWriter{max: max} }

func (w *capWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.total += n
	half := w.max / 2
	if len(w.head) < half {
		k := half - len(w.head)
		if k > len(p) {
			k = len(p)
		}
		w.head = append(w.head, p[:k]...)
		p = p[k:]
	}
	if len(p) > 0 {
		w.tail = append(w.tail, p...)
		if len(w.tail) > half {
			w.tail = append([]byte(nil), w.tail[len(w.tail)-half:]...)
		}
	}
	return n, nil
}

// Truncated 报告写入总量是否超过上限（即 String 里是否有省略标记）。
func (w *capWriter) Truncated() bool { return w.total > w.max }

// String 返回收集到的内容；超限时是「头 + 省略标记 + 尾」。
func (w *capWriter) String() string {
	if !w.Truncated() {
		return string(w.head) + string(w.tail)
	}
	return fmt.Sprintf("%s\n…[省略 %d 字节]…\n%s",
		w.head, w.total-len(w.head)-len(w.tail), w.tail)
}
