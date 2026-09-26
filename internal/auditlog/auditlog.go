// Package auditlog 是 agent 和服务器共用的审计日志器：惰性打开、追加写、
// 值清洗控制字符，超过 maxBytes 轮转成 <path>.1（旧的被覆盖）。写不进去
// 只报一次错，绝不影响主流程——审计是保底，不是依赖。
package auditlog

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMaxBytes 单个审计文件的大小上限，超过就轮转。
const DefaultMaxBytes = 16 << 20 // 16MB

type Writer struct {
	path     string
	maxBytes int64

	mu      sync.Mutex
	f       *os.File
	written int64
	failed  bool // 打不开/写失败只报一次错，之后静默放弃
}

// Open 建一个审计器；path 为空则全部 Log 变成空操作（测试或显式关闭用）。
// maxBytes <= 0 用 DefaultMaxBytes。
func Open(path string, maxBytes int64) *Writer {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	return &Writer{path: path, maxBytes: maxBytes}
}

// Path 返回日志路径（文件可能还没创建）。
func (w *Writer) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

// Log 追加一行：`<时间> <event> k=v k=v`。kv 成对出现；值里的控制字符被
// 去掉（防换行 smuggle 伪造日志行）；值里出现空格、=、引号或为空时整值
// 加 %q 引起来——不然 `user=alice admin=true` 这种一个值里塞两个键的写法
// 能伪造出不存在的字段。
func (w *Writer) Log(event string, kv ...string) {
	if w == nil || w.path == "" {
		return
	}
	var b strings.Builder
	b.WriteString(event)
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteByte(' ')
		b.WriteString(kv[i])
		b.WriteByte('=')
		v := Clean(kv[i+1])
		if v == "" || strings.ContainsAny(v, " =\"") {
			v = strconv.Quote(v)
		}
		b.WriteString(v)
	}
	w.write(time.Now().Format(time.RFC3339) + " " + b.String() + "\n")
}

// Clean 去掉控制字符（换行、终端转义等）。范围比「ASCII 控制符」宽一些：
// C1（0x80–0x9f，终端上同样是转义序列起点）和 U+2028/2029（Unicode 行
// 分隔符，不少查看器会当换行渲染）也剥——审计和终端广播共用这一份。
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
}

func (w *Writer) write(line string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		if w.failed {
			return
		}
		if err := w.openLocked(); err != nil {
			w.failed = true
			slog.Error("审计日志打不开（--audit-log 可改路径）", "path", w.path, "err", err)
			return
		}
	}
	if w.written+int64(len(line)) > w.maxBytes {
		w.rotateLocked()
	}
	n, err := w.f.WriteString(line)
	if err != nil {
		w.failed = true
		slog.Error("审计日志写失败，停用审计", "path", w.path, "err", err)
		_ = w.f.Close()
		w.f = nil
		return
	}
	w.written += int64(n)
}

func (w *Writer) openLocked() error {
	if dir := filepath.Dir(w.path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f = f
	w.written = st.Size()
	slog.Info("audit log", "path", w.path)
	return nil
}

// rotateLocked 把当前文件改名成 .1（覆盖上一轮），再开新文件继续写。
// 改名失败不中断：重新打开原文件接着追加。
func (w *Writer) rotateLocked() {
	_ = w.f.Close()
	w.f = nil
	if err := os.Rename(w.path, w.path+".1"); err != nil {
		slog.Error("审计日志轮转失败，继续写原文件", "path", w.path, "err", err)
	}
	if err := w.openLocked(); err != nil {
		w.failed = true
	}
}
