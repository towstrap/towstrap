package mcpsrv

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const (
	terminalDefaultCols = 80
	terminalDefaultRows = 24
	terminalMaxCols     = 500
	terminalMaxRows     = 200
	terminalMaxInput    = 64 << 10
	terminalBufferSize  = 256 << 10
	terminalMaxWait     = 30 * time.Second
)

type terminalSession struct {
	id      string
	machine string
	term    Terminal
	cols    int
	rows    int
	created time.Time
	onEnd   func(code int)

	// 授权会话记录：authID 非空时这个终端是批了才开的，pump 的输出
	// 会同时写进 auth-records/<execID>.pty，结束后审计事件指到文件。
	authID  string
	execID  string
	recPath string
	rec     *os.File
	recFull bool // 记录到上限后停笔，文件里留了截断说明

	mu        sync.Mutex
	changed   chan struct{}
	buf       []byte
	dropped   int
	closed    bool
	exitCode  int
	lastUse   time.Time
	closeOnce sync.Once
}

func newTerminalSession(id, machine string, term Terminal, cols, rows int, onEnd func(code int)) *terminalSession {
	now := time.Now()
	return &terminalSession{id: id, machine: machine, term: term, cols: cols, rows: rows,
		created: now, lastUse: now, changed: make(chan struct{}), exitCode: -1, onEnd: onEnd}
}

func newTerminalID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "term-" + hex.EncodeToString(b)
}

func (t *terminalSession) start() { go t.pump() }

func (t *terminalSession) pump() {
	code := -1
	defer func() { t.finish(code) }()
	buf := make([]byte, 32*1024)
	for {
		n, err := t.term.Read(buf)
		if n > 0 {
			t.append(buf[:n])
		}
		if err != nil {
			code = t.term.Wait()
			return
		}
	}
}

func (t *terminalSession) append(chunk []byte) {
	t.mu.Lock()
	if t.rec != nil {
		if t.recFull {
			// 记录已到上限，只留内存缓冲，文件不再写
		} else if _, err := t.rec.Write(chunk); err != nil || t.recSize() >= authRecordMaxBytes {
			t.recFull = true
			_, _ = t.rec.WriteString("\n--- 记录超过大小上限，后续输出未落盘 ---\n")
		}
	}
	if len(chunk) >= terminalBufferSize {
		t.dropped += len(t.buf) + len(chunk) - terminalBufferSize
		t.buf = append(t.buf[:0], chunk[len(chunk)-terminalBufferSize:]...)
	} else {
		overflow := len(t.buf) + len(chunk) - terminalBufferSize
		if overflow > 0 {
			t.dropped += overflow
			copy(t.buf, t.buf[overflow:])
			t.buf = t.buf[:len(t.buf)-overflow]
		}
		t.buf = append(t.buf, chunk...)
	}
	close(t.changed)
	t.changed = make(chan struct{})
	t.mu.Unlock()
}

func (t *terminalSession) finish(code int) {
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		t.exitCode = code
		close(t.changed)
		t.changed = make(chan struct{})
	}
	if t.rec != nil {
		fmt.Fprintf(t.rec, "\n---\nended: %s\nexit_code: %d\n", time.Now().Format(time.RFC3339Nano), code)
		_ = t.rec.Close()
		t.rec = nil
	}
	t.mu.Unlock()
	if t.onEnd != nil {
		t.onEnd(code)
	}
}

// recSize 返回授权记录文件已写的字节数（append 里封顶用）。
func (t *terminalSession) recSize() int64 {
	st, err := t.rec.Stat()
	if err != nil {
		return 0
	}
	return st.Size()
}

type terminalReadResult struct {
	output   string
	closed   bool
	exitCode int
	dropped  int
	hasMore  bool
}

func (t *terminalSession) read(wait time.Duration, maxBytes int) terminalReadResult {
	if wait < 0 {
		wait = 0
	}
	if wait > terminalMaxWait {
		wait = terminalMaxWait
	}
	if maxBytes <= 0 || maxBytes > terminalBufferSize {
		maxBytes = terminalBufferSize
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		t.mu.Lock()
		if len(t.buf) > 0 || t.closed {
			n := maxBytes
			if len(t.buf) < n {
				n = len(t.buf)
			}
			out := string(t.buf[:n])
			t.buf = append([]byte(nil), t.buf[n:]...)
			res := terminalReadResult{
				output: out, closed: t.closed, exitCode: t.exitCode,
				dropped: t.dropped, hasMore: len(t.buf) > 0,
			}
			t.dropped = 0
			t.lastUse = time.Now()
			t.mu.Unlock()
			return res
		}
		if wait == 0 {
			t.lastUse = time.Now()
			t.mu.Unlock()
			return terminalReadResult{exitCode: -1}
		}
		changed := t.changed
		t.mu.Unlock()
		select {
		case <-changed:
		case <-deadline.C:
			t.mu.Lock()
			t.lastUse = time.Now()
			res := terminalReadResult{exitCode: -1}
			t.mu.Unlock()
			return res
		}
	}
}

func (t *terminalSession) write(input []byte) (int, error) {
	if len(input) == 0 {
		return 0, nil
	}
	if t.done() {
		return 0, fmt.Errorf("终端已结束")
	}
	written := 0
	for written < len(input) {
		n, err := t.term.Write(input[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	t.markUsed()
	return written, nil
}

func (t *terminalSession) resize(cols, rows int) error {
	if t.done() {
		return fmt.Errorf("终端已结束")
	}
	if err := t.term.Resize(cols, rows); err != nil {
		return err
	}
	t.mu.Lock()
	t.cols, t.rows = cols, rows
	t.lastUse = time.Now()
	t.mu.Unlock()
	return nil
}

func (t *terminalSession) close() (bool, int) {
	t.closeOnce.Do(func() { _ = t.term.Close() })
	t.markUsed()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if done, code := t.state(); done {
			return true, code
		}
		time.Sleep(10 * time.Millisecond)
	}
	done, code := t.state()
	return done, code
}

func (t *terminalSession) done() bool {
	done, _ := t.state()
	return done
}

func (t *terminalSession) state() (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed, t.exitCode
}

func (t *terminalSession) markUsed() {
	t.mu.Lock()
	t.lastUse = time.Now()
	t.mu.Unlock()
}

func (t *terminalSession) idleFor() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Since(t.lastUse)
}
