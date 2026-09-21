package server

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// TestPipeDrainsOutputOnClose 会话关闭时（agent 发了 close），已在 s.ch
// 缓冲里的输出必须先写完再收工——exec 会话末尾的 stdout 不能丢。
func TestPipeDrainsOutputOnClose(t *testing.T) {
	h := NewHub(0)
	srv, dial := wsAttach(t, h)
	defer srv.Close()
	c := dial("alice", "t1")
	defer c.Close()
	waitAgentCount(t, h, 1)
	a, err := h.Agent("alice")
	if err != nil {
		t.Fatal(err)
	}

	s, err := a.addSession("s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	s.ch <- chunk{b: []byte("out-1")}
	s.ch <- chunk{stderr: true, b: []byte("err-1")}
	s.ch <- chunk{b: []byte("out-2")}
	a.removeSession("s1") // 等价于 agent 发了 close：关 s.closed

	pr, pw := io.Pipe()
	defer pw.Close() // 收尾时让 pipe 的输入 goroutine 读到 EOF 退出
	var outBuf, errBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		h.pipe(a, s, pr, &outBuf, &errBuf, false, make(chan struct{}))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe 应在会话关闭、排空缓冲后返回")
	}
	if outBuf.String() != "out-1out-2" {
		t.Fatalf("stdout 应收齐缓冲输出: %q", outBuf.String())
	}
	if errBuf.String() != "err-1" {
		t.Fatalf("stderr 应收齐缓冲输出: %q", errBuf.String())
	}
}

// TestSessionDefaultExitCodeIs255 没拿到 agent 的 close 消息时退出码是 255
// （中断 ≠ 成功，不能让自动化把掉线当 0）；正常 close 覆盖成真实码。
func TestSessionDefaultExitCodeIs255(t *testing.T) {
	a := newAgent("x", "t", nil)
	s, err := a.addSession("s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.exitCode(); got != 255 {
		t.Fatalf("未收 close 的默认退出码应为 255, got %d", got)
	}
	s.setCode(0)
	if got := s.exitCode(); got != 0 {
		t.Fatalf("close 覆盖后应为真实退出码, got %d", got)
	}
}
