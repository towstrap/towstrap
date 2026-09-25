package mcpsrv

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeTerminal struct {
	outR    *io.PipeReader
	outW    *io.PipeWriter
	input   chan []byte
	resized chan [2]int
	waitCh  chan int
	once    sync.Once
}

func newFakeTerminal() *fakeTerminal {
	outR, outW := io.Pipe()
	return &fakeTerminal{
		outR: outR, outW: outW,
		input: make(chan []byte, 16), resized: make(chan [2]int, 4),
		waitCh: make(chan int, 1),
	}
}

func (f *fakeTerminal) Read(b []byte) (int, error) { return f.outR.Read(b) }
func (f *fakeTerminal) Write(b []byte) (int, error) {
	f.input <- append([]byte(nil), b...)
	return len(b), nil
}
func (f *fakeTerminal) Resize(cols, rows int) error {
	f.resized <- [2]int{cols, rows}
	return nil
}
func (f *fakeTerminal) Close() error {
	f.finish(137)
	return nil
}
func (f *fakeTerminal) Wait() int { return <-f.waitCh }
func (f *fakeTerminal) finish(code int) {
	f.once.Do(func() {
		_ = f.outW.Close()
		f.waitCh <- code
	})
}
func (f *fakeTerminal) writeOutput(s string) {
	_, _ = f.outW.Write([]byte(s))
}

type fakeTerminalRunner struct {
	mu    sync.Mutex
	terms []*fakeTerminal
	opts  []TerminalOptions
	fail  error
}

func (f *fakeTerminalRunner) Run(context.Context, string, string, []byte, time.Duration, int) (Result, error) {
	return Result{}, nil
}
func (f *fakeTerminalRunner) Connected(string) bool { return true }
func (f *fakeTerminalRunner) OpenTerminal(_ context.Context, machine string, opts TerminalOptions) (Terminal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	t := newFakeTerminal()
	f.terms = append(f.terms, t)
	f.opts = append(f.opts, opts)
	return t, nil
}
func (f *fakeTerminalRunner) latest() *fakeTerminal {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.terms[len(f.terms)-1]
}
func (f *fakeTerminalRunner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.terms)
}

func readTerminalUntil(t *testing.T, term *terminalSession, want string) terminalReadResult {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var all strings.Builder
	for time.Now().Before(deadline) {
		res := term.read(100*time.Millisecond, terminalBufferSize)
		all.WriteString(res.output)
		if strings.Contains(all.String(), want) || res.closed {
			res.output = all.String()
			return res
		}
	}
	t.Fatalf("终端输出没等到 %q；已收到 %q", want, all.String())
	return terminalReadResult{}
}

func readTerminalClosed(t *testing.T, term *terminalSession) terminalReadResult {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var all strings.Builder
	for time.Now().Before(deadline) {
		res := term.read(100*time.Millisecond, terminalBufferSize)
		all.WriteString(res.output)
		if res.closed {
			res.output = all.String()
			return res
		}
	}
	t.Fatalf("终端没有结束；已收到 %q", all.String())
	return terminalReadResult{}
}

func TestTerminalSessionIO(t *testing.T) {
	raw := newFakeTerminal()
	term := newTerminalSession("t", "m", raw, 80, 24, nil)
	term.start()

	raw.writeOutput("READY> ")
	if res := term.read(time.Second, 1024); !strings.Contains(res.output, "READY") || res.closed {
		t.Fatalf("首轮输出不对: %+v", res)
	}
	if _, err := term.write([]byte("hello\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-raw.input:
		if string(got) != "hello\r" {
			t.Fatalf("输入不对: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("输入没到终端")
	}
	if err := term.resize(120, 40); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-raw.resized:
		if got != [2]int{120, 40} {
			t.Fatalf("尺寸不对: %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("resize 没到终端")
	}
	raw.writeOutput("BYE")
	raw.finish(7)
	res := readTerminalClosed(t, term)
	if !strings.Contains(res.output, "BYE") || res.exitCode != 7 {
		t.Fatalf("结束状态不对: %+v", res)
	}
}

func TestTerminalToolLifecycle(t *testing.T) {
	op := &fakeTerminalRunner{}
	s := newTestServer(t, op, 4)
	res, out, err := s.terminalOpen(context.Background(), &mcp.CallToolRequest{}, terminalOpenIn{
		Machine: "m", Command: "pi", Cwd: "~/work", Cols: 100, Rows: 30,
	})
	if err != nil || res.IsError {
		t.Fatalf("terminal_open: %v %+v", err, res)
	}
	if out.TerminalID == "" || out.Approval != "allowed" || out.Cols != 100 || out.Rows != 30 {
		t.Fatalf("打开结果不对: %+v", out)
	}
	if got := op.opts[0]; got.Command != "pi" || got.Cwd != "~/work" || got.Cols != 100 || got.Rows != 30 {
		t.Fatalf("后端参数不对: %+v", got)
	}
	raw := op.latest()
	raw.writeOutput("pi ready")

	rres, rout, err := s.terminalRead(context.Background(), &mcp.CallToolRequest{}, terminalReadIn{
		TerminalID: out.TerminalID, TimeoutSeconds: 1,
	})
	if err != nil || rres.IsError || !strings.Contains(rout.Output, "pi ready") || rout.Closed {
		t.Fatalf("terminal_read: %v %s %+v", err, resultTextForTest(rres), rout)
	}

	wres, wout, err := s.terminalWrite(context.Background(), &mcp.CallToolRequest{}, terminalWriteIn{
		TerminalID: out.TerminalID, Input: "回答我\r",
	})
	if err != nil || wres.IsError || wout.BytesWritten != len("回答我\r") {
		t.Fatalf("terminal_write: %v %s %+v", err, resultTextForTest(wres), wout)
	}
	select {
	case got := <-raw.input:
		if string(got) != "回答我\r" {
			t.Fatalf("终端输入不对: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("终端没收到输入")
	}

	zres, zout, err := s.terminalResize(context.Background(), &mcp.CallToolRequest{}, terminalResizeIn{
		TerminalID: out.TerminalID, Cols: 120, Rows: 40,
	})
	if err != nil || zres.IsError || zout.Cols != 120 || zout.Rows != 40 {
		t.Fatalf("terminal_resize: %v %s %+v", err, resultTextForTest(zres), zout)
	}
	select {
	case got := <-raw.resized:
		if got != [2]int{120, 40} {
			t.Fatalf("resize 参数不对: %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("resize 没发到后端")
	}

	lres, lout, err := s.terminalList(context.Background(), &mcp.CallToolRequest{}, terminalListIn{})
	if err != nil || lres.IsError || len(lout.Terminals) != 1 {
		t.Fatalf("terminal_list: %v %s %+v", err, resultTextForTest(lres), lout)
	}

	cres, cout, err := s.terminalClose(context.Background(), &mcp.CallToolRequest{}, terminalCloseIn{TerminalID: out.TerminalID})
	if err != nil || cres.IsError || !cout.Closed {
		t.Fatalf("terminal_close: %v %s %+v", err, resultTextForTest(cres), cout)
	}
	if _, err := s.terminalFor(out.TerminalID); err == nil {
		t.Fatal("terminal_close 后不应再找到终端")
	}
}

func TestTerminalLimitAndIdle(t *testing.T) {
	op := &fakeTerminalRunner{}
	s := newTestServer(t, op, 2)
	for i := 0; i < 2; i++ {
		if _, err := s.openTerminal(context.Background(), "m", TerminalOptions{Command: "pi"}, ""); err != nil {
			t.Fatalf("第 %d 个终端应能打开: %v", i, err)
		}
	}
	if _, err := s.openTerminal(context.Background(), "m", TerminalOptions{Command: "pi"}, ""); err == nil {
		t.Fatal("第三个终端应被 max_sessions 挡住")
	}

	s.mu.Lock()
	var first *terminalSession
	for _, term := range s.terms {
		first = term
		break
	}
	s.mu.Unlock()
	first.mu.Lock()
	first.lastUse = time.Now().Add(-2 * time.Minute)
	first.mu.Unlock()
	s.sweepIdle()
	if _, err := s.terminalFor(first.id); err == nil {
		t.Fatal("空闲终端应被回收")
	}
	if done, _ := first.state(); !done {
		t.Fatal("空闲终端应已结束")
	}
}

func TestTerminalPolicyDeny(t *testing.T) {
	op := &fakeTerminalRunner{}
	s := newTestServer(t, op, 4)
	res, _, err := s.terminalOpen(context.Background(), &mcp.CallToolRequest{}, terminalOpenIn{
		Machine: "m", Command: "rm -rf /",
	})
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultTextForTest(res), "策略拒绝") {
		t.Fatalf("deny 命令应直接拒绝: %v %+v", err, res)
	}
	if op.count() != 0 {
		t.Fatal("被拒命令不应打开终端")
	}
}

func TestTerminalUnsupportedRunner(t *testing.T) {
	s := newTestServer(t, dumbRunner{}, 4)
	res, _, err := s.terminalOpen(context.Background(), &mcp.CallToolRequest{}, terminalOpenIn{
		Machine: "m", Command: "pi",
	})
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultTextForTest(res), "不支持 PTY") {
		t.Fatalf("不支持 PTY 的后端应明确报错: %v %+v", err, res)
	}
}

func resultTextForTest(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}
