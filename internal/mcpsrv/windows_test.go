package mcpsrv

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type probeCall struct {
	cmd   string
	stdin []byte
	cwd   string
	at    bool
}

type probeRunner struct {
	mu         sync.Mutex
	calls      []probeCall
	osVar      string
	envOS      string
	fileOut    string
	failNext   int
	probeExit  int
	respectCtx bool
}

func (r *probeRunner) answer(cmd string) (Result, bool) {
	switch cmd {
	case "echo %OS%":
		return Result{Stdout: r.osVar, ExitCode: r.probeExit}, true
	case "echo $env:OS":
		return Result{Stdout: r.envOS, ExitCode: r.probeExit}, true
	}
	return Result{}, false
}

func (r *probeRunner) run(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int, cwd string, at bool) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, probeCall{cmd: cmd, stdin: stdin, cwd: cwd, at: at})
	if r.failNext > 0 {
		r.failNext--
		return Result{}, errors.New("offline")
	}
	if r.respectCtx {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
	}
	if res, ok := r.answer(cmd); ok {
		return res, nil
	}
	return Result{Stdout: r.fileOut}, nil
}

func (r *probeRunner) Run(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int) (Result, error) {
	return r.run(ctx, machine, cmd, stdin, timeout, maxOut, "", false)
}

func (r *probeRunner) RunAt(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int, cwd string) (Result, error) {
	return r.run(ctx, machine, cmd, stdin, timeout, maxOut, cwd, true)
}

func (r *probeRunner) Connected(string) bool { return true }

func (r *probeRunner) last() probeCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[len(r.calls)-1]
}

func (r *probeRunner) probeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c.cmd == "echo %OS%" || c.cmd == "echo $env:OS" {
			n++
		}
	}
	return n
}

func newProbeServer(t *testing.T, r Runner) *Server {
	t.Helper()
	cfg := &Config{
		Machines: map[string]*Machine{"w": {Roots: []string{`C:\work`}}},
		Policy:   PolicyCfg{Default: "run", AskTimeout: time.Second},
		Limits:   LimitsCfg{Timeout: time.Second, MaxTimeout: time.Minute, MaxOutput: 1 << 20, MaxFile: 1024, SessionIdle: time.Minute, MaxSessions: 8},
	}
	s, err := New(cfg, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func decodePS(t *testing.T, cmd string) string {
	t.Helper()
	const prefix = "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
	if !strings.HasPrefix(cmd, prefix) {
		t.Fatalf("不是 PowerShell EncodedCommand: %q", cmd)
	}
	raw, err := base64.StdEncoding.DecodeString(cmd[len(prefix):])
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)%2 != 0 {
		t.Fatal("UTF-16 长度应为偶数")
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

func TestWindowsReadFileCmd(t *testing.T) {
	r := &probeRunner{osVar: "Windows_NT", fileOut: "file-content"}
	s := newProbeServer(t, r)
	res, out, err := s.readFile(context.Background(), &mcp.CallToolRequest{},
		readIn{Machine: "w", Path: `C:\work\a'b.txt`})
	if err != nil || res.IsError {
		t.Fatalf("readFile: %v %+v", err, res)
	}
	if out.Content != "file-content" {
		t.Fatalf("content = %q", out.Content)
	}
	script := decodePS(t, r.last().cmd)
	for _, want := range []string{
		`$p='C:\work\a''b.txt'`, "OpenRead", "OpenStandardOutput", "$r=1025", "exit 1",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("脚本缺 %q:\n%s", want, script)
		}
	}
}

func TestWindowsWriteFileCmd(t *testing.T) {
	r := &probeRunner{envOS: "Windows_NT"}
	s := newProbeServer(t, r)
	res, _, err := s.writeFile(context.Background(), &mcp.CallToolRequest{},
		writeIn{Machine: "w", Path: `C:\work\sub\f.txt`, Content: "data-marker-xyz"})
	if err != nil || res.IsError {
		t.Fatalf("writeFile: %v %+v", err, res)
	}
	call := r.last()
	if string(call.stdin) != "data-marker-xyz" {
		t.Fatalf("内容应走 stdin: %q", call.stdin)
	}
	if strings.Contains(call.cmd, "data-marker-xyz") {
		t.Fatal("内容不应嵌进命令行")
	}
	script := decodePS(t, call.cmd)
	for _, want := range []string{
		`$p='C:\work\sub\f.txt'`, "File]::Create", "OpenStandardInput", "CopyTo", "exit 1",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("脚本缺 %q:\n%s", want, script)
		}
	}
	if r.probeCount() != 2 {
		t.Fatalf("powershell 探测应跑 2 次探针，实际 %d", r.probeCount())
	}
	res, _, err = s.writeFile(context.Background(), &mcp.CallToolRequest{},
		writeIn{Machine: "w", Path: `C:\work\g.txt`, Content: "x"})
	if err != nil || res.IsError {
		t.Fatalf("第二次 writeFile: %v %+v", err, res)
	}
	if r.probeCount() != 2 {
		t.Fatalf("dialect 应缓存，探针总数应为 2，实际 %d", r.probeCount())
	}
}

func TestWindowsTildePath(t *testing.T) {
	r := &probeRunner{osVar: "Windows_NT", fileOut: "x"}
	s := newProbeServer(t, r)
	res, _, err := s.readFile(context.Background(), &mcp.CallToolRequest{},
		readIn{Machine: "w", Path: "~/work/x.txt"})
	if err != nil || res.IsError {
		t.Fatalf("readFile: %v %+v", err, res)
	}
	script := decodePS(t, r.last().cmd)
	for _, want := range []string{"$p='~/work/x.txt'", "$HOME", "StartsWith('~/')", "IsNullOrEmpty($HOME)"} {
		if !strings.Contains(script, want) {
			t.Fatalf("脚本缺 %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "$env:HOME") {
		t.Fatalf("不应用 $env:HOME（Windows PowerShell 默认没有）:\n%s", script)
	}
}

func TestWindowsRunCwdUsesRunAt(t *testing.T) {
	r := &probeRunner{osVar: "Windows_NT"}
	s := newProbeServer(t, r)
	res, _, err := s.runCommand(context.Background(), &mcp.CallToolRequest{},
		runIn{Machine: "w", Command: "echo hi", Cwd: `C:\work`})
	if err != nil || res.IsError {
		t.Fatalf("runCommand: %v %+v", err, res)
	}
	call := r.last()
	if !call.at {
		t.Fatal("Windows+cwd 应走 RunAt")
	}
	if call.cwd != `C:\work` {
		t.Fatalf("cwd = %q", call.cwd)
	}
	if call.cmd != "echo hi" {
		t.Fatalf("命令应原样下发不带 cd 包装: %q", call.cmd)
	}
}

func TestWindowsSessionRejected(t *testing.T) {
	r := &probeRunner{osVar: "Windows_NT"}
	s := newProbeServer(t, r)
	res, _, err := s.runCommand(context.Background(), &mcp.CallToolRequest{},
		runIn{Machine: "w", Command: "echo hi", Session: "s"})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("Windows session 应报错: %v %+v", err, res)
	}
	var text string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	if !strings.Contains(text, "不支持") {
		t.Fatalf("错误应说明不支持常驻 shell: %q", text)
	}
}

func TestPOSIXDialectUnchanged(t *testing.T) {
	r := &probeRunner{osVar: "%OS%", envOS: ":OS", fileOut: "posix-content"}
	s := newProbeServer(t, r)
	res, out, err := s.readFile(context.Background(), &mcp.CallToolRequest{},
		readIn{Machine: "w", Path: "~/x.txt"})
	if err != nil || res.IsError {
		t.Fatalf("readFile: %v %+v", err, res)
	}
	if out.Content != "posix-content" {
		t.Fatalf("content = %q", out.Content)
	}
	call := r.last()
	if call.at {
		t.Fatal("POSIX 不应走 RunAt")
	}
	if call.cmd != `head -c 1025 -- "$HOME/"'x.txt'` {
		t.Fatalf("POSIX 命令不对: %q", call.cmd)
	}
}

func TestDialectProbeErrorNotCached(t *testing.T) {
	r := &probeRunner{failNext: 1, osVar: "Windows_NT", fileOut: "x"}
	s := newProbeServer(t, r)
	res, _, err := s.readFile(context.Background(), &mcp.CallToolRequest{},
		readIn{Machine: "w", Path: `C:\work\f.txt`})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatalf("离线探针应直接报错: %v %+v", err, res)
	}
	if r.probeCount() != 1 {
		t.Fatalf("失败的是第一次探针，探针总数应为 1，实际 %d", r.probeCount())
	}
	res, _, err = s.readFile(context.Background(), &mcp.CallToolRequest{},
		readIn{Machine: "w", Path: `C:\work\f.txt`})
	if err != nil || res.IsError {
		t.Fatalf("探针恢复后 readFile 应走 PowerShell: %v %+v", err, res)
	}
	decodePS(t, r.last().cmd)
	if r.probeCount() != 2 {
		t.Fatalf("失败结果不应缓存，恢复后只该再探 1 次（%%OS%% 命中），总探针数应为 2，实际 %d", r.probeCount())
	}
}

func TestDialectProbeCtxCancelNotCached(t *testing.T) {
	r := &probeRunner{respectCtx: true, envOS: "Windows_NT", fileOut: "x"}
	s := newProbeServer(t, r)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.dialect(ctx, "w"); err == nil {
		t.Fatal("取消的 ctx 应返回错误")
	}
	if d, err := s.dialect(context.Background(), "w"); err != nil || !d.windows() {
		t.Fatalf("取消不应缓存 POSIX: %v %v", d, err)
	}
	if r.probeCount() != 3 {
		t.Fatalf("取消那次不算成功，探针总数应为 3（1 次失败 + 2 次成功），实际 %d", r.probeCount())
	}
}

func TestDialectProbeNonZeroExitNotCached(t *testing.T) {
	r := &probeRunner{probeExit: 1, envOS: "Windows_NT", fileOut: "x"}
	s := newProbeServer(t, r)
	if _, err := s.dialect(context.Background(), "w"); err == nil {
		t.Fatal("探针非零退出应报错")
	}
	r.mu.Lock()
	r.probeExit = 0
	r.mu.Unlock()
	if d, err := s.dialect(context.Background(), "w"); err != nil || d != dialectPowerShell {
		t.Fatalf("恢复后应识别 PowerShell: %v %v", d, err)
	}
}
