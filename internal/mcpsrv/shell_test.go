package mcpsrv

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeShell 用三根 io.Pipe 模拟远端 shell：测试往 stdinReader 读命令
// 脚本，往 stdout/stderrWriter 写输出。respond 回调拿到命令文本和本次
// 哨兵前缀（从写进 stdin 的哨兵脚本里解析出来，和真 shell 一样被动）。
type fakeShell struct {
	inW  *io.PipeWriter // exec 写 stdin 的一端
	outR *io.PipeReader
	errR *io.PipeReader
	in   *io.PipeReader // 测试侧读 stdin
	outW *io.PipeWriter
	errW *io.PipeWriter

	mu     sync.Mutex
	closed bool
}

func newFakeShell() *fakeShell {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	errR, errW := io.Pipe()
	return &fakeShell{inW: inW, outR: outR, errR: errR, in: inR, outW: outW, errW: errW}
}

func (f *fakeShell) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, io.ErrClosedPipe
	}
	return f.inW.Write(b)
}
func (f *fakeShell) Stdout() io.Reader { return f.outR }
func (f *fakeShell) Stderr() io.Reader { return f.errR }
func (f *fakeShell) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		_ = f.inW.Close()
		_ = f.outW.Close()
		_ = f.errW.Close()
	}
	return nil
}

var markerLineRe = regexp.MustCompile(`__TS_([0-9a-f]+)_(\d+)_`)

// readCommand 从 stdin 读到哨兵为止，返回收到的全部命令文本（命令和
// 哨兵在同一物理行里，所以含哨兵的行也算命令文本）和哨兵前缀。
func (f *fakeShell) readCommand() (cmd string, marker string, err error) {
	br := bufio.NewReader(f.in)
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		sb.WriteString(line)
		if m := markerLineRe.FindString(line); m != "" {
			return sb.String(), m, nil
		}
		if err != nil {
			return sb.String(), "", io.ErrUnexpectedEOF
		}
	}
}

// respond 模拟 shell 执行完命令：写两条流的输出 + 各自的哨兵。
// 哨兵前的 \n 模拟 printf 的起手换行。
func (f *fakeShell) respond(marker, out, err string, ec int) {
	fmt.Fprintf(f.outW, "%s\n%s%d\n", out, marker, ec)
	fmt.Fprintf(f.errW, "%s\n%s%d\n", err, marker, ec)
}

func TestShellExecBasic(t *testing.T) {
	f := newFakeShell()
	s := newShellSession(f, "t")
	s.start()
	go func() {
		cmd, mk, err := f.readCommand()
		if err != nil || !strings.Contains(cmd, "echo hi") {
			return
		}
		f.respond(mk, "hi\n", "", 0)
	}()
	res, err := s.exec(context.Background(), "echo hi", 5*time.Second, 1<<20)
	if err != nil || res.ExitCode != 0 || res.Stdout != "hi\n" || res.Stderr != "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// TestShellExecMarkerSplit 哨兵被切在两片输出之间也要认得出来。
func TestShellExecMarkerSplit(t *testing.T) {
	f := newFakeShell()
	s := newShellSession(f, "t")
	s.start()
	go func() {
		_, mk, err := f.readCommand()
		if err != nil {
			return
		}
		fmt.Fprintf(f.outW, "part1\n")
		half := len(mk)/2 + 2
		fmt.Fprintf(f.outW, "\n%s", mk[:half])
		time.Sleep(30 * time.Millisecond)
		fmt.Fprintf(f.outW, "%s0\n", mk[half:])
		fmt.Fprintf(f.errW, "\n%s0\n", mk)
	}()
	res, err := s.exec(context.Background(), "cmd", 5*time.Second, 1<<20)
	if err != nil || res.Stdout != "part1\n" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// TestShellExecFalseMarker 输出里出现哨兵前缀（set -x 会把哨兵脚本
// 回显出来）不能被当成真哨兵——后面没有「数字+换行」就不算。
func TestShellExecFalseMarker(t *testing.T) {
	f := newFakeShell()
	s := newShellSession(f, "t")
	s.start()
	go func() {
		_, mk, err := f.readCommand()
		if err != nil {
			return
		}
		// stderr 先吐出一段带哨兵前缀但不是哨兵的文本，再发真哨兵
		fmt.Fprintf(f.errW, "+ printf '\\n%s%%d\\n' \"$__tsec\"\n", mk)
		time.Sleep(30 * time.Millisecond)
		fmt.Fprintf(f.errW, "\n%s7\n", mk)
		fmt.Fprintf(f.outW, "real out\n\n%s7\n", mk)
	}()
	res, err := s.exec(context.Background(), "set -x; false", 5*time.Second, 1<<20)
	if err != nil || res.ExitCode != 7 || res.Stdout != "real out\n" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if !strings.Contains(res.Stderr, "printf") {
		t.Fatalf("假哨兵文本应保留在 stderr 里: %q", res.Stderr)
	}
}

// TestShellExecDeath 命令里的 exit/进程被杀 → 流 EOF → exec 报死，
// 会话标记 dead。
func TestShellExecDeath(t *testing.T) {
	f := newFakeShell()
	s := newShellSession(f, "t")
	s.start()
	go func() {
		_, _, _ = f.readCommand()
		f.Close() // shell 退出：管道全 EOF
	}()
	res, err := s.exec(context.Background(), "exit", 5*time.Second, 1<<20)
	if err != errShellDead {
		t.Fatalf("want errShellDead, got %v (res=%+v)", err, res)
	}
	if s.alive() {
		t.Fatal("会话应已标记死")
	}
}

// TestShellExecTimeout 命令卡住：超时返回 TimedOut，整个 shell 被杀。
func TestShellExecTimeout(t *testing.T) {
	f := newFakeShell()
	s := newShellSession(f, "t")
	s.start()
	go func() { _, _, _ = f.readCommand() }() // 吃掉输入，永远不回
	res, err := s.exec(context.Background(), "sleep 999", 200*time.Millisecond, 1<<20)
	if err != nil || !res.TimedOut {
		t.Fatalf("want TimedOut, got res=%+v err=%v", res, err)
	}
	if s.alive() {
		t.Fatal("超时后 shell 应被杀")
	}
}

// TestShellBacklog 两条命令之间到达的输出（后台任务）并入下一条的 stdout。
func TestShellBacklog(t *testing.T) {
	f := newFakeShell()
	s := newShellSession(f, "t")
	s.start()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, mk, err := f.readCommand()
		if err != nil {
			return
		}
		f.respond(mk, "first\n", "", 0)
		time.Sleep(30 * time.Millisecond)
		fmt.Fprintf(f.outW, "bg-job noise\n") // 命令结束后的迟到输出
		time.Sleep(30 * time.Millisecond)
		_, mk, err = f.readCommand()
		if err != nil {
			return
		}
		f.respond(mk, "second\n", "", 0)
	}()
	res, err := s.exec(context.Background(), "one", 5*time.Second, 1<<20)
	if err != nil || res.Stdout != "first\n" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	time.Sleep(60 * time.Millisecond) // 等迟到输出落进 backlog
	res, err = s.exec(context.Background(), "two", 5*time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "bg-job noise") || !strings.Contains(res.Stdout, "second\n") {
		t.Fatalf("backlog 应并入下一条输出: %q", res.Stdout)
	}
	<-done
}

// ---- Server 级：会话表管理（max_sessions、重启标记、空闲回收）----

// fakeOpener 实现 Runner + ShellOpener：Run 走不通的桩，OpenShell 给
// 一个 fakeShell，并把写进 stdin 的每条命令（含哨兵行）推进 got——
// 测试既能断言封装格式，也能拿哨兵前缀回包。
type fakeOpener struct {
	mu     sync.Mutex
	opened int
	shells []*fakeShell
	got    chan shellWrite
}

type shellWrite struct{ cmd, marker string }

func (f *fakeOpener) Run(context.Context, string, string, []byte, time.Duration, int) (Result, error) {
	return Result{}, fmt.Errorf("fakeOpener 不支持 Run")
}
func (f *fakeOpener) Connected(string) bool { return true }
func (f *fakeOpener) OpenShell(context.Context, string) (Shell, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sh := newFakeShell()
	f.shells = append(f.shells, sh)
	f.opened++
	got := f.gotch()
	// 吃掉 stdin（命令都往这写）：io.Pipe 是同步的，没人读 Write 会
	// 永久阻塞。攒到哨兵出现算一条完整命令，推进 got。
	go func() {
		br := bufio.NewReader(sh.in)
		var sb strings.Builder
		for {
			line, err := br.ReadString('\n')
			sb.WriteString(line)
			if m := markerLineRe.FindString(line); m != "" {
				select {
				case got <- shellWrite{sb.String(), m}:
				default:
				}
				sb.Reset()
			}
			if err != nil {
				return
			}
		}
	}()
	return sh, nil
}

// gotch 懒建 got 通道（autoRespond 可能先于 OpenShell 被调）。
func (f *fakeOpener) gotch() chan shellWrite {
	if f.got == nil {
		f.got = make(chan shellWrite, 64)
	}
	return f.got
}

// latest 返回最近开出来的 fakeShell（responder 用）。
func (f *fakeOpener) latest() *fakeShell {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.shells[len(f.shells)-1]
}

// writesList 是应答泵攒下的命令文本（线程安全）。
type writesList struct {
	mu   sync.Mutex
	cmds []string
}

func (w *writesList) get(i int) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cmds[i]
}
func (w *writesList) len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.cmds)
}

// autoRespond 起一个应答泵：每收到一条写进 shell 的命令就按 exit 0 回
// 双哨兵，把命令文本攒进返回的列表。
func (f *fakeOpener) autoRespond() *writesList {
	w := &writesList{}
	f.mu.Lock()
	got := f.gotch()
	f.mu.Unlock()
	go func() {
		for sw := range got {
			w.mu.Lock()
			w.cmds = append(w.cmds, sw.cmd)
			w.mu.Unlock()
			f.latest().respond(sw.marker, "", "", 0)
		}
	}()
	return w
}

func newTestServer(t *testing.T, opener Runner, maxSessions int) *Server {
	t.Helper()
	cfg := &Config{
		Machines: map[string]*Machine{"m": {}},
		Policy:   PolicyCfg{Default: "run", AskTimeout: time.Second},
		Limits:   LimitsCfg{Timeout: time.Second, MaxTimeout: time.Minute, MaxOutput: 1 << 20, MaxFile: 1024, SessionIdle: time.Minute, MaxSessions: maxSessions},
	}
	s, err := New(cfg, opener)
	if err != nil {
		t.Fatal(err)
	}
	s.remotes["m"] = remoteInfo{dialect: dialectPOSIX}
	t.Cleanup(s.Close)
	return s
}

func TestShellSessionLimit(t *testing.T) {
	op := &fakeOpener{}
	s := newTestServer(t, op, 2)
	ctx := context.Background()
	for _, name := range []string{"a", "b"} {
		if _, _, _, err := s.shellFor(ctx, "m", name); err != nil {
			t.Fatalf("shellFor %s: %v", name, err)
		}
	}
	if _, _, _, err := s.shellFor(ctx, "m", "c"); err == nil {
		t.Fatal("第三个会话应被 max_sessions 挡住")
	}
	// 死掉的会话不占位：杀掉 a 后应能再开
	s.shells["m\x00a"].kill()
	sh, created, restarted, err := s.shellFor(ctx, "m", "a")
	if err != nil || !created || !restarted {
		t.Fatalf("重建死会话应 created+restarted: %v %v %v", created, restarted, err)
	}
	_ = sh
}

func TestShellSessionIdleSweep(t *testing.T) {
	op := &fakeOpener{}
	s := newTestServer(t, op, 8)
	ctx := context.Background()
	sh, _, _, err := s.shellFor(ctx, "m", "idle1")
	if err != nil {
		t.Fatal(err)
	}
	// 把 lastUse 拨到过去，触发回收
	sh.mu.Lock()
	sh.lastUse = time.Now().Add(-2 * time.Minute)
	sh.mu.Unlock()
	s.sweepIdle()
	s.mu.Lock()
	_, stillThere := s.shells["m\x00idle1"]
	s.mu.Unlock()
	if stillThere {
		t.Fatal("空闲会话应被 sweepIdle 摘掉")
	}
	if sh.alive() {
		t.Fatal("空闲会话应被杀")
	}
	// 活跃的不能动
	sh2, _, _, _ := s.shellFor(ctx, "m", "live")
	s.sweepIdle()
	if !sh2.alive() {
		t.Fatal("活跃会话不应被回收")
	}
}

// dumbRunner 只实现 Runner、不实现 ShellOpener。
type dumbRunner struct{}

func (dumbRunner) Run(context.Context, string, string, []byte, time.Duration, int) (Result, error) {
	return Result{}, nil
}
func (dumbRunner) Connected(string) bool { return true }

func TestShellForUnsupportedRunner(t *testing.T) {
	// 不实现 ShellOpener 的 runner：session 模式要报明确错误
	cfg := &Config{
		Machines: map[string]*Machine{"m": {}},
		Policy:   PolicyCfg{Default: "run", AskTimeout: time.Second},
		Limits:   LimitsCfg{Timeout: time.Second, MaxTimeout: time.Minute, MaxOutput: 1 << 20, MaxFile: 1024, SessionIdle: time.Minute, MaxSessions: 8},
	}
	s, err := New(cfg, dumbRunner{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, _, err := s.shellFor(context.Background(), "m", "x"); err == nil {
		t.Fatal("runner 不支持 OpenShell 时应报错")
	}
}

// ---- 安全回归：拒绝的命令不能进 shell、写进去的字节必须封好 ----

// TestSessionDeniedWritesNothing 策略拒绝的命令连 shell 都不该开——
// 任何字节写进常驻 shell 都可能攒在输入里，被下一条已批准的命令凑齐执行。
func TestSessionDeniedWritesNothing(t *testing.T) {
	op := &fakeOpener{}
	cfg := &Config{
		Machines: map[string]*Machine{"m": {}},
		Policy:   PolicyCfg{Default: "run", Deny: []string{`forbidden`}, AskTimeout: time.Second},
		Limits:   LimitsCfg{Timeout: time.Second, MaxTimeout: time.Minute, MaxOutput: 1 << 20, MaxFile: 1024, SessionIdle: time.Minute, MaxSessions: 8},
	}
	s, err := New(cfg, op)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, _, err := s.runCommand(context.Background(), &mcp.CallToolRequest{}, runIn{
		Machine: "m", Command: "echo ok && forbidden-thing", Session: "w",
	})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("deny 命令应返回错误结果: res=%v err=%v", res, err)
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.opened != 0 {
		t.Fatal("被拒的命令不该开出 shell")
	}
}

// TestSessionFraming 写进常驻 shell 的字节必须是 eval '字面量' 封装：
// 内嵌换行留在引号里、裸 ' 被转义——一条调用对 shell 永远是一行输入，
// 残缺的命令片段不会漏成顶层输入攒到下一次执行。
func TestSessionFraming(t *testing.T) {
	op := &fakeOpener{}
	s := newTestServer(t, op, 8)
	ctx := context.Background()
	req := &mcp.CallToolRequest{}
	writes := op.autoRespond()

	call := func(command string) *mcp.CallToolResult {
		t.Helper()
		res, _, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: command, Session: "w"})
		if err != nil {
			t.Fatalf("runCommand %q: %v", command, err)
		}
		return res
	}

	// 多行命令：换行必须留在 eval 的单引号里
	res := call("echo a\necho b")
	if res.IsError {
		t.Fatalf("多行命令被拒: %v", res.Content)
	}
	w := writes.get(0)
	if !strings.Contains(w, "eval 'echo a\necho b'") {
		t.Fatalf("命令应整体封进 eval 单引号，实际写入: %q", w)
	}
	if n := strings.Count(w, "\n"); n != 2 { // 引号内 1 个 + 行尾 1 个
		t.Fatalf("内嵌换行漏出引号（应有 2 个 \\n，有 %d）: %q", n, w)
	}

	// 未闭合的单引号：必须被转义，不能变成挂起的顶层输入
	call("echo 'unclosed")
	w = writes.get(1)
	if !strings.Contains(w, `eval 'echo '\''unclosed'`) {
		t.Fatalf("裸引号应被转义，实际写入: %q", w)
	}
	if n := strings.Count(w, "\n"); n != 1 {
		t.Fatalf("应只有行尾一个 \\n，有 %d: %q", n, w)
	}

	// 已存在的会话传 cwd：报错且一个字节都不写
	before := writes.len()
	res = call2(t, s, ctx, req, runIn{Machine: "m", Command: "pwd", Session: "w", Cwd: "/tmp"})
	if !res.IsError {
		t.Fatal("已有会话传 cwd 应报错")
	}
	if writes.len() != before {
		t.Fatal("cwd 报错路径不该往 shell 写字节")
	}
}

func call2(t *testing.T, s *Server, ctx context.Context, req *mcp.CallToolRequest, in runIn) *mcp.CallToolResult {
	t.Helper()
	res, _, err := s.runCommand(ctx, req, in)
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	return res
}

// TestSessionCwdOnCreate 新会话带 cwd：写入的命令应带 cd 前缀且路径加引号。
func TestSessionCwdOnCreate(t *testing.T) {
	op := &fakeOpener{}
	s := newTestServer(t, op, 8)
	writes := op.autoRespond()
	res := call2(t, s, context.Background(), &mcp.CallToolRequest{}, runIn{
		Machine: "m", Command: "pwd", Session: "v", Cwd: "/tmp/we'ird",
	})
	if res.IsError {
		t.Fatalf("建会话失败: %v", res.Content)
	}
	w := writes.get(0)
	if !strings.Contains(w, `cd -- '/tmp/we'\''ird' && eval 'pwd'`) {
		t.Fatalf("cwd 应加引号做前缀，实际写入: %q", w)
	}
}
