package mcpsrv

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// countingRunner 记下每条真被执行的命令——确认环节合不合格就看它。
type countingRunner struct {
	mu   sync.Mutex
	runs []string
}

func (c *countingRunner) Run(_ context.Context, _ string, cmd string, _ []byte, _ time.Duration, _ int) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := fakeResolve(cmd); ok {
		// 路径解析是文件工具的基础设施调用，不算「被执行的命令」。
		return Result{Stdout: p}, nil
	}
	c.runs = append(c.runs, cmd)
	return Result{Stdout: "ok"}, nil
}
func (c *countingRunner) Connected(string) bool { return true }
func (c *countingRunner) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.runs)
}

// rememberedKey 把批准钉死在完整上下文上：换类型/cwd/stdin 摘要都
// 是另一条请求，一个「同意」不能跨边界复用。尤其是 command↔terminal
// 分桶——批过一次 run_command{bash -l} 不能放行同名交互终端。
func TestRememberedKeyBinding(t *testing.T) {
	base := ApprovalRequest{Machine: "m", Kind: "command", Detail: "bash -l"}
	same := ApprovalRequest{Machine: "m", Kind: "command", Detail: "bash -l"}
	if rememberedKey(base) != rememberedKey(same) {
		t.Fatal("同请求应同键")
	}
	for name, req := range map[string]ApprovalRequest{
		"terminal 同命令": {Machine: "m", Kind: "terminal", Detail: "bash -l"},
		"换 cwd":        {Machine: "m", Kind: "command", Detail: "bash -l", Cwd: "/tmp"},
		"带 stdin":      {Machine: "m", Kind: "command", Detail: "bash -s", Digest: digestOf("rm -rf /")},
		"stdin 换了内容":   {Machine: "m", Kind: "command", Detail: "bash -s", Digest: digestOf("rm -rf /tmp")},
		"换机器":          {Machine: "other", Kind: "command", Detail: "bash -l"},
	} {
		if rememberedKey(base) == rememberedKey(req) && name != "terminal 同命令" {
			t.Errorf("%s 不应与基准同键", name)
		}
	}
	// command 和 terminal 即便所有字段相同，Kind 不同必须分桶
	term := ApprovalRequest{Machine: "m", Kind: "terminal", Detail: "bash -l"}
	if rememberedKey(base) == rememberedKey(term) {
		t.Error("command/terminal 必须分桶——批一次命令不能解锁交互终端")
	}
	// stdin 摘要参与绑定：同命令不同 stdin 是两回事
	d1 := ApprovalRequest{Machine: "m", Kind: "command", Detail: "bash -s", Digest: digestOf("ls")}
	d2 := ApprovalRequest{Machine: "m", Kind: "command", Detail: "bash -s", Digest: digestOf("rm -rf /")}
	if rememberedKey(d1) == rememberedKey(d2) {
		t.Error("stdin 不同必须分键——批了 ls 的 bash -s 不能跑 rm 的 stdin")
	}
}

// previewOf 的输出：单行、剥掉控制字符、带摘要钉死身份。
func TestPreviewOf(t *testing.T) {
	p := previewOf("stdin", "rm -rf /\n\x1b[2J\x07evil")
	if strings.ContainsAny(p, "\n\x1b\x07") {
		t.Fatalf("预览必须剥控制字符: %q", p)
	}
	if !strings.Contains(p, "stdin") || !strings.Contains(p, "sha256") {
		t.Fatalf("预览要带类型和摘要: %q", p)
	}
	if previewOf("stdin", "") != "" {
		t.Fatal("空输入不产预览")
	}
}

// TestAutoFallsBackToLocal：ask_via 不写（auto）且客户端没有弹窗能力时，
// 批准必须落到本地待批文件——审批默认要真人，不能悄悄降格成 LLM 会话内
// 确认；OnPending 钩子要把提示递出去（内嵌服务器接它写 SSH 终端）。
func TestAutoFallsBackToLocal(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.ApprovalsDir = t.TempDir()
	s.cfg.Policy.AskTimeout = 5 * time.Second
	pending := make(chan string, 1)
	s.cfg.OnPending = func(machine, text string) { pending <- machine + "|" + text }

	type res struct {
		r   *mcp.CallToolResult
		err error
	}
	done := make(chan res, 1)
	go func() {
		r, _, err := s.runCommand(context.Background(), &mcp.CallToolRequest{},
			runIn{Machine: "m", Command: "rm -rf /tmp/x"})
		done <- res{r, err}
	}()

	// auto + 无会话（= 无弹窗能力）：待批文件出现、OnPending 收到机器名
	var id string
	deadline := time.Now().Add(3 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		if pend, _ := Pending(s.cfg.ApprovalsDir); len(pend) > 0 {
			id = pend[0].ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("auto 无弹窗能力时应落本地待批文件")
	}
	select {
	case note := <-pending:
		if !strings.HasPrefix(note, "m|") {
			t.Fatalf("OnPending 应带机器名 m: %q", note)
		}
	default:
		t.Fatal("待批挂上时 OnPending 没收到通知")
	}
	// 文件协议批准后真的执行
	if _, err := ApprovePending(s.cfg.ApprovalsDir, id, false, false); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.r == nil || r.r.IsError {
			t.Fatalf("批准后应执行成功: %+v %v", r.r, r.err)
		}
		if op.count() != 1 {
			t.Fatal("命令没真的执行")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("批准后调用没返回")
	}
}

// TestLLMConfirmFlow 覆盖「会话内确认」的两步握手：ask 命令第一次调用只
// 发指引不执行；LLM 带 confirmed=true 重试才放行；标记一次性、按命令区分。
func TestLLMConfirmFlow(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "llm"
	ctx := context.Background()
	req := &mcp.CallToolRequest{}

	// 第一次调用 rm（内置 ask 名单）：报错指引、不执行
	res, _, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/x"})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("ask 命令首次应报错: %v %+v", err, res)
	}
	if txt := resultTextForTest(res); !strings.Contains(txt, "需要用户确认") || !strings.Contains(txt, "confirmed=true") {
		t.Fatalf("报错应带确认指引: %s", txt)
	}
	if op.count() != 0 {
		t.Fatal("没确认就执行了")
	}

	// 另一条没发起过确认的命令直接带 confirmed=true：不能预授权，
	// 照样走首次确认（服务端说了算什么时候需要同意）
	res, _, err = s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/y", Confirmed: true})
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultTextForTest(res), "需要用户确认") {
		t.Fatalf("未发起确认的命令不能靠 confirmed 直接过: %v %+v", err, res)
	}
	if op.count() != 0 {
		t.Fatal("confirmed 预授权绕过了确认")
	}

	// 用户同意后带 confirmed=true 重试原命令：执行，approval=confirmed
	res, out, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/x", Confirmed: true})
	if err != nil || res.IsError || out.Approval != "confirmed" {
		t.Fatalf("confirmed 重试应执行: %v %s %+v", err, resultTextForTest(res), out)
	}
	if op.count() != 1 {
		t.Fatalf("执行次数不对: %d", op.count())
	}

	// 标记一次性：同命令再来一轮还要重新确认
	res, _, err = s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/x"})
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultTextForTest(res), "需要用户确认") {
		t.Fatalf("确认标记应一次性: %v %+v", err, res)
	}
	if op.count() != 1 {
		t.Fatal("用过的确认标记又放行了一次")
	}
}

// TestLLMConfirmRemember 验证 confirmed+remember：用户说「以后都允许」时
// 同类命令在会话内不再问。
func TestLLMConfirmRemember(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "llm"
	ctx := context.Background()
	req := &mcp.CallToolRequest{}

	if res, _, _ := s.runCommand(ctx, req, runIn{Machine: "m", Command: "sudo id"}); res == nil || !res.IsError {
		t.Fatal("首次应进确认")
	}
	res, out, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: "sudo id", Confirmed: true, Remember: true})
	if err != nil || res.IsError || out.Approval != "confirmed" {
		t.Fatalf("confirmed+remember 应执行: %v %s %+v", err, resultTextForTest(res), out)
	}
	// 同命令再次执行：命中 remembered，不再确认
	res, out, err = s.runCommand(ctx, req, runIn{Machine: "m", Command: "sudo id"})
	if err != nil || res.IsError || out.Approval != "remembered" {
		t.Fatalf("remember 后同命令应 remembered 放行: %v %s %+v", err, resultTextForTest(res), out)
	}
	if op.count() != 2 {
		t.Fatalf("执行次数不对: %d", op.count())
	}
}

// TestLLMConfirmDenyUnaffected：confirmed 只解 ask 档，硬拒命令不吃这套。
func TestLLMConfirmDenyUnaffected(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	res, _, err := s.runCommand(context.Background(), &mcp.CallToolRequest{},
		runIn{Machine: "m", Command: "rm -rf /", Confirmed: true})
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultTextForTest(res), "策略拒绝") {
		t.Fatalf("deny 命令应照旧硬拒: %v %+v", err, res)
	}
	if op.count() != 0 {
		t.Fatal("deny 命令被执行了")
	}
}

// TestLLMConfirmWriteFile：write_file 出 roots 也走同一条会话内确认。
func TestLLMConfirmWriteFile(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "llm"
	ctx := context.Background()
	req := &mcp.CallToolRequest{}
	in := writeIn{Machine: "m", Path: "/tmp/confirm-me", Content: "x"}

	res, _, err := s.writeFile(ctx, req, in)
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultTextForTest(res), "需要用户确认") {
		t.Fatalf("越界写文件应要确认: %v %+v", err, res)
	}
	in.Confirmed = true
	res, _, err = s.writeFile(ctx, req, in)
	if err != nil || res.IsError {
		t.Fatalf("confirmed 后应写入: %v %s", err, resultTextForTest(res))
	}
	if op.count() != 1 {
		t.Fatal("写入没落盘")
	}
}

// TestAskViaLocalRestoresPending：ask_via: local 时回到老的待批文件流程。
func TestAskViaLocalRestoresPending(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "local"
	s.cfg.ApprovalsDir = t.TempDir()
	s.cfg.Policy.AskTimeout = 200 * time.Millisecond

	res, _, err := s.runCommand(context.Background(), &mcp.CallToolRequest{},
		runIn{Machine: "m", Command: "rm /tmp/x"})
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultTextForTest(res), "超时") {
		t.Fatalf("local 模式应挂起到超时: %v %+v", err, res)
	}
	if op.count() != 0 {
		t.Fatal("local 模式没人批不该执行")
	}
}

// TestLocalRemember：本地批准通道里「允许并不再问」（对话框第三钮 /
// approve --remember 落下的 .remember 文件）要把命令记进会话名单——
// 同命令再来直接放行、不落新待批文件；不同命令照常问。
func TestLocalRemember(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "local"
	s.cfg.ApprovalsDir = t.TempDir()
	s.cfg.Policy.AskTimeout = 5 * time.Second
	ctx := context.Background()
	req := &mcp.CallToolRequest{}

	// 第一次调用挂起等批准；看到待批文件后模拟「批准并记住」
	type res struct {
		r   *mcp.CallToolResult
		out runOut
		err error
	}
	done := make(chan res, 1)
	go func() {
		r, o, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/x"})
		done <- res{r, o, err}
	}()
	var id string
	deadline := time.Now().Add(3 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		if pend, _ := Pending(s.cfg.ApprovalsDir); len(pend) > 0 {
			id = pend[0].ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("3 秒内没出现待批文件")
	}
	if _, err := ApprovePending(s.cfg.ApprovalsDir, id, false, true); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.r == nil || r.r.IsError {
			t.Fatalf("批准后应执行成功: %+v %v", r.r, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("批准后调用没返回")
	}

	// 同命令再来：remembered 直接放行，不再落待批文件
	r2, out2, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/x"})
	if err != nil || r2 == nil || r2.IsError || out2.Approval != "remembered" {
		t.Fatalf("同命令应 remembered 放行: %v %+v %+v", err, r2, out2)
	}
	if pend, _ := Pending(s.cfg.ApprovalsDir); len(pend) != 0 {
		t.Fatalf("remembered 不该再落待批文件: %+v", pend)
	}
	if op.count() != 2 {
		t.Fatalf("执行次数不对: %d", op.count())
	}

	// 不同命令不受影响，照常进待批
	go s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/y"})
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pend, _ := Pending(s.cfg.ApprovalsDir); len(pend) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("不同命令应照常进批准")
}

// TestMachinePolicyOpen：machines.<m>.policy=open（agent 自报或机器 yaml
// 写）让 ask 环节整体跳过——命令直放且标 approval=open、越界写文件不问、
// 审计记 MCP-POLICY-OPEN；deny 名单保底不动。
func TestMachinePolicyOpen(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Machines["m"].Policy = "open"
	s.cfg.ApprovalsDir = t.TempDir()
	var events []string
	s.cfg.Audit = func(ev string, _ ...string) { events = append(events, ev) }
	ctx := context.Background()
	req := &mcp.CallToolRequest{}

	// rm 在内置 ask 名单里：open 机器直接执行，不落待批、不弹窗
	res, out, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/x"})
	if err != nil || res == nil || res.IsError || out.Approval != "open" {
		t.Fatalf("open 机器应免批准直放: %v %+v %+v", err, res, out)
	}
	if pend, _ := Pending(s.cfg.ApprovalsDir); len(pend) != 0 {
		t.Fatalf("open 不该落待批文件: %+v", pend)
	}

	// deny 保底：open 放的是 ask，不放 deny
	res, _, err = s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm -rf /"})
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultTextForTest(res), "策略拒绝") {
		t.Fatalf("open 机器上 deny 命令应照旧硬拒: %v %+v", err, res)
	}

	// write_file 越界：open 机器不问直接写
	res, _, err = s.writeFile(ctx, req, writeIn{Machine: "m", Path: "/tmp/open-write", Content: "x"})
	if err != nil || res == nil || res.IsError {
		t.Fatalf("open 机器越界写应免批准: %v %+v", err, res)
	}
	if pend, _ := Pending(s.cfg.ApprovalsDir); len(pend) != 0 {
		t.Fatalf("open 不该落待批文件: %+v", pend)
	}
	if op.count() != 2 {
		t.Fatalf("执行次数不对: %d", op.count())
	}

	// 审计：两条放行各记 MCP-POLICY-OPEN；deny 记 MCP-POLICY-DENY
	var opens, denies int
	for _, ev := range events {
		switch ev {
		case "MCP-POLICY-OPEN":
			opens++
		case "MCP-POLICY-DENY":
			denies++
		}
	}
	if opens != 2 || denies != 1 {
		t.Fatalf("审计事件不对: open=%d deny=%d（%v）", opens, denies, events)
	}
}

// readAuthRecords 扫 auth-records 目录，返回每条记录的全文。
func readAuthRecords(t *testing.T, s *Server) []string {
	t.Helper()
	ents, err := os.ReadDir(s.authRecordDir())
	if err != nil {
		t.Fatalf("授权记录目录不存在: %v", err)
	}
	var out []string
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(s.authRecordDir(), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return out
}

var authIDRe = regexp.MustCompile(`(?m)^auth: (ap-[0-9a-f]+)$`)

// TestAuthRecordExec：授权过的命令留完整档案——申请的命令、实际结果、
// 授权编号一一对应；remembered 复用的执行指回当初那次批准（同一个 auth）。
func TestAuthRecordExec(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "llm"
	s.cfg.ApprovalsDir = filepath.Join(t.TempDir(), "approvals")
	ctx := context.Background()
	req := &mcp.CallToolRequest{}

	// 普通（非授权）命令不留记录
	if res, _, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: "echo hi"}); err != nil || res.IsError {
		t.Fatalf("普通命令应直接执行: %v %s", err, resultTextForTest(res))
	}
	if _, err := os.Stat(s.authRecordDir()); !os.IsNotExist(err) {
		t.Fatal("非授权命令不该建授权记录目录")
	}

	// ask 命令：确认 → 执行 → 留档
	if res, _, _ := s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/x"}); res == nil || !res.IsError {
		t.Fatal("首次应进确认")
	}
	res, out, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/x", Confirmed: true, Remember: true})
	if err != nil || res.IsError || out.Approval != "confirmed" {
		t.Fatalf("confirmed 应执行: %v %s", err, resultTextForTest(res))
	}
	recs := readAuthRecords(t, s)
	if len(recs) != 1 {
		t.Fatalf("应有 1 条授权记录，实际 %d", len(recs))
	}
	rec := recs[0]
	for _, want := range []string{"auth: ap-", "exec: ex-", "command: rm /tmp/x", "kind: exec", "exit_code: 0", "ok"} {
		if !strings.Contains(rec, want) {
			t.Fatalf("记录缺 %q:\n%s", want, rec)
		}
	}
	firstAuth := authIDRe.FindStringSubmatch(rec)[1]

	// remembered 复用：第二条记录换了 exec，但 auth 指回第一次批准
	if res, out, err := s.runCommand(ctx, req, runIn{Machine: "m", Command: "rm /tmp/x"}); err != nil || res.IsError || out.Approval != "remembered" {
		t.Fatalf("remembered 应放行: %v %s %+v", err, resultTextForTest(res), out)
	}
	recs = readAuthRecords(t, s)
	if len(recs) != 2 {
		t.Fatalf("应有 2 条授权记录，实际 %d", len(recs))
	}
	var second string
	for _, r := range recs {
		if r != rec {
			second = r
		}
	}
	if got := authIDRe.FindStringSubmatch(second)[1]; got != firstAuth {
		t.Fatalf("remembered 执行应指回当初的授权 %s，实际 %s", firstAuth, got)
	}
}

// TestAuthRecordPTY：授权过的 PTY 终端输出全程落盘，关闭时写收尾。
func TestAuthRecordPTY(t *testing.T) {
	op := &fakeTerminalRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "llm"
	s.cfg.ApprovalsDir = filepath.Join(t.TempDir(), "approvals")
	ctx := context.Background()
	req := &mcp.CallToolRequest{}
	in := terminalOpenIn{Machine: "m", Command: "sudo pi", Cols: 80, Rows: 24}

	// sudo 命中 ask：首开只发指引，终端不创建
	res, _, err := s.terminalOpen(ctx, req, in)
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("首开应进确认: %v %+v", err, res)
	}
	if op.count() != 0 {
		t.Fatal("没确认就开了终端")
	}

	in.Confirmed = true
	res, out, err := s.terminalOpen(ctx, req, in)
	if err != nil || res.IsError || out.Approval != "confirmed" {
		t.Fatalf("confirmed 应开终端: %v %s %+v", err, resultTextForTest(res), out)
	}
	raw := op.latest()
	raw.writeOutput("SECRET-OUTPUT-123")
	term, _ := s.terminalFor(out.TerminalID)
	readTerminalUntil(t, term, "SECRET-OUTPUT-123")
	if _, _, err := s.terminalClose(ctx, req, terminalCloseIn{TerminalID: out.TerminalID}); err != nil {
		t.Fatal(err)
	}

	recs := readAuthRecords(t, s)
	if len(recs) != 1 {
		t.Fatalf("应有 1 条 PTY 记录，实际 %d", len(recs))
	}
	rec := recs[0]
	for _, want := range []string{"auth: ap-", "exec: ex-", "command: sudo pi", "SECRET-OUTPUT-123", "exit_code: 137"} {
		if !strings.Contains(rec, want) {
			t.Fatalf("PTY 记录缺 %q:\n%s", want, rec)
		}
	}
}
