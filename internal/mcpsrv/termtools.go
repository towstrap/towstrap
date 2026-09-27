package mcpsrv

// 终端工具：terminal_open/write/read/resize/close/list 和 PTY 记录。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type terminalOpenIn struct {
	Machine   string `json:"machine" jsonschema:"机器名，来自 list_machines"`
	Command   string `json:"command" jsonschema:"要在 PTY 里执行的命令（经 shell -c 解释）；例如 pi、vim、top，想开交互 shell 就写 bash -l/zsh -l"`
	Cwd       string `json:"cwd,omitempty" jsonschema:"工作目录；不设就用 agent 的默认目录"`
	Cols      int    `json:"cols,omitempty" jsonschema:"终端列数，默认 80，最大 500"`
	Rows      int    `json:"rows,omitempty" jsonschema:"终端行数，默认 24，最大 200"`
	Confirmed bool   `json:"confirmed,omitempty" jsonschema:"仅 llm 会话内确认路径生效：用户在对话中明确同意后，配合「需要用户确认」的报错原样重试；其它批准路径下此参数无效；没问过用户不要设"`
	Remember  bool   `json:"remember,omitempty" jsonschema:"随 confirmed 一起设（仅 llm 会话内确认路径生效）：用户说此类操作以后都允许时用"`
}

type terminalOpenOut struct {
	TerminalID string `json:"terminal_id" jsonschema:"后续 terminal_read/write/resize/close 要用的终端 ID"`
	Machine    string `json:"machine"`
	Cols       int    `json:"cols"`
	Rows       int    `json:"rows"`
	Approval   string `json:"approval" jsonschema:"本次怎么过的批准：allowed / approved / remembered / confirmed / open"`
}

type terminalWriteIn struct {
	TerminalID string `json:"terminal_id" jsonschema:"terminal_open 返回的终端 ID"`
	Input      string `json:"input" jsonschema:"写进 PTY 的原始输入；可包含换行、Ctrl 字符和 ANSI 按键序列"`
}

type terminalWriteOut struct {
	BytesWritten int  `json:"bytes_written"`
	Closed       bool `json:"closed" jsonschema:"远端进程当前是否已结束"`
	ExitCode     int  `json:"exit_code" jsonschema:"已结束时是退出码；还在运行是 -1"`
}

type terminalReadIn struct {
	TerminalID     string `json:"terminal_id" jsonschema:"terminal_open 返回的终端 ID"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"没有新输出时最多等几秒，默认 1 秒，最大 30 秒；0 表示立刻返回"`
	MaxBytes       int    `json:"max_bytes,omitempty" jsonschema:"本次最多返回多少字节，默认按 max_output，最大 262144"`
}

type terminalReadOut struct {
	Output       string `json:"output" jsonschema:"PTY 合并输出，可能包含 ANSI 控制序列"`
	Closed       bool   `json:"closed" jsonschema:"远端进程是否已结束"`
	ExitCode     int    `json:"exit_code" jsonschema:"已结束时是退出码；还在运行是 -1"`
	Truncated    bool   `json:"truncated" jsonschema:"缓冲区满后是否丢过中间输出"`
	DroppedBytes int    `json:"dropped_bytes,omitempty" jsonschema:"自上次读取以来丢掉的字节数"`
	HasMore      bool   `json:"has_more" jsonschema:"缓冲区里还有没有未读输出"`
}

type terminalResizeIn struct {
	TerminalID string `json:"terminal_id"`
	Cols       int    `json:"cols" jsonschema:"新的列数，1-500"`
	Rows       int    `json:"rows" jsonschema:"新的行数，1-200"`
}

type terminalResizeOut struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

type terminalCloseIn struct {
	TerminalID string `json:"terminal_id"`
}

type terminalCloseOut struct {
	Closed   bool `json:"closed" jsonschema:"关闭请求是否已发出"`
	ExitCode int  `json:"exit_code" jsonschema:"已经拿到退出状态时是退出码，否则 -1"`
}

type terminalListIn struct{}

type terminalInfo struct {
	TerminalID  string `json:"terminal_id"`
	Machine     string `json:"machine"`
	Cols        int    `json:"cols"`
	Rows        int    `json:"rows"`
	Closed      bool   `json:"closed"`
	ExitCode    int    `json:"exit_code"`
	IdleSeconds int64  `json:"idle_seconds"`
}

type terminalListOut struct {
	Terminals []terminalInfo `json:"terminals"`
}

// openTermRecord 给授权过的 PTY 终端开记录文件并写好头部，返回路径。
// 必须在 term.start() 之前调，保证开头输出不漏。失败返回空串——审计
// 事件里 record 缺省即表示没落盘。
func (s *Server) openTermRecord(term *terminalSession, opts TerminalOptions) string {
	dir := s.authRecordDir()
	if dir == "" {
		return ""
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ""
	}
	p := filepath.Join(dir, term.execID+".pty")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return ""
	}
	fmt.Fprintf(f, "# towstrap 授权会话记录（PTY 终端）\nauth: %s\nexec: %s\nmachine: %s\nterminal: %s\ncommand: %s\ncwd: %s\nsize: %dx%d\nstarted: %s\n--- 以下为终端原始输出 ---\n",
		term.authID, term.execID, term.machine, term.id, opts.Command,
		orDash(opts.Cwd), opts.Cols, opts.Rows, term.created.Format(time.RFC3339Nano))
	term.rec = f
	return p
}

func terminalSize(cols, rows int) (int, int, error) {
	if cols == 0 {
		cols = terminalDefaultCols
	}
	if rows == 0 {
		rows = terminalDefaultRows
	}
	if cols < 1 || cols > terminalMaxCols || rows < 1 || rows > terminalMaxRows {
		return 0, 0, fmt.Errorf("终端尺寸不合法：cols 1-%d，rows 1-%d", terminalMaxCols, terminalMaxRows)
	}
	return cols, rows, nil
}

func (s *Server) terminalOpen(ctx context.Context, req *mcp.CallToolRequest, in terminalOpenIn) (*mcp.CallToolResult, terminalOpenOut, error) {
	in.Machine = s.resolveMachine(in.Machine)
	if _, ok := s.cfg.Machines[in.Machine]; !ok || s.machineBlocked(in.Machine) {
		r, e := errResult("机器 %q 不在配置里或当前凭据无权访问，先用 list_machines 看有哪些", in.Machine)
		return r, terminalOpenOut{}, e
	}
	if strings.TrimSpace(in.Command) == "" {
		r, e := errResult("terminal_open 需要 command；要开交互 shell 可写 bash -l 或 zsh -l")
		return r, terminalOpenOut{}, e
	}
	cols, rows, err := terminalSize(in.Cols, in.Rows)
	if err != nil {
		r, e := errResult("%v", err)
		return r, terminalOpenOut{}, e
	}
	s.watchSession(req.Session)
	approval, authID, early := s.authorizeCommand(ctx, req, "terminal", in.Machine, in.Command, in.Cwd, "", "", in.Confirmed, in.Remember)
	if early != nil {
		return early, terminalOpenOut{}, nil
	}
	term, err := s.openTerminal(ctx, in.Machine, TerminalOptions{
		Command: in.Command, Cwd: in.Cwd, Cols: cols, Rows: rows,
	}, authID)
	if err != nil {
		r, e := errResult("开 PTY 终端失败：%v", err)
		return r, terminalOpenOut{}, e
	}
	kv := []string{"machine", in.Machine, "terminal", term.id,
		"cmd", in.Command, "cols", fmt.Sprintf("%d", cols), "rows", fmt.Sprintf("%d", rows), "approval", approval}
	if authID != "" {
		kv = append(kv, "auth", authID, "exec", term.execID, "record", term.recPath)
	}
	s.audit("MCP-TERMINAL-OPEN", kv...)
	out := terminalOpenOut{TerminalID: term.id, Machine: in.Machine, Cols: cols, Rows: rows, Approval: approval}
	return textResult("PTY 终端已打开：terminal_id=%s machine=%s size=%dx%d approval=%s\n下一步用 terminal_read 等启动输出，用 terminal_write 发按键；用完记得 terminal_close。",
		term.id, in.Machine, cols, rows, approval), out, nil
}

func (s *Server) terminalWrite(_ context.Context, _ *mcp.CallToolRequest, in terminalWriteIn) (*mcp.CallToolResult, terminalWriteOut, error) {
	term, err := s.terminalFor(in.TerminalID)
	if err != nil {
		r, e := errResult("%v", err)
		return r, terminalWriteOut{}, e
	}
	if len(in.Input) > terminalMaxInput {
		r, e := errResult("input %d 字节超过单次上限 %d", len(in.Input), terminalMaxInput)
		return r, terminalWriteOut{}, e
	}
	n, err := term.write([]byte(in.Input))
	if err != nil {
		r, e := errResult("写终端失败（已写 %d 字节）：%v", n, err)
		return r, terminalWriteOut{}, e
	}
	closed, code := term.state()
	s.audit("MCP-TERMINAL-WRITE", "machine", term.machine, "terminal", term.id, "bytes", fmt.Sprintf("%d", n))
	return textResult("已写入 %d 字节", n), terminalWriteOut{BytesWritten: n, Closed: closed, ExitCode: code}, nil
}

func (s *Server) terminalRead(_ context.Context, _ *mcp.CallToolRequest, in terminalReadIn) (*mcp.CallToolResult, terminalReadOut, error) {
	term, err := s.terminalFor(in.TerminalID)
	if err != nil {
		r, e := errResult("%v", err)
		return r, terminalReadOut{}, e
	}
	if in.TimeoutSeconds < 0 {
		r, e := errResult("timeout_seconds 不能是负数")
		return r, terminalReadOut{}, e
	}
	maxBytes := in.MaxBytes
	if maxBytes <= 0 {
		maxBytes = s.cfg.Limits.MaxOutput
	}
	res := term.read(time.Duration(in.TimeoutSeconds)*time.Second, maxBytes)
	out := terminalReadOut{
		Output: res.output, Closed: res.closed, ExitCode: res.exitCode,
		Truncated: res.dropped > 0, DroppedBytes: res.dropped, HasMore: res.hasMore,
	}
	s.audit("MCP-TERMINAL-READ", "machine", term.machine, "terminal", term.id,
		"bytes", fmt.Sprintf("%d", len(res.output)), "closed", fmt.Sprintf("%t", res.closed))
	text := fmt.Sprintf("terminal=%s closed=%t exit_code=%d dropped_bytes=%d has_more=%t\n%s",
		term.id, res.closed, res.exitCode, res.dropped, res.hasMore, res.output)
	return textResult("%s", text), out, nil
}

func (s *Server) terminalResize(_ context.Context, _ *mcp.CallToolRequest, in terminalResizeIn) (*mcp.CallToolResult, terminalResizeOut, error) {
	term, err := s.terminalFor(in.TerminalID)
	if err != nil {
		r, e := errResult("%v", err)
		return r, terminalResizeOut{}, e
	}
	cols, rows, err := terminalSize(in.Cols, in.Rows)
	if err != nil {
		r, e := errResult("%v", err)
		return r, terminalResizeOut{}, e
	}
	if err := term.resize(cols, rows); err != nil {
		r, e := errResult("改终端尺寸失败：%v", err)
		return r, terminalResizeOut{}, e
	}
	s.audit("MCP-TERMINAL-RESIZE", "machine", term.machine, "terminal", term.id,
		"cols", fmt.Sprintf("%d", cols), "rows", fmt.Sprintf("%d", rows))
	return textResult("终端尺寸已改为 %dx%d", cols, rows), terminalResizeOut{Cols: cols, Rows: rows}, nil
}

func (s *Server) terminalClose(_ context.Context, _ *mcp.CallToolRequest, in terminalCloseIn) (*mcp.CallToolResult, terminalCloseOut, error) {
	term, err := s.terminalFor(in.TerminalID)
	if err != nil {
		r, e := errResult("%v", err)
		return r, terminalCloseOut{}, e
	}
	s.mu.Lock()
	delete(s.terms, in.TerminalID)
	s.mu.Unlock()
	closed, code := term.close()
	s.audit("MCP-TERMINAL-CLOSE", "machine", term.machine, "terminal", term.id,
		"closed", fmt.Sprintf("%t", closed), "code", fmt.Sprintf("%d", code))
	return textResult("终端 %s 已关闭", term.id), terminalCloseOut{Closed: true, ExitCode: code}, nil
}

func (s *Server) terminalList(_ context.Context, _ *mcp.CallToolRequest, _ terminalListIn) (*mcp.CallToolResult, terminalListOut, error) {
	s.mu.Lock()
	all := make([]*terminalSession, 0, len(s.terms))
	for _, term := range s.terms {
		all = append(all, term)
	}
	s.mu.Unlock()
	terms := all[:0]
	for _, term := range all {
		if !s.machineBlocked(term.machine) {
			terms = append(terms, term)
		}
	}
	sort.Slice(terms, func(i, j int) bool { return terms[i].id < terms[j].id })
	out := terminalListOut{}
	var tb strings.Builder
	tb.WriteString("本会话打开的终端：\n")
	for _, term := range terms {
		term.mu.Lock()
		closed, code := term.closed, term.exitCode
		cols, rows := term.cols, term.rows
		idle := time.Since(term.lastUse)
		term.mu.Unlock()
		out.Terminals = append(out.Terminals, terminalInfo{
			TerminalID: term.id, Machine: term.machine,
			Cols: cols, Rows: rows, Closed: closed, ExitCode: code, IdleSeconds: int64(idle / time.Second),
		})
		fmt.Fprintf(&tb, "- %s：%s %dx%d closed=%t exit_code=%d idle=%s\n",
			term.id, term.machine, cols, rows, closed, code, idle.Round(time.Second))
	}
	if len(terms) == 0 {
		tb.WriteString("（无）\n")
	}
	return textResult("%s", tb.String()), out, nil
}
