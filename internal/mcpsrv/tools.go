package mcpsrv

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/towstrap/towstrap/internal/version"
)

// Server 把一份配置变成一个 MCP server：工具、策略过滤、人工批准。
// remembered 按客户端会话记「相同命令不再问」；shells/terms 是本客户端会话
// 开的常驻进程，客户端会话结束全回收。
type Server struct {
	cfg    *Config
	pol    *Policy
	runner Runner

	mu         sync.Mutex
	remembered map[string]map[string]string  // sessionID -> machine\x00detail -> 当初的授权编号
	pending    map[string]map[string]pendAsk // sessionID -> machine\x00detail -> 已发起未答复的确认
	watching   map[string]bool               // 已挂上会话清理的 sessionID
	shells     map[string]*shellSession      // machine\x00名字 -> 常驻 shell
	terms      map[string]*terminalSession   // terminal_id -> PTY 终端
	dialects   map[string]shellDialect
	reapStop   chan struct{} // 非空 = 回收器在跑
}

// New 建 Server：编译策略，runner 是命令执行后端（stdio 模式传 *Pool，
// 服务器内嵌模式传走 Hub 的实现）。
func New(cfg *Config, runner Runner) (*Server, error) {
	pol, err := newPolicy(&cfg.Policy)
	if err != nil {
		return nil, err
	}
	if cfg.ApproveCmd == "" {
		cfg.ApproveCmd = "towstrap-mcp approve"
		if cfg.ApprovalsDir != "" {
			// 带上目录：显示的命令粘到终端就能用，裸 approve 在自定义
			// 目录下会找不到待批文件。
			cfg.ApproveCmd += " --approvals-dir " + cfg.ApprovalsDir
		}
	}
	return &Server{cfg: cfg, pol: pol, runner: runner,
		remembered: make(map[string]map[string]string), pending: make(map[string]map[string]pendAsk),
		watching: make(map[string]bool),
		shells:   make(map[string]*shellSession), terms: make(map[string]*terminalSession),
		dialects: make(map[string]shellDialect)}, nil
}

// Close 释放执行后端（实现方有关闭方法就调），顺手关掉所有常驻会话。
func (s *Server) Close() {
	s.closeSessions()
	if c, ok := s.runner.(interface{ Close() }); ok {
		c.Close()
	}
}

// audit 记一条 MCP 侧审计；配置没给 Audit 回调就落 slog（stderr）。
func (s *Server) audit(event string, kv ...string) {
	if s.cfg.Audit != nil {
		s.cfg.Audit(event, kv...)
		return
	}
	args := make([]any, 0, len(kv)+1)
	args = append(args, "event", event)
	for _, v := range kv {
		args = append(args, v)
	}
	slog.Info("mcp", args...)
}

// machineAllowed 让执行后端对机器授权做实时复核；stdio Pool 不实现，
// 静态 mcp.yaml 清单就是边界。
func (s *Server) machineAllowed(machine string) bool {
	if checker, ok := s.runner.(MachineChecker); ok {
		return checker.MachineAllowed(machine)
	}
	return true
}

// machineBlocked 在授权已撤掉时顺带清掉这台机器留下的常驻进程：
// 不能只挡住下一次调用而让旧 PTY/shell 继续跑着。
func (s *Server) machineBlocked(machine string) bool {
	if s.machineAllowed(machine) {
		return false
	}
	s.revokeMachineSessions(machine)
	return true
}

func (s *Server) revokeMachineSessions(machine string) {
	s.mu.Lock()
	prefix := machine + "\x00"
	for key, sh := range s.shells {
		if strings.HasPrefix(key, prefix) {
			sh.kill()
			delete(s.shells, key)
		}
	}
	for id, term := range s.terms {
		if term.machine == machine {
			_, _ = term.close()
			delete(s.terms, id)
		}
	}
	s.mu.Unlock()
}

// watchSession 在客户端会话结束时清掉它的 remembered 名单和常驻进程。
// 这些资源挂在 mcpsrv.Server 上；服务器内嵌模式下 Server 跟着 MCP 会话
// 走，会话一断远端进程就没主了，必须当场回收。每个会话只挂一次。
func (s *Server) watchSession(ss *mcp.ServerSession) {
	if ss == nil {
		return // 单测等无真实会话的场景
	}
	s.mu.Lock()
	if s.watching[ss.ID()] {
		s.mu.Unlock()
		return
	}
	s.watching[ss.ID()] = true
	s.mu.Unlock()
	go func() {
		_ = ss.Wait()
		s.mu.Lock()
		delete(s.remembered, ss.ID())
		delete(s.pending, ss.ID())
		delete(s.watching, ss.ID())
		s.mu.Unlock()
		s.closeSessions()
	}()
}

// shellFor 取/建一个常驻 shell。created 表示这次调用新开了 shell
// （cwd 只在此时生效）；restarted 表示同名的旧 shell 死了刚换新——
// 之前会话里的 cd/环境变量等状态已丢，要提示给 LLM。OpenShell 可能
// 阻塞几秒，但同一客户端会话内并发建同名 shell 必须互斥，所以在
// s.mu 里做。
func (s *Server) shellFor(ctx context.Context, machine, name string) (sh *shellSession, created, restarted bool, err error) {
	opener, ok := s.runner.(ShellOpener)
	if !ok {
		return nil, false, false, fmt.Errorf("当前执行后端不支持常驻会话（stdio 模式需较新版本 towstrap-mcp）")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := machine + "\x00" + name
	if old := s.shells[key]; old != nil {
		if old.alive() {
			return old, false, false, nil
		}
		old.kill()
		delete(s.shells, key)
		restarted = true
	}
	if len(s.shells)+len(s.terms) >= s.cfg.Limits.MaxSessions {
		return nil, false, false, fmt.Errorf("常驻会话数达到上限（%d）——exit/close 掉不用的会话，或等它们空闲回收", s.cfg.Limits.MaxSessions)
	}
	raw, err := opener.OpenShell(ctx, machine)
	if err != nil {
		return nil, false, false, err
	}
	sh = newShellSession(raw, name)
	sh.start()
	s.shells[key] = sh
	s.ensureReaper()
	return sh, true, restarted, nil
}

// openTerminal 新开一个 PTY 终端。终端 ID 只在本 Server（也就是本 MCP
// 客户端会话）里有效；打开过程和 shellFor 一样占锁，保证并发下不会
// 突破 max_sessions。authID 非空说明这个终端是批了才开的，输出要
// 全程落盘做授权会话记录。
func (s *Server) openTerminal(ctx context.Context, machine string, opts TerminalOptions, authID string) (*terminalSession, error) {
	opener, ok := s.runner.(TerminalOpener)
	if !ok {
		return nil, fmt.Errorf("当前执行后端不支持 PTY 终端")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.shells)+len(s.terms) >= s.cfg.Limits.MaxSessions {
		return nil, fmt.Errorf("常驻会话数达到上限（%d）——terminal_close 掉不用的终端，或等它们空闲回收", s.cfg.Limits.MaxSessions)
	}
	raw, err := opener.OpenTerminal(ctx, machine, opts)
	if err != nil {
		return nil, err
	}
	id := newTerminalID()
	for s.terms[id] != nil {
		id = newTerminalID()
	}
	var term *terminalSession // 闭包要引用自己，先声明再赋值
	term = newTerminalSession(id, machine, raw, opts.Cols, opts.Rows, func(code int) {
		kv := []string{"machine", machine, "terminal", id, "code", fmt.Sprintf("%d", code)}
		if term.authID != "" {
			kv = append(kv, "auth", term.authID, "exec", term.execID, "record", term.recPath)
		}
		s.audit("MCP-TERMINAL-END", kv...)
	})
	term.authID = authID
	if authID != "" {
		// 授权过的 PTY 会话输出全程落盘：先写头再开泵，不漏开头。
		term.execID = newExecID()
		term.recPath = s.openTermRecord(term, opts)
	}
	s.terms[id] = term
	term.start()
	s.ensureReaper()
	return term, nil
}

func (s *Server) terminalFor(id string) (*terminalSession, error) {
	s.mu.Lock()
	term := s.terms[id]
	s.mu.Unlock()
	if term == nil || s.machineBlocked(term.machine) {
		return nil, fmt.Errorf("终端 %q 不存在、已关闭，或当前凭据无权访问", id)
	}
	return term, nil
}

// ensureReaper 懒起回收器：定期杀掉空闲超时的常驻进程。只在该
// Server 有了第一个常驻会话后才起。
func (s *Server) ensureReaper() {
	if s.reapStop != nil {
		return
	}
	s.reapStop = make(chan struct{})
	stop := s.reapStop // 捕获进局部变量：goroutine 不能裸读字段，否则和 closeShells 置 nil 撞车
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				s.sweepIdle()
			}
		}
	}()
}

// sweepIdle 扫一轮：空闲超过 session_idle 的常驻 shell/PTY 杀掉并从表里摘掉。
func (s *Server) sweepIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sh := range s.shells {
		if sh.idleFor() > s.cfg.Limits.SessionIdle {
			sh.kill()
			delete(s.shells, k)
		}
	}
	for id, term := range s.terms {
		if term.idleFor() > s.cfg.Limits.SessionIdle {
			_, _ = term.close()
			delete(s.terms, id)
		}
	}
}

// closeSessions 关掉所有常驻 shell/PTY、停掉回收器。幂等。
func (s *Server) closeSessions() {
	s.mu.Lock()
	if s.reapStop != nil {
		close(s.reapStop)
		s.reapStop = nil
	}
	for k, sh := range s.shells {
		sh.kill()
		delete(s.shells, k)
	}
	for id, term := range s.terms {
		_, _ = term.close()
		delete(s.terms, id)
	}
	s.mu.Unlock()
}

// instructions 是发给 LLM 的「使用须知」，每次握手随 initialize 结果下发。
const instructions = `你通过 towstrap 在真实的远程机器上执行命令。这些机器属于用户，命令以那台机器上 agent 的系统用户身份真实执行，后果不可撤销——把每一条命令都当成在用户的电脑上敲回车。

规则：
1. 不带 session 的 run_command 每次都是新起的 shell：cd、环境变量不会保留到下一次，用 cwd 参数指定工作目录。带 session 参数（如 session: "work"）则进一个常驻 shell：cd、export、source 激活的环境、后台任务都会保留到同名会话的下一条命令——像本地终端一样用即可。
2. 命令先过策略再执行：deny 名单里的直接拒绝；ask 名单里的（删文件、提权、杀进程、git push 等危险操作）要经批准后才执行——批准方式见文末「ask 命中的批准方式」：客户端弹确认框，或由管理员在终端/本机对话框批准；仅当写明走会话内确认时，才把命令和风险转告用户、得到明确同意后带 confirmed=true 重试（没问过用户不要设 confirmed）。等待批准时调用会挂起——把正在等批准的情况告诉用户即可，不要反复重试。allow 名单里的只读/低风险命令自动放行；其余按默认策略（run 直接执行 / ask 需批准 / deny 拒绝）。被拒绝或超时时，向用户说明你想执行什么、为什么，由用户决定；不要改写命令绕过策略。
3. 改文件优先用 write_file（在允许目录内自动放行，用绝对路径或 ~/ 开头），读文件用 read_file；大输出会被截断（标记里有省略字节数），必要时用 head/tail/grep 缩小范围。
4. 破坏性操作（删除、覆盖、git push --force、reset --hard、改系统配置）即便策略放行，也先向用户确认。
5. run_command 的 exit_code 才是成败依据，不要只看 stdout。
6. session 模式的边界：不支持 stdin；命令超时或会话终结会杀掉整个进程组（shell 和它的前台命令、& 后台任务一起清）——想在会话结束后留一个常驻服务，用 setsid 起（如 setsid npm run dev >/tmp/dev.log 2>&1 &）；exit/exec 会终结会话，下一条同名命令自动开新 shell。会话空闲超时会被回收。
7. 需要真实终端的 TUI/交互程序（pi、vim、top、ssh、bash -l 等）用 terminal_open 开 PTY；之后 terminal_write 发原始按键、terminal_read 读合并输出、terminal_resize 改窗口、terminal_close 关闭。不要把这类程序放进 run_command/session 里等它退出。终端也受 session_idle 和 max_sessions 限制，用完要 terminal_close。
机器列表和说明见 list_machines。`

// MCP 建出挂了工具的 *mcp.Server。Instructions 在固定须知后面
// 动态拼上机器列表和策略概况。
func (s *Server) MCP() *mcp.Server {
	var names []string
	for name := range s.cfg.Machines {
		names = append(names, name)
	}
	sort.Strings(names)
	var mb strings.Builder
	for _, n := range names {
		m := s.cfg.Machines[n]
		fmt.Fprintf(&mb, "\n- %s：%s", n, m.Description)
	}
	var approveHow string
	switch s.cfg.Policy.AskVia {
	case "local":
		approveHow = "调用会挂起等人工批准——管理员在终端运行 " + s.cfg.ApproveCmd + " 或点本机弹出的对话框；告诉用户正在等批准即可"
	case "llm":
		approveHow = "在会话里由你向用户确认后带 confirmed=true 重试"
	default:
		approveHow = "客户端支持弹窗就弹窗；不支持时调用会挂起等人工批准（管理员运行 " + s.cfg.ApproveCmd + " 或点本机对话框）——告诉用户正在等批准即可，confirmed=true 在这条路径下无效"
	}
	inst := fmt.Sprintf(instructions+"\n\n机器列表：%s\n\n策略：默认 %s；allow 名单 %d 条、deny 名单 %d 条、ask 名单 %d 条；ask 命中的批准方式：%s。",
		mb.String(), s.cfg.Policy.Default,
		len(s.pol.allow), len(s.pol.deny), len(s.pol.ask), approveHow)

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "towstrap-mcp",
		Version: version.String(),
	}, &mcp.ServerOptions{Instructions: inst})
	s.addTools(srv)
	return srv
}

// ---- 工具入参/出参。jsonschema tag 是给 LLM 看的字段说明，要写清。 ----

type listIn struct{}

type machineInfo struct {
	Name        string   `json:"name" jsonschema:"机器名（towstrap 账号名）"`
	Description string   `json:"description" jsonschema:"用户给的机器说明"`
	Roots       []string `json:"roots" jsonschema:"write_file 自动放行的目录"`
	Connected   bool     `json:"connected" jsonschema:"这台机器当前是否在线（服务器模式）/已有 SSH 连接（stdio 模式）"`
}

type listOut struct {
	Machines []machineInfo `json:"machines"`
}

type runIn struct {
	Machine        string `json:"machine" jsonschema:"机器名，来自 list_machines"`
	Command        string `json:"command" jsonschema:"要在被控机上执行的 shell 命令（经 shell -c 解释，可用管道）"`
	Cwd            string `json:"cwd,omitempty" jsonschema:"工作目录；不带 session 时每次都是新 shell，不设就用 agent 的默认目录；带 session 时只在建会话时生效"`
	Session        string `json:"session,omitempty" jsonschema:"常驻 shell 会话名：同名会话共享一个远端 shell，cd/export/后台任务全部保留；不带则每条命令独立"`
	Stdin          string `json:"stdin,omitempty" jsonschema:"喂给命令标准输入的内容（session 模式不支持）"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"超时秒数，不写用配置默认，超上限会被夹到上限"`
	Confirmed      bool   `json:"confirmed,omitempty" jsonschema:"仅 llm 会话内确认路径生效：用户在对话中明确同意后，配合「需要用户确认」的报错原样重试；其它批准路径下此参数无效；没问过用户不要设"`
	Remember       bool   `json:"remember,omitempty" jsonschema:"随 confirmed 一起设（仅 llm 会话内确认路径生效）：用户说此类操作以后都允许时用"`
}

type runOut struct {
	ExitCode        int    `json:"exit_code" jsonschema:"命令退出码；timed_out 或没拿到退出码时为 -1"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	TimedOut        bool   `json:"timed_out" jsonschema:"true 表示因超时被 SIGKILL"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	DurationMs      int64  `json:"duration_ms"`
	Approval        string `json:"approval" jsonschema:"本次怎么过的批准：allowed 策略直接放行 / approved 用户本次批准 / remembered 命中记住的批准 / confirmed 用户在会话中同意 / open 机器姿态免批准"`
	Session         string `json:"session,omitempty" jsonschema:"本条命令用的常驻会话名（有的话）"`
	Restarted       bool   `json:"session_restarted,omitempty" jsonschema:"同名旧 shell 死了、刚换新 shell——之前会话里的 cd/环境变量等状态已丢失"`
}

type readIn struct {
	Machine string `json:"machine" jsonschema:"机器名"`
	Path    string `json:"path" jsonschema:"要读的文件路径，建议绝对路径或 ~/ 开头"`
}

type readOut struct {
	Content string `json:"content"`
	Bytes   int    `json:"bytes"`
}

type writeIn struct {
	Machine   string `json:"machine" jsonschema:"机器名"`
	Path      string `json:"path" jsonschema:"要写的文件路径，用绝对路径或 ~/ 开头；在机器 roots 里自动放行，否则要用户批准"`
	Content   string `json:"content" jsonschema:"要写入的完整内容（覆盖写）"`
	Confirmed bool   `json:"confirmed,omitempty" jsonschema:"仅 llm 会话内确认路径生效：用户在对话中明确同意后，配合「需要用户确认」的报错原样重试；其它批准路径下此参数无效；没问过用户不要设"`
	Remember  bool   `json:"remember,omitempty" jsonschema:"随 confirmed 一起设（仅 llm 会话内确认路径生效）：用户说此类操作以后都允许时用"`
}

type writeOut struct {
	BytesWritten int `json:"bytes_written"`
}

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

func (s *Server) addTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "list_machines",
		Description: "列出配置里的被控机：名字（当 machine 参数用）、说明、" +
			"write_file 自动放行的目录、当前连接状态。不含任何凭据。",
	}, s.listMachines)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "run_command",
		Description: "在被控机上执行一条 shell 命令。每次都是新起的 shell：" +
			"cd、环境变量不会带到下一次，工作目录用 cwd 参数。命令先过策略：" +
			"deny 名单直接拒绝，allow 名单（只读/低风险）自动放行，其余要用户" +
			"批准（弹确认框或终端 " + s.cfg.ApproveCmd + "）。成败看 exit_code，" +
			"stdout/stderr 分开返回，超过上限各截断并标记省略字节数；" +
			"timed_out 为 true 表示命令被超时杀掉。",
	}, s.runCommand)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "read_file",
		Description: "读被控机上的文本文件。受 deny_paths 限制（私钥、凭证、" +
			"agent 自己的配置读不了），超过 max_file 或含 NUL 会报错。" +
			"读文件不需要批准。",
	}, s.readFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "write_file",
		Description: "把内容完整写入被控机上的文件（覆盖写）。路径用绝对路径" +
			"或 ~/ 开头：在机器的 roots 目录里自动放行，之外要用户批准；" +
			"deny_paths 命中的直接拒绝。content 不能超过 max_file。",
	}, s.writeFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "terminal_open",
		Description: "在被控机上开一个真实 PTY 终端并执行 command。适合 pi、vim、top、" +
			"ssh、bash -l 这类需要终端的交互程序；返回 terminal_id，之后用 " +
			"terminal_write 发按键、terminal_read 读输出、terminal_resize 改窗口、" +
			"terminal_close 关闭。command 和 run_command 一样过策略和批准。" +
			"终端跟着本 MCP 会话走，关闭或会话结束即终止。",
	}, s.terminalOpen)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "terminal_write",
		Description: "向已打开的 PTY 终端写原始输入。input 是终端字节流：" +
			"普通文本、回车 \\r/\\n、Ctrl 组合键（如 \\u0003）和方向键 ANSI 序列都可以。",
	}, s.terminalWrite)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "terminal_read",
		Description: "读取 PTY 终端输出。PTY 输出是 stdout/stderr 合并后的终端流，" +
			"可能包含 ANSI 清屏、移动光标等控制序列；timeout_seconds 用来等新输出，" +
			"closed/exit_code 表示远端进程是否已结束。",
	}, s.terminalRead)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "terminal_resize",
		Description: "修改 PTY 终端窗口大小；TUI 程序会收到 SIGWINCH 并按新尺寸重绘。",
	}, s.terminalResize)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "terminal_close",
		Description: "关闭 PTY 终端并终止远端进程。",
	}, s.terminalClose)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "terminal_list",
		Description: "列出本 MCP 会话当前打开的 PTY 终端及状态。",
	}, s.terminalList)
}

// errResult 工具执行失败统一走这里：IsError + 文字说明。不返回 Go error——
// 那会变成协议级错误，LLM 看不到原因。
func errResult(format string, args ...any) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}},
	}, nil
}

func textResult(format string, args ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}},
	}
}

func (s *Server) listMachines(_ context.Context, _ *mcp.CallToolRequest, _ listIn) (*mcp.CallToolResult, listOut, error) {
	var names []string
	for name := range s.cfg.Machines {
		names = append(names, name)
	}
	sort.Strings(names)
	out := listOut{}
	var tb strings.Builder
	for _, n := range names {
		if s.machineBlocked(n) {
			continue
		}
		m := s.cfg.Machines[n]
		out.Machines = append(out.Machines, machineInfo{
			Name: n, Description: m.Description, Roots: m.Roots,
			Connected: s.runner.Connected(n),
		})
		fmt.Fprintf(&tb, "- %s：%s（roots: %s）\n", n, m.Description, strings.Join(m.Roots, ", "))
	}
	return textResult("可用机器：\n%s", tb.String()), out, nil
}

// tellClient 把「要在哪台机器上跑什么命令」推成一条 MCP 日志消息：
// 每条实际执行的命令都出现在客户端会话窗口，不靠客户端渲染工具参数。
// 客户端不支持/不显示 logging 时 Log 返回错，吞掉即可——审计日志是保底。
func tellClient(ctx context.Context, req *mcp.CallToolRequest, machine, command string) {
	if req == nil || req.Session == nil {
		return
	}
	_ = req.Session.Log(ctx, &mcp.LoggingMessageParams{
		Level:  "notice",
		Logger: "towstrap",
		Data:   fmt.Sprintf("在 %s 执行命令：%s", machine, command),
	})
}

// resolveMachine 把客户端给的机器名解析成 cfg.Machines 里的规范键
// （账号+机器）：demo/local 归一成 demo+local；不带分隔符的裸机器名在
// 可见机器里找唯一同名的，重名/找不到返回原样走后面的报错路径。
func (s *Server) resolveMachine(name string) string {
	want := strings.Replace(name, "/", "+", 1)
	if _, ok := s.cfg.Machines[want]; ok {
		return want
	}
	if strings.ContainsRune(want, '+') {
		return name
	}
	hit := ""
	for id := range s.cfg.Machines {
		if i := strings.IndexByte(id, '+'); i >= 0 && id[i+1:] == want {
			if hit != "" {
				return name // 多义：两个账号都有这台机器名
			}
			hit = id
		}
	}
	if hit != "" {
		return hit
	}
	return name
}

// llmConfirmResult 是「会话内确认」的指引报错——这条消息本身就是给 LLM
// 的操作说明：把操作转告用户、要到明确同意后带 confirmed=true 重试。
func llmConfirmResult(ar ApprovalRequest) *mcp.CallToolResult {
	what := "命令"
	if ar.Kind != "command" {
		what = "操作"
	}
	r, _ := errResult("这个%s命中了需要用户确认的策略，刚才没有执行。请把内容转告用户、说明风险、询问是否允许：\n\n机器：%s\n%s：%s\n\n用户明确同意后，用相同参数重新调用本工具并加 confirmed=true；用户说此类操作以后都允许时再加 remember=true。没问到同意就不要设 confirmed=true。确认请求 %d 分钟内有效。",
		what, ar.Machine, what, ar.Detail, int(llmConfirmTTL/time.Minute))
	return r
}

// authRecordDir 是授权会话记录的存放目录：批准目录旁的 auth-records/
// （默认就在审计日志目录边上，跟着审计走）。目录为空表示没配，退化为
// 只在审计事件里记截断的尾部输出。
func (s *Server) authRecordDir() string {
	if s.cfg.ApprovalsDir == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.cfg.ApprovalsDir), "auth-records")
}

// newExecID 生成执行编号：一次授权可能放行多条执行（remembered 的复用），
// 每条执行一个编号，记录文件名按它唯一。
func newExecID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "ex-" + hex.EncodeToString(b)
}

// recordAuthExec 给授权过的执行留档：申请的命令 + 实际结果（退出码、
// 时长、输出全文）写进 auth-records/<execID>.log，审计事件用
// auth=<批准编号> exec=<执行编号> record=<路径> 把三者串起来。
// 写盘失败不退让——审计事件带上截断的尾部输出兜底。
func (s *Server) recordAuthExec(authID, machine, kind, command, cwd, session string, res Result) {
	execID := newExecID()
	var b strings.Builder
	fmt.Fprintf(&b, "# towstrap 授权会话记录\nauth: %s\nexec: %s\ntime: %s\nmachine: %s\nkind: %s\ncommand: %s\ncwd: %s\nsession: %s\n---\nexit_code: %d\ntimed_out: %t\nduration_ms: %d\nstdout_truncated: %t\nstderr_truncated: %t\n--- stdout ---\n%s\n--- stderr ---\n%s\n",
		authID, execID, time.Now().Format(time.RFC3339Nano), machine, kind,
		command, orDash(cwd), orDash(session),
		res.ExitCode, res.TimedOut, res.Duration.Milliseconds(),
		res.StdoutTruncated, res.StderrTruncated, res.Stdout, res.Stderr)
	recPath := ""
	if dir := s.authRecordDir(); dir != "" {
		if err := os.MkdirAll(dir, 0700); err == nil {
			p := filepath.Join(dir, execID+".log")
			if err := os.WriteFile(p, []byte(b.String()), 0600); err == nil {
				recPath = p
			}
		}
	}
	kv := []string{"auth", authID, "exec", execID, "machine", machine, "kind", kind,
		"cmd", command, "exit_code", fmt.Sprintf("%d", res.ExitCode),
		"duration_ms", fmt.Sprintf("%d", res.Duration.Milliseconds())}
	if recPath != "" {
		kv = append(kv, "record", recPath)
	} else {
		// 没落盘成文件就把尾部输出塞进审计事件，保证记录不断链
		kv = append(kv, "stdout_tail", tail(res.Stdout, 1024), "stderr_tail", tail(res.Stderr, 1024))
	}
	s.audit("MCP-AUTH-EXEC", kv...)
}

// tail 取字符串末尾 n 字节（截断发生在前面，保留最近的输出）。
func tail(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// authRecordMaxBytes 是单个授权会话记录文件的体积上限：PTY 输出没底，
// 超过就停笔并在文件里留说明。
const authRecordMaxBytes = 4 << 20

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

// machineOpen 这台机器声明了免批准姿态（policy: open——agent hello
// 自报或机器 yaml 里写）。deny 名单不受影响，只跳过 ask 环节。
func (s *Server) machineOpen(machine string) bool {
	m := s.cfg.Machines[machine]
	return m != nil && m.Policy == "open"
}

// authorizeCommand 走命令策略和人工批准。返回 early != nil 时调用方直接
// 把这个结果交回（拒绝、弹窗请求、会话内确认指引或批准环节失败）；否则
// 返回 approval 标记和授权编号（authID 非空 = 这条命令是批了才跑的，
// 调用方要给它留执行记录）。
func (s *Server) authorizeCommand(ctx context.Context, req *mcp.CallToolRequest, machine, command, cwd string, confirmed, remember bool) (approval, authID string, early *mcp.CallToolResult) {
	dec, reason := s.pol.Command(command)
	if dec == Deny {
		s.audit("MCP-POLICY-DENY", "machine", machine, "kind", "command", "detail", command, "reason", reason)
		r, _ := errResult("策略拒绝：%s。不要改写命令绕过；如确有必要，请向用户说明并由用户调整策略。", reason)
		return "", "", r
	}
	if dec == Ask && s.machineOpen(machine) {
		// 机器姿态 open：部署者声明这台免批准。记一条和 MCP-POLICY-DENY
		// 对仗的事件，事后能看清是姿态放行的、不是真人批的。
		s.audit("MCP-POLICY-OPEN", "machine", machine, "kind", "command", "detail", command)
		tellClient(ctx, req, machine, command)
		return "open", "", nil
	}
	if dec != Ask {
		tellClient(ctx, req, machine, command)
		return "allowed", "", nil
	}
	ar := ApprovalRequest{Machine: machine, Kind: "command", Detail: command, Cwd: cwd}
	out, askAgain, authID, err := s.approve(ctx, req, ar, confirmed, remember)
	if askAgain {
		return "", "", elicitRequest(ar)
	}
	if out == AwaitingLLM {
		return "", "", llmConfirmResult(ar)
	}
	if err != nil && out != Timeout {
		r, _ := errResult("批准环节出错：%v", err)
		return "", "", r
	}
	switch out {
	case Approved:
		tellClient(ctx, req, machine, command)
		return "approved", authID, nil
	case ApprovedRemember:
		tellClient(ctx, req, machine, command)
		return "remembered", authID, nil
	case ApprovedLLM:
		tellClient(ctx, req, machine, command)
		return "confirmed", authID, nil
	case DeniedByUser:
		r, _ := errResult("用户拒绝了这条命令。请向用户说明你想执行什么、为什么，由用户决定；也可以请用户把它加进 policy.allow 名单。")
		return "", "", r
	case Timeout:
		r, _ := errResult("等待批准超时（%s）：用户在弹窗里没表态，也没在终端跑 %s。请向用户说明情况再决定是否重试。", humanDur(s.cfg.Policy.AskTimeout), s.cfg.ApproveCmd)
		return "", "", r
	default:
		r, _ := errResult("批准环节不可用：%v", err)
		return "", "", r
	}
}

func (s *Server) runCommand(ctx context.Context, req *mcp.CallToolRequest, in runIn) (*mcp.CallToolResult, runOut, error) {
	in.Machine = s.resolveMachine(in.Machine)
	if _, ok := s.cfg.Machines[in.Machine]; !ok || s.machineBlocked(in.Machine) {
		r, e := errResult("机器 %q 不在配置里或当前凭据无权访问，先用 list_machines 看有哪些", in.Machine)
		return r, runOut{}, e
	}

	timeout := s.cfg.Limits.Timeout
	clamped := false
	if in.TimeoutSeconds > 0 {
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
		if timeout > s.cfg.Limits.MaxTimeout {
			timeout = s.cfg.Limits.MaxTimeout
			clamped = true
		}
	}

	s.watchSession(req.Session)
	approval, authID, early := s.authorizeCommand(ctx, req, in.Machine, in.Command, in.Cwd, in.Confirmed, in.Remember)
	if early != nil {
		return early, runOut{}, nil
	}

	if in.Session != "" {
		return s.runInSession(ctx, req, in, timeout, approval, authID)
	}

	var res Result
	var err error
	win := false
	if in.Cwd != "" {
		d, derr := s.dialect(ctx, in.Machine)
		if derr != nil {
			r, e := errResult("%v", derr)
			return r, runOut{}, e
		}
		win = d.windows()
	}
	if in.Cwd != "" && win {
		wr, ok := s.runner.(WorkingDirectoryRunner)
		if !ok {
			r, e := errResult("这台是 Windows 机器，cwd 需要执行后端支持工作目录传递（当前后端不支持）")
			return r, runOut{}, e
		}
		res, err = wr.RunAt(ctx, in.Machine, in.Command, []byte(in.Stdin), timeout, s.cfg.Limits.MaxOutput, in.Cwd)
	} else {
		cmd := in.Command
		if in.Cwd != "" {
			cmd = fmt.Sprintf("cd -- %s && (\n%s\n)", shellPathExpr(in.Cwd), in.Command)
		}
		res, err = s.runner.Run(ctx, in.Machine, cmd, []byte(in.Stdin), timeout, s.cfg.Limits.MaxOutput)
	}
	if err != nil {
		r, e := errResult("执行失败：%v", err)
		return r, runOut{}, e
	}
	if authID != "" {
		s.recordAuthExec(authID, in.Machine, "exec", in.Command, in.Cwd, "", res)
	}
	out := runOut{
		ExitCode:        res.ExitCode,
		Stdout:          res.Stdout,
		Stderr:          res.Stderr,
		TimedOut:        res.TimedOut,
		StdoutTruncated: res.StdoutTruncated,
		StderrTruncated: res.StderrTruncated,
		DurationMs:      res.Duration.Milliseconds(),
		Approval:        approval,
	}
	text := fmt.Sprintf("exit_code=%d timed_out=%t duration=%dms approval=%s\n--- stdout ---\n%s\n--- stderr ---\n%s",
		res.ExitCode, res.TimedOut, res.Duration.Milliseconds(), approval, res.Stdout, res.Stderr)
	if clamped {
		text += fmt.Sprintf("\n（timeout_seconds 超过上限，已夹到 %s）", s.cfg.Limits.MaxTimeout)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

// runInSession 走常驻 shell 路径：取/建同名 shell，把命令写进去，靠
// 双哨兵收结果。cwd 只在建会话时生效（之后想换目录直接在命令里 cd）。
// authID 非空说明这条命令是批了才跑的，结果要留授权会话记录。
func (s *Server) runInSession(ctx context.Context, req *mcp.CallToolRequest, in runIn, timeout time.Duration, approval, authID string) (*mcp.CallToolResult, runOut, error) {
	if !sessNameRe.MatchString(in.Session) {
		r, e := errResult("session 名不合法：只能用字母、数字、点、下划线、短横线，最长 64")
		return r, runOut{}, e
	}
	if in.Stdin != "" {
		r, e := errResult("session 模式不支持 stdin 参数（常驻 shell 的 stdin 是持续打开的，没法半关）")
		return r, runOut{}, e
	}
	d, err := s.dialect(ctx, in.Machine)
	if err != nil {
		r, e := errResult("%v", err)
		return r, runOut{}, e
	}
	if d.windows() {
		r, e := errResult("Windows 机器不支持常驻 shell 会话（session 参数），请去掉 session 用普通 run_command")
		return r, runOut{}, e
	}
	s.watchSession(req.Session) // 挂上会话结束清理；批准路径里已挂也没关系

	// 命令先封进单引号字面量，再交给 shell：
	//   - 策略是按朴素切段判的，不引号的话 `echo hi && <回车> rm -rf /`
	//     会被当成一条 echo 放行，第二行照样在常驻 shell 里执行
	//   - 更糟的是拒绝/超时时 shell 会把没跑完的行一直攒着，等下一条
	//     已批准的命令把它凑齐——等于用户拒绝了也照样被执行
	// 引号里换行被吃掉、历史展开（!）和 glob 都不生效，引号是唯一边界。
	sh, created, restarted, err := s.shellFor(ctx, in.Machine, in.Session)
	if err != nil {
		r, e := errResult("开会话失败：%v", err)
		return r, runOut{}, e
	}
	// cwd 只在建会话时生效。放在 shellFor 之后是因为只有它才知道这次
	// 是不是新开的；已存在的会话传 cwd 是调用方的错，到这里就返回，
	// 一条字节都不往那个 shell 里写。
	if in.Cwd != "" && !created {
		r, e := errResult("会话 %q 已存在，cwd 只在建会话时生效；换目录直接在命令里 cd", in.Session)
		return r, runOut{}, e
	}
	cmd := "eval " + shellQuote(in.Command)
	if in.Cwd != "" {
		cmd = fmt.Sprintf("cd -- %s && %s", shellPathExpr(in.Cwd), cmd)
	}
	kv := []string{"machine", in.Machine, "session", in.Session, "cmd", in.Command}
	if authID != "" {
		kv = append(kv, "auth", authID)
	}
	s.audit("MCP-SESSION-CMD", kv...)

	res, err := sh.exec(ctx, cmd, timeout, s.cfg.Limits.MaxOutput)
	if err == errShellDead {
		if authID != "" {
			// 批了开跑但 shell 中断：半截输出也要留档，退出码记 -1
			res.ExitCode = -1
			s.recordAuthExec(authID, in.Machine, "session", in.Command, in.Cwd, in.Session, res)
		}
		// 死掉的 shell 留在 shells 表里：下一条同名命令走到这就能
		// 告诉 LLM「换了新 shell、状态丢了」；没人再用就由空闲回收。
		r, e := errResult("shell 会话中断（命令里的 exit/exec、进程被杀或连接断开）——这条命令没跑完；同名 session 下一条命令会起新 shell，之前的状态已丢\n--- 中断前的输出 ---\n%s%s", res.Stdout, res.Stderr)
		return r, runOut{}, e
	}
	if err != nil {
		r, e := errResult("执行失败：%v", err)
		return r, runOut{}, e
	}
	if authID != "" {
		s.recordAuthExec(authID, in.Machine, "session", in.Command, in.Cwd, in.Session, res)
	}
	out := runOut{
		ExitCode:        res.ExitCode,
		Stdout:          res.Stdout,
		Stderr:          res.Stderr,
		TimedOut:        res.TimedOut,
		StdoutTruncated: res.StdoutTruncated,
		StderrTruncated: res.StderrTruncated,
		DurationMs:      res.Duration.Milliseconds(),
		Approval:        approval,
		Session:         in.Session,
		Restarted:       restarted,
	}
	text := fmt.Sprintf("exit_code=%d timed_out=%t duration=%dms approval=%s session=%s\n--- stdout ---\n%s\n--- stderr ---\n%s",
		res.ExitCode, res.TimedOut, res.Duration.Milliseconds(), approval, in.Session, res.Stdout, res.Stderr)
	if restarted {
		text += "\n（同名旧 shell 已退出，这是新会话——之前的状态不保留）"
	}
	if res.TimedOut {
		text += "\n（超时被杀的是整个会话 shell，这个 session 已结束）"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

func (s *Server) readFile(ctx context.Context, _ *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, readOut, error) {
	in.Machine = s.resolveMachine(in.Machine)
	m, ok := s.cfg.Machines[in.Machine]
	if !ok || s.machineBlocked(in.Machine) {
		r, e := errResult("机器 %q 不在配置里或当前凭据无权访问", in.Machine)
		return r, readOut{}, e
	}
	d, err := s.dialect(ctx, in.Machine)
	if err != nil {
		r, e := errResult("%v", err)
		return r, readOut{}, e
	}
	win := d.windows()
	if !s.pol.PathFor(in.Path, win) {
		s.audit("MCP-POLICY-DENY", "machine", in.Machine, "kind", "read_file", "detail", in.Path, "reason", "deny_paths")
		r, e := errResult("策略拒绝：路径 %q 命中 deny_paths（私钥、凭证、agent 配置这类文件不开放）。如确有必要，请向用户说明并由用户调整策略。", in.Path)
		return r, readOut{}, e
	}
	if m.ProtectedFor(in.Path, win) {
		s.audit("MCP-POLICY-DENY", "machine", in.Machine, "kind", "read_file", "detail", in.Path, "reason", "agent-protect")
		r, e := errResult("策略拒绝：%q 是这台机器 agent 自报的禁碰文件（token/配置文件），任何路径写法都不开放。", in.Path)
		return r, readOut{}, e
	}
	// 多读一个字节用来判断超限；head -c 对不存在的文件也会走 stderr 报错。
	var cmd string
	if win {
		cmd = psReadCommand(in.Path, s.cfg.Limits.MaxFile+1)
	} else {
		cmd = fmt.Sprintf("head -c %d -- %s", s.cfg.Limits.MaxFile+1, shellPathExpr(in.Path))
	}
	res, err := s.runner.Run(ctx, in.Machine, cmd, nil, s.cfg.Limits.Timeout, s.cfg.Limits.MaxFile+1024)
	if err != nil {
		r, e := errResult("执行失败：%v", err)
		return r, readOut{}, e
	}
	if res.ExitCode != 0 {
		r, e := errResult("读 %s 失败（exit_code=%d）：%s", in.Path, res.ExitCode, strings.TrimSpace(res.Stderr))
		return r, readOut{}, e
	}
	if len(res.Stdout) > s.cfg.Limits.MaxFile {
		r, e := errResult("文件 %s 超过上限 %d 字节，请用 run_command 的 head/tail/grep 读一部分", in.Path, s.cfg.Limits.MaxFile)
		return r, readOut{}, e
	}
	if strings.IndexByte(res.Stdout, 0) >= 0 {
		r, e := errResult("文件 %s 含 NUL 字节，是二进制文件，不支持读取", in.Path)
		return r, readOut{}, e
	}
	return textResult("%s", res.Stdout), readOut{Content: res.Stdout, Bytes: len(res.Stdout)}, nil
}

func (s *Server) writeFile(ctx context.Context, req *mcp.CallToolRequest, in writeIn) (*mcp.CallToolResult, writeOut, error) {
	in.Machine = s.resolveMachine(in.Machine)
	m, ok := s.cfg.Machines[in.Machine]
	if !ok || s.machineBlocked(in.Machine) {
		r, e := errResult("机器 %q 不在配置里或当前凭据无权访问", in.Machine)
		return r, writeOut{}, e
	}
	d, err := s.dialect(ctx, in.Machine)
	if err != nil {
		r, e := errResult("%v", err)
		return r, writeOut{}, e
	}
	win := d.windows()
	if !s.pol.PathFor(in.Path, win) {
		s.audit("MCP-POLICY-DENY", "machine", in.Machine, "kind", "write_file", "detail", in.Path, "reason", "deny_paths")
		r, e := errResult("策略拒绝：路径 %q 命中 deny_paths。如确有必要，请向用户说明并由用户调整策略。", in.Path)
		return r, writeOut{}, e
	}
	if m.ProtectedFor(in.Path, win) {
		s.audit("MCP-POLICY-DENY", "machine", in.Machine, "kind", "write_file", "detail", in.Path, "reason", "agent-protect")
		r, e := errResult("策略拒绝：%q 是这台机器 agent 自报的禁碰文件（token/配置文件），任何路径写法都不开放。", in.Path)
		return r, writeOut{}, e
	}
	if len(in.Content) > s.cfg.Limits.MaxFile {
		r, e := errResult("内容 %d 字节超过上限 %d", len(in.Content), s.cfg.Limits.MaxFile)
		return r, writeOut{}, e
	}
	var authID string // 非空 = 这次写是批了才落的，结尾要留授权会话记录
	if !m.InRootsFor(in.Path, win) && s.machineOpen(in.Machine) {
		s.audit("MCP-POLICY-OPEN", "machine", in.Machine, "kind", "write_file",
			"detail", fmt.Sprintf("写入 %s（%d 字节）", in.Path, len(in.Content)))
	} else if !m.InRootsFor(in.Path, win) {
		ar := ApprovalRequest{
			Machine: in.Machine, Kind: "write_file",
			Detail: fmt.Sprintf("写入 %s（%d 字节）", in.Path, len(in.Content)),
		}
		out, askAgain, aid, err := s.approve(ctx, req, ar, in.Confirmed, in.Remember)
		authID = aid
		if askAgain {
			return elicitRequest(ar), writeOut{}, nil
		}
		if out == AwaitingLLM {
			return llmConfirmResult(ar), writeOut{}, nil
		}
		if err != nil && out != Timeout {
			r, e := errResult("批准环节出错：%v", err)
			return r, writeOut{}, e
		}
		switch out {
		case Approved, ApprovedRemember, ApprovedLLM:
		case DeniedByUser:
			r, e := errResult("用户拒绝了写入 %s。请向用户说明目的，由用户决定；或把目录加进机器的 roots。", in.Path)
			return r, writeOut{}, e
		case Timeout:
			r, e := errResult("等待批准超时（%s）", humanDur(s.cfg.Policy.AskTimeout))
			return r, writeOut{}, e
		default:
			r, e := errResult("批准环节不可用：%v", err)
			return r, writeOut{}, e
		}
	}
	var cmd string
	if win {
		cmd = psWriteCommand(in.Path)
	} else {
		cmd = fmt.Sprintf("cat > %s", shellPathExpr(in.Path))
	}
	res, err := s.runner.Run(ctx, in.Machine,
		cmd, []byte(in.Content),
		s.cfg.Limits.Timeout, 4096)
	if err != nil {
		r, e := errResult("执行失败：%v", err)
		return r, writeOut{}, e
	}
	if authID != "" {
		// 授权写入留档：记路径、字节数、结果和内容指纹——不记全文
		// （内容可能很大），要核对原文去机器上找文件。
		sum := sha256.Sum256([]byte(in.Content))
		s.recordAuthExec(authID, in.Machine, "write_file",
			fmt.Sprintf("写入 %s（%d 字节，sha256=%x）", in.Path, len(in.Content), sum[:8]), "", "", res)
	}
	if res.ExitCode != 0 {
		r, e := errResult("写 %s 失败（exit_code=%d）：%s", in.Path, res.ExitCode, strings.TrimSpace(res.Stderr))
		return r, writeOut{}, e
	}
	return textResult("已写入 %s（%d 字节）", in.Path, len(in.Content)),
		writeOut{BytesWritten: len(in.Content)}, nil
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
	approval, authID, early := s.authorizeCommand(ctx, req, in.Machine, in.Command, in.Cwd, in.Confirmed, in.Remember)
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

// shellQuote 把一个字符串包成 shell 单引号字面量（内部 ' 变 '\”）。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellPathExpr(p string) string {
	if p == "~" {
		return `"$HOME"`
	}
	if strings.HasPrefix(p, "~/") {
		return `"$HOME/"` + shellQuote(p[2:])
	}
	return shellQuote(p)
}
