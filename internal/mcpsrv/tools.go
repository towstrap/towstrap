package mcpsrv

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/towstrap/towstrap/internal/version"
)

// Server 把一份配置变成一个 MCP server：四个工具、策略过滤、人工批准。
// remembered 按客户端会话记「相同命令不再问」。
type Server struct {
	cfg    *Config
	pol    *Policy
	runner Runner

	mu         sync.Mutex
	remembered map[string]map[string]bool // sessionID -> machine\x00detail
	watching   map[string]bool            // 已挂上会话清理的 sessionID
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
	}
	return &Server{cfg: cfg, pol: pol, runner: runner,
		remembered: make(map[string]map[string]bool), watching: make(map[string]bool)}, nil
}

// Close 释放执行后端（实现方有关闭方法就调）。
func (s *Server) Close() {
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

// watchSession 在客户端会话结束时清掉它的 remembered 名单，防止会话 ID
// 在 map 里无限累积。每个会话只挂一次。
func (s *Server) watchSession(ss *mcp.ServerSession) {
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
		delete(s.watching, ss.ID())
		s.mu.Unlock()
	}()
}

// instructions 是发给 LLM 的「使用须知」，每次握手随 initialize 结果下发。
// 里头的 %s 是批准命令（stdio 模式 towstrap-mcp approve，服务器模式
// towstrap-server mcp approve）。
const instructions = `你通过 towstrap 在真实的远程机器上执行命令。这些机器属于用户，命令以那台机器上 agent 的系统用户身份真实执行，后果不可撤销——把每一条命令都当成在用户的电脑上敲回车。

规则：
1. 每次 run_command 都是新起的 shell：cd、环境变量、shell 变量不会保留到下一次。用 cwd 参数指定工作目录，不要依赖上一条命令的 cd。
2. 命令先过策略再执行：deny 名单里的直接拒绝；allow 名单里的只读/低风险命令自动放行；其余需要用户批准（会弹确认框，或由用户运行 %s）。被拒绝或超时时，向用户说明你想执行什么、为什么，由用户决定；不要改写命令绕过策略。
3. 改文件优先用 write_file（在允许目录内自动放行，用绝对路径或 ~/ 开头），读文件用 read_file；大输出会被截断（标记里有省略字节数），必要时用 head/tail/grep 缩小范围。
4. 破坏性操作（删除、覆盖、git push --force、reset --hard、改系统配置）即便策略放行，也先向用户确认。
5. run_command 的 exit_code 才是成败依据，不要只看 stdout。
机器列表和说明见 list_machines。`

// MCP 建出挂了四个工具的 *mcp.Server。Instructions 在固定须知后面
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
	inst := fmt.Sprintf(instructions+"\n\n机器列表：%s\n\n策略：默认 %s；allow 名单 %d 条、deny 名单 %d 条；批准方式：弹窗或用户终端运行 %s。",
		s.cfg.ApproveCmd, mb.String(), s.cfg.Policy.Default,
		len(s.pol.allow), len(s.pol.deny), s.cfg.ApproveCmd)

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
	Cwd            string `json:"cwd,omitempty" jsonschema:"工作目录；每次都是新 shell，不设就用 agent 的默认目录"`
	Stdin          string `json:"stdin,omitempty" jsonschema:"喂给命令标准输入的内容"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"超时秒数，不写用配置默认，超上限会被夹到上限"`
}

type runOut struct {
	ExitCode        int    `json:"exit_code" jsonschema:"命令退出码；timed_out 或没拿到退出码时为 -1"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	TimedOut        bool   `json:"timed_out" jsonschema:"true 表示因超时被 SIGKILL"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	DurationMs      int64  `json:"duration_ms"`
	Approval        string `json:"approval" jsonschema:"本次怎么过的批准：allowed 策略直接放行 / approved 用户本次批准 / remembered 命中记住的批准"`
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
	Machine string `json:"machine" jsonschema:"机器名"`
	Path    string `json:"path" jsonschema:"要写的文件路径，用绝对路径或 ~/ 开头；在机器 roots 里自动放行，否则要用户批准"`
	Content string `json:"content" jsonschema:"要写入的完整内容（覆盖写）"`
}

type writeOut struct {
	BytesWritten int `json:"bytes_written"`
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
		m := s.cfg.Machines[n]
		out.Machines = append(out.Machines, machineInfo{
			Name: n, Description: m.Description, Roots: m.Roots,
			Connected: s.runner.Connected(n),
		})
		fmt.Fprintf(&tb, "- %s：%s（roots: %s）\n", n, m.Description, strings.Join(m.Roots, ", "))
	}
	return textResult("可用机器：\n%s", tb.String()), out, nil
}

func (s *Server) runCommand(ctx context.Context, req *mcp.CallToolRequest, in runIn) (*mcp.CallToolResult, runOut, error) {
	if _, ok := s.cfg.Machines[in.Machine]; !ok {
		r, e := errResult("机器 %q 不在配置里，先用 list_machines 看有哪些", in.Machine)
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

	approval := "allowed"
	dec, reason := s.pol.Command(in.Command)
	switch dec {
	case Deny:
		s.audit("MCP-POLICY-DENY", "machine", in.Machine, "kind", "command", "detail", in.Command, "reason", reason)
		r, e := errResult("策略拒绝：%s。不要改写命令绕过；如确有必要，请向用户说明并由用户调整策略。", reason)
		return r, runOut{}, e
	case Ask:
		ar := ApprovalRequest{Machine: in.Machine, Kind: "command", Detail: in.Command, Cwd: in.Cwd}
		out, askAgain, err := s.approve(ctx, req, ar)
		if askAgain {
			// 客户端支持弹窗：把 InputRequests 交出去，SDK 完成往返后
			// 会把这个 handler 再调一次（带着答复）。
			return elicitRequest(ar), runOut{}, nil
		}
		if err != nil && out != Timeout {
			r, e := errResult("批准环节出错：%v", err)
			return r, runOut{}, e
		}
		switch out {
		case Approved:
			approval = "approved"
		case ApprovedRemember:
			approval = "remembered"
		case DeniedByUser:
			r, e := errResult("用户拒绝了这条命令。请向用户说明你想执行什么、为什么，由用户决定；也可以请用户把它加进 policy.allow 名单。")
			return r, runOut{}, e
		case Timeout:
			r, e := errResult("等待批准超时（%s）：用户在弹窗里没表态，也没在终端跑 %s。请向用户说明情况再决定是否重试。", s.cfg.Policy.AskTimeout, s.cfg.ApproveCmd)
			return r, runOut{}, e
		default:
			r, e := errResult("批准环节不可用：%v", err)
			return r, runOut{}, e
		}
	}

	cmd := in.Command
	if in.Cwd != "" {
		cmd = fmt.Sprintf("cd -- %s && (\n%s\n)", shellQuote(in.Cwd), in.Command)
	}
	res, err := s.runner.Run(ctx, in.Machine, cmd, []byte(in.Stdin), timeout, s.cfg.Limits.MaxOutput)
	if err != nil {
		r, e := errResult("执行失败：%v", err)
		return r, runOut{}, e
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

func (s *Server) readFile(ctx context.Context, _ *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, readOut, error) {
	m, ok := s.cfg.Machines[in.Machine]
	if !ok {
		r, e := errResult("机器 %q 不在配置里", in.Machine)
		return r, readOut{}, e
	}
	if !s.pol.Path(in.Path) {
		s.audit("MCP-POLICY-DENY", "machine", in.Machine, "kind", "read_file", "detail", in.Path, "reason", "deny_paths")
		r, e := errResult("策略拒绝：路径 %q 命中 deny_paths（私钥、凭证、agent 配置这类文件不开放）。如确有必要，请向用户说明并由用户调整策略。", in.Path)
		return r, readOut{}, e
	}
	if m.Protected(in.Path) {
		s.audit("MCP-POLICY-DENY", "machine", in.Machine, "kind", "read_file", "detail", in.Path, "reason", "agent-protect")
		r, e := errResult("策略拒绝：%q 是这台机器 agent 自报的禁碰文件（token/配置文件），任何路径写法都不开放。", in.Path)
		return r, readOut{}, e
	}
	// 多读一个字节用来判断超限；head -c 对不存在的文件也会走 stderr 报错。
	cmd := fmt.Sprintf("head -c %d -- %s", s.cfg.Limits.MaxFile+1, shellQuote(in.Path))
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
	m, ok := s.cfg.Machines[in.Machine]
	if !ok {
		r, e := errResult("机器 %q 不在配置里", in.Machine)
		return r, writeOut{}, e
	}
	if !s.pol.Path(in.Path) {
		s.audit("MCP-POLICY-DENY", "machine", in.Machine, "kind", "write_file", "detail", in.Path, "reason", "deny_paths")
		r, e := errResult("策略拒绝：路径 %q 命中 deny_paths。如确有必要，请向用户说明并由用户调整策略。", in.Path)
		return r, writeOut{}, e
	}
	if m.Protected(in.Path) {
		s.audit("MCP-POLICY-DENY", "machine", in.Machine, "kind", "write_file", "detail", in.Path, "reason", "agent-protect")
		r, e := errResult("策略拒绝：%q 是这台机器 agent 自报的禁碰文件（token/配置文件），任何路径写法都不开放。", in.Path)
		return r, writeOut{}, e
	}
	if len(in.Content) > s.cfg.Limits.MaxFile {
		r, e := errResult("内容 %d 字节超过上限 %d", len(in.Content), s.cfg.Limits.MaxFile)
		return r, writeOut{}, e
	}
	if !m.InRoots(in.Path) {
		ar := ApprovalRequest{
			Machine: in.Machine, Kind: "write_file",
			Detail: fmt.Sprintf("写入 %s（%d 字节）", in.Path, len(in.Content)),
		}
		out, askAgain, err := s.approve(ctx, req, ar)
		if askAgain {
			return elicitRequest(ar), writeOut{}, nil
		}
		if err != nil && out != Timeout {
			r, e := errResult("批准环节出错：%v", err)
			return r, writeOut{}, e
		}
		switch out {
		case Approved, ApprovedRemember:
		case DeniedByUser:
			r, e := errResult("用户拒绝了写入 %s。请向用户说明目的，由用户决定；或把目录加进机器的 roots。", in.Path)
			return r, writeOut{}, e
		case Timeout:
			r, e := errResult("等待批准超时（%s）", s.cfg.Policy.AskTimeout)
			return r, writeOut{}, e
		default:
			r, e := errResult("批准环节不可用：%v", err)
			return r, writeOut{}, e
		}
	}
	res, err := s.runner.Run(ctx, in.Machine,
		fmt.Sprintf("cat > %s", shellQuote(in.Path)), []byte(in.Content),
		s.cfg.Limits.Timeout, 4096)
	if err != nil {
		r, e := errResult("执行失败：%v", err)
		return r, writeOut{}, e
	}
	if res.ExitCode != 0 {
		r, e := errResult("写 %s 失败（exit_code=%d）：%s", in.Path, res.ExitCode, strings.TrimSpace(res.Stderr))
		return r, writeOut{}, e
	}
	return textResult("已写入 %s（%d 字节）", in.Path, len(in.Content)),
		writeOut{BytesWritten: len(in.Content)}, nil
}

// shellQuote 把一个字符串包成 shell 单引号字面量（内部 ' 变 '\”）。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
