package mcpsrv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/towstrap/towstrap/internal/notify"
)

// ApprovalRequest 是一次等待批准的请求。Detail 是命令本身或文件路径。
type ApprovalRequest struct {
	Machine string
	Kind    string // "command" | "write_file"
	Detail  string
	Cwd     string
}

// Outcome 是批准环节的结果。
type Outcome int

const (
	Approved         Outcome = iota // 用户点了允许
	ApprovedRemember                // 命中了「本次会话记住」
	DeniedByUser                    // 用户点了拒绝/取消
	Timeout                         // 等到 ask_timeout 也没人处理
	Unavailable                     // 客户端不支持弹窗，本地回退也没法走
	AwaitingLLM                     // 已把「先问用户」的指引交还给 LLM 会话，等带 confirmed 的重试
	ApprovedLLM                     // LLM 会话带回 confirmed=true：用户在对话里同意了（弱于真人弹窗，审计单列）
)

// llmConfirmTTL 是「会话内确认」发起后等 confirmed 重试的窗口：问过就算
// 数，但用户隔太久才答复时让 LLM 重新问一遍，避免拿很早以前的许可套现在
// 的操作。
const llmConfirmTTL = 10 * time.Minute

// pendingFile 是 approvals_dir 里 <id>.json 的内容，approve/deny 子命令
// 靠写 <id>.approved / <id>.denied 表态。
type pendingFile struct {
	ID      string    `json:"id"`
	Machine string    `json:"machine"`
	Kind    string    `json:"kind"`
	Detail  string    `json:"detail"`
	Cwd     string    `json:"cwd,omitempty"`
	Created time.Time `json:"created"`
	PID     int       `json:"pid"`
}

// elicitKey 是 InputRequests 里批准请求的键名。
const elicitKey = "approval"

// rememberedKey 是「本次会话记住」的键：同一台机器上相同 detail 不再问。
func rememberedKey(req ApprovalRequest) string { return req.Machine + "\x00" + req.Detail }

// sessID 容忍单测等没有真实会话的 nil。
func sessID(sess *mcp.ServerSession) string {
	if sess == nil {
		return ""
	}
	return sess.ID()
}

// isRemembered / remember 管理会话内的记住名单（按客户端会话隔离）。
// 记住的不只是「问过」，还有当初的授权编号——之后每次凭记住放行执行的
// 记录都指回那一次批准，方便审计把执行和授权串起来。
func (s *Server) rememberedGrant(sess *mcp.ServerSession, req ApprovalRequest) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.remembered[sessID(sess)][rememberedKey(req)]
	return id, ok
}

func (s *Server) remember(sess *mcp.ServerSession, req ApprovalRequest, grantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := sessID(sess)
	if s.remembered[id] == nil {
		s.remembered[id] = make(map[string]string)
	}
	s.remembered[id][rememberedKey(req)] = grantID
}

// pendAsk 是一次已发出、还没拿到答复的确认请求：id 是授权编号（审计里
// auth= 把它和最终执行一一对应），via 记走的是弹窗还是会话内确认。
type pendAsk struct {
	id  string
	via string
	at  time.Time
}

// pendingAt / markPending / clearPending 管理「会话内确认」和弹窗回合的
// 挂起标记：本会话已对这条请求发起过确认才算数，confirmed 重试凭标记放行、
// 用过即销，防止 LLM 拿一个标记反复跑同名危险命令。
func (s *Server) pendingAt(sess *mcp.ServerSession, req ApprovalRequest) (pendAsk, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[sessID(sess)][rememberedKey(req)]
	return p, ok
}

func (s *Server) markPending(sess *mcp.ServerSession, req ApprovalRequest, p pendAsk) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := sessID(sess)
	if s.pending[id] == nil {
		s.pending[id] = make(map[string]pendAsk)
	}
	s.pending[id][rememberedKey(req)] = p
}

func (s *Server) clearPending(sess *mcp.ServerSession, req ApprovalRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending[sessID(sess)], rememberedKey(req))
}

// supportsElicitation 看客户端 initialize 时声明的能力：会弹确认框才走
// elicitation，否则走本地批准回退。
func supportsElicitation(sess *mcp.ServerSession) bool {
	if sess == nil {
		return false
	}
	ip := sess.InitializeParams()
	return ip != nil && ip.Capabilities != nil && ip.Capabilities.Elicitation != nil
}

// elicitResult 取出 handler 被二次调用时带回来的批准答复；
// 第一轮调用时返回 nil。
func elicitResult(req *mcp.CallToolRequest) *mcp.ElicitResult {
	if req.Params == nil || req.Params.InputResponses == nil {
		return nil
	}
	if r, ok := req.Params.InputResponses[elicitKey]; ok {
		if er, ok := r.(*mcp.ElicitResult); ok {
			return er
		}
	}
	return nil
}

// elicitRequest 造一个「带 InputRequests 的结果」让 handler 返回——这是
// SDK 的 MRTR（SEP-2322）模式：新协议客户端由客户端中间件完成往返，
// 旧协议客户端由服务器中间件转成传统 elicitation/create，两种协议下
// handler 都会被再调一次且 InputResponses 里带着答复。
// 注意：不能在新协议下直接调 ServerSession.Elicit——SDK 会报
// "cannot be sent while serving a request"，必须用 InputRequests。
func elicitRequest(req ApprovalRequest) *mcp.CallToolResult {
	msg := fmt.Sprintf("towstrap：在 %s 上执行\n\n%s\n\ncwd: %s", req.Machine, req.Detail, orDash(req.Cwd))
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{
			elicitKey: &mcp.ElicitParams{
				Message: msg,
				RequestedSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"approve":  map[string]any{"type": "boolean", "title": "允许执行", "default": true},
						"remember": map[string]any{"type": "boolean", "title": "本次会话内相同命令不再询问", "default": false},
					},
					"required": []string{"approve"},
				},
			},
		},
	}
}

// evalElicit 把弹窗答复换算成 Outcome：accept+approve → 批准
// （remember 时把这次授权编号记进会话名单）；decline/cancel/没勾
// approve → 拒绝。
func (s *Server) evalElicit(sess *mcp.ServerSession, req ApprovalRequest, er *mcp.ElicitResult, grantID string) Outcome {
	if er.Action != "accept" {
		return DeniedByUser
	}
	ok, _ := er.Content["approve"].(bool)
	if !ok {
		return DeniedByUser
	}
	if remember, _ := er.Content["remember"].(bool); remember {
		s.remember(sess, req, grantID)
	}
	return Approved
}

// approve 走批准环节，confirmed/remember 是工具入参里 LLM 带回来的答复；
// 返回值里的 authID 是这次授权的编号（ApprovedRemember 指回当初那次批准），
// 审计事件都带 auth= 便于把「申请—批准—执行」一一对应。通道按 ask_via 选：
//
//   - 不写（auto）：客户端支持 elicitation 就弹确认框（本轮返回 askAgain=true，
//     调用方把 elicitRequest 的结果交出去，SDK 完成往返后会把 handler 再调
//     一次、InputResponses 里带着答复）；不支持就走本地待批文件——审批
//     默认要真人，经不经过客户端弹窗都一样。
//   - ask_via=local：本地待批文件 + 批准命令兜底（客户端会不会弹窗都走这条——
//     有的客户端声明了 elicitation 却渲染不出弹窗，操作员需要这个开关绕开它）；
//     local_notify 打开时还会在被批准机器上弹系统对话框。
//   - ask_via=llm：会话内确认——先记一笔「已发起确认」，返回 AwaitingLLM 让
//     调用方把「先问用户」的指引报给 LLM；用户同意后 LLM 带 confirmed=true
//     重试，凭标记放行。confirmed 只是 LLM 声称用户同意——防误操作，不防
//     恶意模型，审计记成 MCP-CONFIRMED 与真人批准区分。这是**显式可选**：
//     不写 ask_via 时不会自动走这条。
//
// 进出批准环节都记审计：MCP-ASK（via=elicit|local|llm）、
// MCP-APPROVED / MCP-CONFIRMED / MCP-DENIED / MCP-ASK-TIMEOUT。
func (s *Server) approve(ctx context.Context, req *mcp.CallToolRequest, ar ApprovalRequest, confirmed, remember bool) (out Outcome, askAgain bool, authID string, err error) {
	s.watchSession(req.Session)
	if gid, ok := s.rememberedGrant(req.Session, ar); ok {
		return ApprovedRemember, false, gid, nil
	}
	if p, ok := s.pendingAt(req.Session, ar); ok && time.Since(p.at) <= llmConfirmTTL {
		if er := elicitResult(req); er != nil {
			out = s.evalElicit(req.Session, ar, er, p.id)
			s.clearPending(req.Session, ar)
			rem, _ := er.Content["remember"].(bool)
			if rem && out == Approved {
				s.auditOutcome(out, ar, p.id, "remember", "true")
			} else {
				s.auditOutcome(out, ar, p.id)
			}
			s.tellSettled(ctx, req.Session, ar.Machine, p.id, out, rem)
			return out, false, p.id, nil
		}
		switch {
		case p.via == "elicit":
			return Approved, true, p.id, nil // 弹窗答复在路上/丢了：重发 elicit 请求
		case !confirmed:
			return AwaitingLLM, false, p.id, nil // 还在等用户答复，原样重试不算同意
		default:
			s.clearPending(req.Session, ar)
			if remember {
				s.remember(req.Session, ar, p.id)
			}
			if remember {
				s.auditOutcome(ApprovedLLM, ar, p.id, "remember", "true")
			} else {
				s.auditOutcome(ApprovedLLM, ar, p.id)
			}
			s.tellSettled(ctx, req.Session, ar.Machine, p.id, ApprovedLLM, remember)
			return ApprovedLLM, false, p.id, nil
		}
	} else if ok {
		s.clearPending(req.Session, ar) // 过期：当成新请求重新发起确认
	}
	if s.cfg.Policy.AskVia == "llm" {
		o, id := s.askViaLLM(req, ar)
		return o, false, id, nil
	}
	// auto（没写 ask_via）且客户端支持弹窗：走 elicitation——真人在客户端
	// 里点确认框。显式 local 不走这里（它压过客户端能力）。
	if s.cfg.Policy.AskVia == "" && supportsElicitation(req.Session) {
		id := newAuthID()
		s.markPending(req.Session, ar, pendAsk{id: id, via: "elicit", at: time.Now()})
		s.audit("MCP-ASK", "machine", ar.Machine, "kind", ar.Kind, "detail", ar.Detail, "via", "elicit", "auth", id)
		s.tellNotice(ctx, req.Session, ar.Machine, fmt.Sprintf(
			"确认请求 %s 已发往客户端弹窗（%s: %s）；看不到弹窗说明客户端不支持渲染，可改用 policy.ask_via: local 走本机批准",
			id, ar.Machine, clip(ar.Detail, 120)))
		return Approved, true, id, nil
	}
	// 剩下两种进本地待批文件通道：显式 ask_via=local，或 auto 且客户端
	// 不支持弹窗——审批默认要真人，不自动降格成 LLM 会话内确认。
	id := newAuthID()
	s.audit("MCP-ASK", "machine", ar.Machine, "kind", ar.Kind, "detail", ar.Detail, "via", "local", "auth", id)
	out, rem, err := s.waitLocal(ctx, req.Session, ar, id)
	if out == Approved && rem {
		s.remember(req.Session, ar, id) // 「允许并不再问」记进本会话名单
	}
	if rem {
		s.auditOutcome(out, ar, id, "remember", "true")
	} else {
		s.auditOutcome(out, ar, id)
	}
	s.tellSettled(ctx, req.Session, ar.Machine, id, out, rem)
	return out, false, id, err
}

// askViaLLM 记一笔「已发起会话内确认」并让调用方把指引交还给 LLM；
// 返回值是 Outcome 和这次挂起的授权编号。
func (s *Server) askViaLLM(req *mcp.CallToolRequest, ar ApprovalRequest) (Outcome, string) {
	id := newAuthID()
	s.markPending(req.Session, ar, pendAsk{id: id, via: "llm", at: time.Now()})
	s.audit("MCP-ASK", "machine", ar.Machine, "kind", ar.Kind, "detail", ar.Detail, "via", "llm", "auth", id)
	return AwaitingLLM, id
}

// auditOutcome 把批准结果记成审计事件，带上授权编号；extra 追加
// 「remember=true」这类补充字段（批准同时进了记住名单时用）。
func (s *Server) auditOutcome(out Outcome, ar ApprovalRequest, authID string, extra ...string) {
	var ev string
	switch out {
	case Approved, ApprovedRemember:
		ev = "MCP-APPROVED"
	case ApprovedLLM:
		ev = "MCP-CONFIRMED"
	case DeniedByUser:
		ev = "MCP-DENIED"
	case Timeout:
		ev = "MCP-ASK-TIMEOUT"
	default:
		return // Unavailable 之类的由调用方报错，不记结果事件
	}
	kv := []string{"machine", ar.Machine, "kind", ar.Kind, "detail", ar.Detail, "auth", authID}
	s.audit(ev, append(kv, extra...)...)
}

// tellNotice 往各处发一条通知：MCP logging 给远端客户端（看不到对话框
// 的客户端至少知道发生了什么）、stderr 上的 slog（stdio 走 SSH 时直接
// 落在远端终端，内嵌模式进服务端日志）、OnPending 钩子（内嵌服务器接
// 它写进同账号的 SSH 终端）。工具调用阻塞/出结果时远端原本什么迹象都没有。
func (s *Server) tellNotice(ctx context.Context, sess *mcp.ServerSession, machine, msg string) {
	slog.Warn(msg)
	if sess != nil {
		_ = sess.Log(ctx, &mcp.LoggingMessageParams{
			Level:  "warning",
			Logger: "towstrap",
			Data:   msg,
		})
	}
	if s.cfg.OnPending != nil {
		s.cfg.OnPending(machine, msg)
	}
}

// tellSettled 批准出了结果时同步给各处：等在终端前的人能立刻看到刚才
// 挂着的那个请求是批了、被拒了还是超时了，不用回客户端猜。
func (s *Server) tellSettled(ctx context.Context, sess *mcp.ServerSession, machine, authID string, out Outcome, remember bool) {
	what := ""
	switch out {
	case Approved:
		what = "已批准，正在执行"
		if remember {
			what = "已批准（本会话内相同命令不再问），正在执行"
		}
	case ApprovedLLM:
		what = "会话内确认通过，正在执行"
	case DeniedByUser:
		what = "已被拒绝，未执行"
	case Timeout:
		what = "等待批准超时，未执行"
	case Unavailable:
		what = "批准通道不可用，未执行"
	}
	if what == "" {
		return
	}
	s.tellNotice(ctx, sess, machine, fmt.Sprintf("%s：%s", what, authID))
}

// humanDur 把时长说成人话：对话框、SSH 提示、报错里给用户看的，
// 不能拿 Go 的 "5m0s" 直接摆上去。
func humanDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%d毫秒", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%d秒", int(d.Seconds()))
	}
	if d < time.Hour {
		if sec := int(d.Seconds()) % 60; sec != 0 {
			return fmt.Sprintf("%d分%d秒", int(d.Minutes()), sec)
		}
		return fmt.Sprintf("%d分钟", int(d.Minutes()))
	}
	if m := int(d.Minutes()) % 60; m != 0 {
		return fmt.Sprintf("%d小时%d分钟", int(d.Hours()), m)
	}
	return fmt.Sprintf("%d小时", int(d.Hours()))
}

// clip 截断长命令给提示消息用。
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// waitLocal 是本地批准回退：写 <id>.json、弹桌面通知、每 500ms 看一次
// <id>.approved / <id>.denied 出没出现，直到超时或调用方取消。id 就是
// 授权编号，批准命令和审计事件里看到的是同一个。remember=true 表示批准时
// 还选了「不再问」（对话框第三钮或 approve --remember 写下的 .remember 文件），
// 由调用方决定记不记进会话名单。
func (s *Server) waitLocal(ctx context.Context, sess *mcp.ServerSession, req ApprovalRequest, id string) (Outcome, bool, error) {
	dir := s.cfg.ApprovalsDir
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Unavailable, false, fmt.Errorf("建批准目录 %s: %w", dir, err)
	}
	pf := pendingFile{
		ID: id, Machine: req.Machine, Kind: req.Kind,
		Detail: req.Detail, Cwd: req.Cwd, Created: time.Now(), PID: os.Getpid(),
	}
	b, _ := json.MarshalIndent(pf, "", "  ")
	jsonPath := filepath.Join(dir, id+".json")
	if err := os.WriteFile(jsonPath, b, 0600); err != nil {
		return Unavailable, false, fmt.Errorf("写待批文件 %s: %w", jsonPath, err)
	}
	s.tellNotice(ctx, sess, req.Machine, fmt.Sprintf(
		"等待人工批准 %s（%s: %s）——批准：%s %s；%s内未处理视为拒绝",
		id, req.Machine, clip(req.Detail, 80), s.cfg.ApproveCmd, id, humanDur(s.cfg.Policy.AskTimeout)))
	approved := filepath.Join(dir, id+".approved")
	denied := filepath.Join(dir, id+".denied")
	remember := filepath.Join(dir, id+".remember")

	// LocalNotify 开时（stdio 模式、或服务器明确开了 mcp.local_notify）：
	// 横幅通知 + wall 广播（覆盖本机真实登录的终端——真 sshd、控制台
	// 都能看见）先发出去保底，同时尝试弹能点的系统对话框——点了就直接落
	// .approved/.denied（「允许并不再问」多落一个 .remember）；
	// 这台机器弹不了（没图形界面/没 zenity）也不亏。
	if s.cfg.LocalNotify {
		dlgCtx, cancelDlg := context.WithCancel(ctx)
		defer cancelDlg() // 批准结果一出来（包括终端命令批准）就把对话框收掉
		go func() {
			detail := req.Detail
			if len(detail) > 80 {
				detail = detail[:80] + "…"
			}
			title := "towstrap 需要批准"
			// 分行排版：对话框/通知/wall 都是给人看的，一眼能扫到机器、
			// 命令、编号，比挤成一行清楚。对话框有自己的三个按钮，
			// 不需要终端命令；通知和 wall 点不了，得给出命令行批准方式。
			base := fmt.Sprintf("机器：%s\n命令：%s\n批准编号：%s\n\n%s内不处理视为拒绝",
				req.Machine, detail, id, humanDur(s.cfg.Policy.AskTimeout))
			hint := fmt.Sprintf("\n\n也可在终端运行：\n%s %s", s.cfg.ApproveCmd, id)
			notify.Desktop(title, base+hint)
			notify.Wall(title + "：" + base + hint)
			ans, answered := notify.Confirm(dlgCtx, title, base, s.cfg.Policy.AskTimeout)
			if !answered {
				return
			}
			stamp := []byte(time.Now().Format(time.RFC3339))
			switch ans {
			case notify.Allow:
				_ = os.WriteFile(approved, stamp, 0600)
			case notify.AllowRemember:
				_ = os.WriteFile(remember, stamp, 0600)
				_ = os.WriteFile(approved, stamp, 0600)
			default:
				_ = os.WriteFile(denied, stamp, 0600)
			}
		}()
	}

	defer func() {
		_ = os.Remove(jsonPath)
		_ = os.Remove(approved)
		_ = os.Remove(denied)
		_ = os.Remove(remember)
	}()

	deadline := time.NewTimer(s.cfg.Policy.AskTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return Timeout, false, ctx.Err()
		case <-deadline.C:
			return Timeout, false, nil
		case <-tick.C:
			if _, err := os.Stat(approved); err == nil {
				_, rem := os.Stat(remember)
				return Approved, rem == nil, nil
			}
			if _, err := os.Stat(denied); err == nil {
				return DeniedByUser, false, nil
			}
		}
	}
}

// newAuthID 生成授权编号：审计事件、待批文件、会话记录共用它做关联。
func newAuthID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "ap-" + hex.EncodeToString(b)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---- 下面的函数给 towstrap-mcp 的 pending/approve/deny 子命令用 ----

// Pending 列出 approvals_dir 里等待批准的请求。
func Pending(dir string) ([]PendingFile, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []PendingFile
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var pf pendingFile
		if json.Unmarshal(b, &pf) == nil && pf.ID != "" {
			out = append(out, pf)
		}
	}
	return out, nil
}

// PendingFile 是导出的待批记录，给 CLI 打印用。
type PendingFile = pendingFile

// settle 写 <id>.approved / <id>.denied 文件。id 可以是 "--all" 之外的
// 具体 id；all=true 时对目录里每个待批请求都写一份。remember 只和批准
// 搭配：多落一个 <id>.remember，服务端见到后把该命令记进发起会话的名单。
func settle(dir, id, suffix string, all, remember bool) (int, error) {
	var ids []string
	if all {
		list, err := Pending(dir)
		if err != nil {
			return 0, err
		}
		for _, pf := range list {
			ids = append(ids, pf.ID)
		}
		if len(ids) == 0 {
			return 0, fmt.Errorf("没有等待批准的请求")
		}
	} else {
		if id == "" {
			return 0, fmt.Errorf("缺批准 id（或 --all）")
		}
		// 请求还在才写表态文件，不然 .approved/.denied 会永远留在目录里。
		if _, err := os.Stat(filepath.Join(dir, id+".json")); err != nil {
			return 0, fmt.Errorf("没有这个待批请求（可能已超时或已处理）：%s", id)
		}
		ids = []string{id}
	}
	stamp := []byte(time.Now().Format(time.RFC3339))
	for _, one := range ids {
		if remember {
			if err := os.WriteFile(filepath.Join(dir, one+".remember"), stamp, 0600); err != nil {
				return 0, fmt.Errorf("写 %s.remember: %w", one, err)
			}
		}
		p := filepath.Join(dir, one+suffix)
		if err := os.WriteFile(p, stamp, 0600); err != nil {
			return 0, fmt.Errorf("写 %s: %w", p, err)
		}
	}
	return len(ids), nil
}

// ApprovePending 批准一个（或 --all 全部）待批请求，返回处理的条数。
// remember=true 时同时让发起会话记住这条命令（本会话内不再问）。
func ApprovePending(dir, id string, all, remember bool) (int, error) {
	return settle(dir, id, ".approved", all, remember)
}

// DenyPending 拒绝一个（或 --all 全部）待批请求。
func DenyPending(dir, id string, all bool) (int, error) {
	return settle(dir, id, ".denied", all, false)
}
