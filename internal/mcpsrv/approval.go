package mcpsrv

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/towstrap/towstrap/internal/notify"
)

// ApprovalRequest 是一次等待批准的请求。Detail 是命令本身或文件路径。
// Session/Digest 是绑定位：批准的效力只覆盖「这台机器、这种操作、
// 这段内容、这个工作目录、这个常驻会话、这份输入」——光换 cwd 或
// stdin 内容再调同名命令，照样重新问。Kind 进绑定位：批过一次
// run_command 不会把同命令的 terminal_open 也放行（PTY 一开后续
// 按键不再过策略，那是另一种操作）。Preview 是给人看的输入内容
// 单行预览（stdin/写入内容的大小+摘要+开头），绑定身份靠 Digest。
type ApprovalRequest struct {
	Machine string
	Kind    string // "command" | "terminal" | "write_file"
	Detail  string
	Cwd     string
	Session string // run_command 的常驻 shell 名（会话命令和一次性命令的批准不互认）
	Digest  string // stdin/写入内容的 sha256（hex 前 16 位）；空 = 没输入
	Preview string // 已剥控制字符的单行内容预览；空 = 没输入
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
	AskSpent                        // llm 确认标记在窗口内已消费过：同一条请求不再放行，也不重新挂起
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
	Session string    `json:"session,omitempty"`
	Digest  string    `json:"digest,omitempty"`
	Preview string    `json:"preview,omitempty"`
	Created time.Time `json:"created"`
	PID     int       `json:"pid"`
}

// elicitKey 是 InputRequests 里批准请求的键名。
const elicitKey = "approval"

// rememberedKey 是「本次会话记住」和「会话内确认挂起」共同的键：批准
// 绑定到完整上下文（机器 + 类型 + 内容 + cwd + 常驻会话 + 输入摘要）——
// 换任何一项都是另一条请求，不能用同一个同意。
func rememberedKey(req ApprovalRequest) string {
	return strings.Join([]string{req.Machine, req.Kind, req.Detail, req.Cwd, req.Session, req.Digest}, "\x00")
}

// digestOf 给批准绑定位算内容指纹：命令的 stdin 和 write_file 的内容
// 长度不做进 Detail，只靠摘要把「批的那份内容」钉死。空输入给空串。
func digestOf(content string) string {
	if content == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:8])
}

// previewOf 给批准界面造输入内容的单行预览：字节数+摘要钉死身份，
// 开头一小段（剥掉控制字符）让人看得出批的是什么。批准绑定位用的是
// Digest；预览只是给弹窗/对话框/待批清单看，本身不参与绑定。
func previewOf(label, content string) string {
	if content == "" {
		return ""
	}
	// QuoteToGraphic 给单行预览加引号并转义残留控制字符（Clean 会留
	// \n/\t，预览是一行的不能带真换行），又不像 %q 把中文转成 \uXXXX。
	return fmt.Sprintf("%s：%d 字节，sha256 %s，开头 %s",
		label, len(content), digestOf(content), strconv.QuoteToGraphic(clip(notify.Clean(content), 120)))
}

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

// claimPending 在锁内「有活的复用、没活的挂新」：同会话同键已有未过期
// 标记就复用它的授权编号（fresh=false），没有才登记新标记。pendingAt +
// markPending 分两步时，并发同键调用会互相覆盖——先挂的那个 ap- 编号
// 记了 MCP-ASK 却永远等不到对应的结果事件，审计链断一截。
func (s *Server) claimPending(sess *mcp.ServerSession, req ApprovalRequest, via string) (id string, fresh bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sid := sessID(sess)
	if s.pending[sid] == nil {
		s.pending[sid] = make(map[string]pendAsk)
	}
	key := rememberedKey(req)
	if p, ok := s.pending[sid][key]; ok && time.Since(p.at) <= llmConfirmTTL {
		return p.id, false
	}
	id = newAuthID()
	s.pending[sid][key] = pendAsk{id: id, via: via, at: time.Now()}
	return id, true
}

func (s *Server) clearPending(sess *mcp.ServerSession, req ApprovalRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending[sessID(sess)], rememberedKey(req))
}

// consumePending 原子地「查到并摘掉」挂起标记：拿 confirmed 并发重试
// 同一请求时，只有抢到标记的调用被放行，第二个走新请求流程重新问。
// 之前 pendingAt + clearPending 两步分开，并发下两个调用都能挤过去。
func (s *Server) consumePending(sess *mcp.ServerSession, req ApprovalRequest) (pendAsk, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := sessID(sess)
	key := rememberedKey(req)
	p, ok := s.pending[id][key]
	if ok {
		delete(s.pending[id], key)
		// llm 通道的「用户同意」是模型自称的——标记消费过就留墓碑，
		// 窗口内同一条请求不许再挂起新标记，否则一次同意能拆成
		// 无限次执行（AwaitingLLM 指引本身就能再走一圈确认流程）。
		// elicit/local 消费的是真人答复，不受此限。
		if p.via == "llm" {
			if s.spent[id] == nil {
				s.spent[id] = make(map[string]pendAsk)
			}
			s.spent[id][key] = p
		}
	}
	return p, ok
}

// spentAt 查墓碑：这条请求在窗口内已经消费过一枚 llm 确认标记吗；
// 命中时把原标记还回来，提示里能指回那一次的授权编号。
func (s *Server) spentAt(sess *mcp.ServerSession, req ApprovalRequest) (pendAsk, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.spent[sessID(sess)][rememberedKey(req)]
	return p, ok
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
	msg := fmt.Sprintf("towstrap：在 %s 上执行\n\n%s\n\ncwd: %s",
		req.Machine, notify.Clean(req.Detail), notify.Clean(orDash(req.Cwd)))
	if req.Session != "" {
		msg += "\nsession: " + notify.Clean(req.Session)
	}
	if req.Preview != "" {
		msg += "\n\n" + req.Preview
	}
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
//     一次、InputResponses 里带着答复）。不支持弹窗时看本侧有没有真人：
//     stdio（Remote=false）落本地待批文件——审批默认要真人；内嵌服务
//     器（Remote=true）的「本机」是无人值守的服务器，落到会话内确认，
//     等的是对话那头的远程用户。
//   - ask_via=local：本地待批文件 + 批准命令兜底（客户端会不会弹窗都走这条——
//     有的客户端声明了 elicitation 却渲染不出弹窗，操作员需要这个开关绕开它）；
//     local_notify 打开时还会在被批准机器上弹系统对话框。
//   - ask_via=llm：会话内确认——先记一笔「已发起确认」，返回 AwaitingLLM 让
//     调用方把「先问用户」的指引报给 LLM；用户同意后 LLM 带 confirmed=true
//     重试，凭标记放行。confirmed 只是 LLM 声称用户同意——防误操作，不防
//     恶意模型，审计记成 MCP-CONFIRMED 与真人批准区分。
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
			// 有答复才消费标记——没答复的并发调用继续等自己的回合；
			// 消费是原子的，两个带着答复的并发调用只有一个能落定。
			pp, consumed := s.consumePending(req.Session, ar)
			if !consumed {
				return AwaitingLLM, false, "", nil
			}
			out = s.evalElicit(req.Session, ar, er, pp.id)
			rem, _ := er.Content["remember"].(bool)
			if rem && out == Approved {
				s.auditOutcome(out, ar, pp.id, "remember", "true")
			} else {
				s.auditOutcome(out, ar, pp.id)
			}
			s.tellSettled(ctx, req.Session, pp.id, out, rem)
			return out, false, pp.id, nil
		}
		switch {
		case p.via == "elicit":
			return Approved, true, p.id, nil // 弹窗答复在路上/丢了：重发 elicit 请求
		case !confirmed:
			return AwaitingLLM, false, p.id, nil // 还在等用户答复，原样重试不算同意
		default:
			// confirmed 重试：原子消费标记——并发带 confirmed 的两个调用
			// 只有一个放行，另一个当成新请求重新走确认。
			pp, consumed := s.consumePending(req.Session, ar)
			if !consumed {
				return AwaitingLLM, false, "", nil
			}
			if remember {
				s.remember(req.Session, ar, pp.id)
			}
			if remember {
				s.auditOutcome(ApprovedLLM, ar, pp.id, "remember", "true")
			} else {
				s.auditOutcome(ApprovedLLM, ar, pp.id)
			}
			s.tellSettled(ctx, req.Session, pp.id, ApprovedLLM, remember)
			return ApprovedLLM, false, pp.id, nil
		}
	} else if ok {
		s.clearPending(req.Session, ar) // 过期：当成新请求重新发起确认
	}
	// 会话内确认通道：显式 ask_via=llm，或 auto 且本侧没人值守
	// （Remote——内嵌服务器的「本机」是服务器自己，本地待批文件和
	// 对话框只会挂到超时）且客户端不支持弹窗。stdio 的 Remote 恒
	// false，auto 照旧落本地批准。
	if s.cfg.Policy.AskVia == "llm" ||
		(s.cfg.Policy.AskVia == "" && s.cfg.Remote && !supportsElicitation(req.Session)) {
		// 墓碑在窗口内：这条请求的会话内确认标记已消费过，不再
		// 放行也不重新挂起——否则一次同意能拆成无限次执行。要再
		// 跑这条命令得等 llmConfirmTTL 过了重新确认一轮，或首次
		// 确认时带 remember。
		if p, ok := s.spentAt(req.Session, ar); ok && time.Since(p.at) <= llmConfirmTTL {
			s.audit("MCP-ASK-SPENT", "machine", ar.Machine, "kind", ar.Kind, "detail", ar.Detail, "auth", p.id)
			return AskSpent, false, p.id, nil
		}
		o, id := s.askViaLLM(req, ar)
		s.tellNotice(ctx, req.Session, fmt.Sprintf(
			"确认请求 %s 已发往会话内确认（%s: %s）——等对话里的用户答复",
			id, ar.Machine, clip(ar.Detail, 120)))
		return o, false, id, nil
	}
	// auto（没写 ask_via）且客户端支持弹窗：走 elicitation——真人在客户端
	// 里点确认框。显式 local 不走这里（它压过客户端能力）。
	if s.cfg.Policy.AskVia == "" && supportsElicitation(req.Session) {
		id, fresh := s.claimPending(req.Session, ar, "elicit")
		if fresh {
			s.audit("MCP-ASK", "machine", ar.Machine, "kind", ar.Kind, "detail", ar.Detail, "via", "elicit", "auth", id)
			s.tellNotice(ctx, req.Session, fmt.Sprintf(
				"确认请求 %s 已发往客户端弹窗（%s: %s）；客户端不支持渲染弹窗时会走会话内确认，也可配 policy.ask_via 强制通道",
				id, ar.Machine, clip(ar.Detail, 120)))
		}
		// 并发同键调用共享同一个授权编号：各自发各自的弹窗，任一答复
		// 落定后其余答复落空（标记已被消费），不会出现一次同意放行两次。
		s.tellProgress(ctx, req, fmt.Sprintf("等待确认 %s（%s: %s）", id, ar.Machine, clip(ar.Detail, 80)))
		return Approved, true, id, nil
	}
	// 剩下两种进本地待批文件通道：显式 ask_via=local，或 stdio auto 且
	// 客户端不支持弹窗（Remote 的已在上面截走去会话内确认）。
	id := newAuthID()
	s.audit("MCP-ASK", "machine", ar.Machine, "kind", ar.Kind, "detail", ar.Detail, "via", "local", "auth", id)
	s.tellProgress(ctx, req, fmt.Sprintf("等待人工批准 %s（%s: %s）", id, ar.Machine, clip(ar.Detail, 80)))
	out, rem, err := s.waitLocal(ctx, req.Session, ar, id)
	if out == Approved && rem {
		s.remember(req.Session, ar, id) // 「允许并不再问」记进本会话名单
	}
	if rem {
		s.auditOutcome(out, ar, id, "remember", "true")
	} else {
		s.auditOutcome(out, ar, id)
	}
	s.tellSettled(ctx, req.Session, id, out, rem)
	return out, false, id, err
}

// askViaLLM 记一笔「已发起会话内确认」并让调用方把指引交还给 LLM；
// 返回值是 Outcome 和这次挂起的授权编号。
func (s *Server) askViaLLM(req *mcp.CallToolRequest, ar ApprovalRequest) (Outcome, string) {
	id, fresh := s.claimPending(req.Session, ar, "llm")
	if fresh {
		s.audit("MCP-ASK", "machine", ar.Machine, "kind", ar.Kind, "detail", ar.Detail, "via", "llm", "auth", id)
	}
	// fresh=false：并发同键调用复用已在等的授权编号（审计只有一条
	// MCP-ASK），LLM 照旧拿 AwaitingLLM+同一个 id 去等用户答复。
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

// tellNotice 给调用方发一条提示：MCP logging 到发起调用的客户端，外加
// stderr 上的 slog（stdio 走 SSH 时落在远端日志，内嵌模式进服务端日志）。
// 注意 logging 是尽力投递：客户端没发过 logging/setLevel（新协议里则是
// 请求 _meta 没带 logLevel）SDK 就静默丢弃，且该特性在 2026-07-28 版
// 协议起已废弃——确定性通道是工具返回值和 progress 通知，logging 只当
// 加分项用。
func (s *Server) tellNotice(ctx context.Context, sess *mcp.ServerSession, msg string) {
	msg = notify.Clean(msg) // 命令内容不可信：剥掉终端转义再到处发
	slog.Warn(msg)
	if sess != nil {
		_ = sess.Log(ctx, &mcp.LoggingMessageParams{
			Level:  "warning",
			Logger: "towstrap",
			Data:   msg,
		})
	}
}

// tellProgress 走 notifications/progress 给调用方补一条可见信号：没有
// 级别门，请求 _meta 里带了 progressToken 就能送达（各家客户端常会带），
// 没带就跳过——同样尽力投递，只是覆盖面比 logging 好得多。pending 期间
// 用它给「正在等批准」一个客户端可见的落点。
func (s *Server) tellProgress(ctx context.Context, req *mcp.CallToolRequest, msg string) {
	if req == nil || req.Session == nil || req.Params == nil {
		return
	}
	ptok := req.Params.GetProgressToken()
	if ptok == nil {
		return
	}
	_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
		ProgressToken: ptok,
		Message:       notify.Clean(msg),
	})
}

// tellSettled 批准出了结果时同步给会话那头的用户：刚才挂着的那个请求
// 是批了、被拒了还是超时了，不用回客户端猜。
func (s *Server) tellSettled(ctx context.Context, sess *mcp.ServerSession, authID string, out Outcome, remember bool) {
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
	s.tellNotice(ctx, sess, fmt.Sprintf("%s：%s", what, authID))
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

// clip 截断长命令给提示消息用：收在 UTF-8 字符边界上——按字节硬切会
// 把多字节字符切成两半，落到落盘预览和日志里就是坏字节。
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.ValidString(s[:n]) {
		n--
	}
	return s[:n] + "…"
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
		Detail: req.Detail, Cwd: req.Cwd, Session: req.Session, Digest: req.Digest,
		Preview: req.Preview,
		Created: time.Now(), PID: os.Getpid(),
	}
	b, _ := json.MarshalIndent(pf, "", "  ")
	jsonPath := filepath.Join(dir, id+".json")
	if err := os.WriteFile(jsonPath, b, 0600); err != nil {
		return Unavailable, false, fmt.Errorf("写待批文件 %s: %w", jsonPath, err)
	}
	notice := fmt.Sprintf(
		"等待人工批准 %s（%s: %s）——批准：%s %s；%s内未处理视为拒绝",
		id, req.Machine, clip(req.Detail, 80), s.cfg.ApproveCmd, id, humanDur(s.cfg.Policy.AskTimeout))
	// cwd/常驻会话是批准判断的一部分（同一条命令换个目录批不批可能
	// 不一样），审批人得看得到。
	if req.Cwd != "" {
		notice += "\ncwd: " + req.Cwd
	}
	if req.Session != "" {
		notice += "\nsession: " + req.Session
	}
	if req.Preview != "" {
		notice += "\n" + req.Preview
	}
	s.tellNotice(ctx, sess, notice)
	approved := filepath.Join(dir, id+".approved")
	denied := filepath.Join(dir, id+".denied")
	remember := filepath.Join(dir, id+".remember")

	// LocalNotify 开时（stdio 模式、或服务器明确开了 mcp.local_notify）：
	// 先发横幅通知保底，同时尝试弹能点的系统对话框——点了就直接落
	// .approved/.denied（「允许并不再问」多落一个 .remember）；
	// 这台机器弹不了（没图形界面/没 zenity）也不亏。注意永远不往终端
	// 里写字节：wall 广播会把 vim/top 这类 TUI 的屏幕画花，而且批
	// 的是发起调用的用户，不该惊动本机上别的登录者。
	if s.cfg.LocalNotify {
		dlgCtx, cancelDlg := context.WithCancel(ctx)
		defer cancelDlg() // 批准结果一出来（包括终端命令批准）就把对话框收掉
		go func() {
			detail := req.Detail
			if len(detail) > 80 {
				detail = detail[:80] + "…"
			}
			title := "towstrap 需要批准"
			// 分行排版：对话框/通知都是给人看的，一眼能扫到机器、
			// 命令、编号，比挤成一行清楚。对话框有自己的三个按钮，
			// 不需要终端命令；横幅通知点不了，得给出命令行批准方式。
			extra := ""
			if req.Preview != "" {
				extra = req.Preview + "\n"
			}
			ctxLine := ""
			if req.Cwd != "" {
				ctxLine += "\ncwd：" + req.Cwd
			}
			if req.Session != "" {
				ctxLine += "\nsession：" + req.Session
			}
			base := fmt.Sprintf("机器：%s\n命令：%s%s\n%s批准编号：%s\n\n%s内不处理视为拒绝",
				req.Machine, detail, ctxLine, extra, id, humanDur(s.cfg.Policy.AskTimeout))
			hint := fmt.Sprintf("\n\n也可在终端运行：\n%s %s", s.cfg.ApproveCmd, id)
			notify.Desktop(title, base+hint)
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
