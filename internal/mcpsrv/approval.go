package mcpsrv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ws2ssh/internal/notify"
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
)

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

// isRemembered / remember 管理会话内的记住名单（按客户端会话隔离）。
func (s *Server) isRemembered(sess *mcp.ServerSession, req ApprovalRequest) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remembered[sess.ID()][rememberedKey(req)]
}

func (s *Server) remember(sess *mcp.ServerSession, req ApprovalRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remembered[sess.ID()] == nil {
		s.remembered[sess.ID()] = make(map[string]bool)
	}
	s.remembered[sess.ID()][rememberedKey(req)] = true
}

// supportsElicitation 看客户端 initialize 时声明的能力：会弹确认框才走
// elicitation，否则走本地批准回退。
func supportsElicitation(sess *mcp.ServerSession) bool {
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
	msg := fmt.Sprintf("ws2ssh：在 %s 上执行\n\n%s\n\ncwd: %s", req.Machine, req.Detail, orDash(req.Cwd))
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
// （remember 时记进会话名单）；decline/cancel/没勾 approve → 拒绝。
func (s *Server) evalElicit(sess *mcp.ServerSession, req ApprovalRequest, er *mcp.ElicitResult) Outcome {
	if er.Action != "accept" {
		return DeniedByUser
	}
	ok, _ := er.Content["approve"].(bool)
	if !ok {
		return DeniedByUser
	}
	if remember, _ := er.Content["remember"].(bool); remember {
		s.remember(sess, req)
	}
	return Approved
}

// approve 走两层批准：客户端支持 elicitation 就弹确认框（本轮返回
// askAgain=true，调用方把 elicitRequest 的结果交出去，SDK 完成往返后会
// 把 handler 再调一次、InputResponses 里带着答复）；不支持就在
// approvals_dir 里落一个待批文件，等用户跑 ws2ssh-mcp approve。
func (s *Server) approve(ctx context.Context, req *mcp.CallToolRequest, ar ApprovalRequest) (out Outcome, askAgain bool, err error) {
	if s.isRemembered(req.Session, ar) {
		return ApprovedRemember, false, nil
	}
	if er := elicitResult(req); er != nil {
		return s.evalElicit(req.Session, ar, er), false, nil
	}
	if supportsElicitation(req.Session) {
		return Approved, true, nil
	}
	out, err = s.waitLocal(ctx, ar)
	return out, false, err
}

// waitLocal 是本地批准回退：写 <id>.json、弹桌面通知、每 500ms 看一次
// <id>.approved / <id>.denied 出没出现，直到超时或调用方取消。
func (s *Server) waitLocal(ctx context.Context, req ApprovalRequest) (Outcome, error) {
	dir := s.cfg.ApprovalsDir
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Unavailable, fmt.Errorf("建批准目录 %s: %w", dir, err)
	}
	id := newApprovalID()
	pf := pendingFile{
		ID: id, Machine: req.Machine, Kind: req.Kind,
		Detail: req.Detail, Cwd: req.Cwd, Created: time.Now(), PID: os.Getpid(),
	}
	b, _ := json.MarshalIndent(pf, "", "  ")
	jsonPath := filepath.Join(dir, id+".json")
	if err := os.WriteFile(jsonPath, b, 0600); err != nil {
		return Unavailable, fmt.Errorf("写待批文件 %s: %w", jsonPath, err)
	}
	detail := req.Detail
	if len(detail) > 80 {
		detail = detail[:80] + "…"
	}
	notify.Desktop("ws2ssh-mcp 需要批准",
		fmt.Sprintf("%s: %s；运行 ws2ssh-mcp approve %s", req.Machine, detail, id))

	approved := filepath.Join(dir, id+".approved")
	denied := filepath.Join(dir, id+".denied")
	defer func() {
		_ = os.Remove(jsonPath)
		_ = os.Remove(approved)
		_ = os.Remove(denied)
	}()

	deadline := time.NewTimer(s.cfg.Policy.AskTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return Timeout, ctx.Err()
		case <-deadline.C:
			return Timeout, nil
		case <-tick.C:
			if _, err := os.Stat(approved); err == nil {
				return Approved, nil
			}
			if _, err := os.Stat(denied); err == nil {
				return DeniedByUser, nil
			}
		}
	}
}

func newApprovalID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---- 下面的函数给 ws2ssh-mcp 的 pending/approve/deny 子命令用 ----

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
// 具体 id；all=true 时对目录里每个待批请求都写一份。
func settle(dir, id, suffix string, all bool) (int, error) {
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
	for _, one := range ids {
		p := filepath.Join(dir, one+suffix)
		if err := os.WriteFile(p, []byte(time.Now().Format(time.RFC3339)), 0600); err != nil {
			return 0, fmt.Errorf("写 %s: %w", p, err)
		}
	}
	return len(ids), nil
}

// ApprovePending 批准一个（或 --all 全部）待批请求，返回处理的条数。
func ApprovePending(dir, id string, all bool) (int, error) { return settle(dir, id, ".approved", all) }

// DenyPending 拒绝一个（或 --all 全部）待批请求。
func DenyPending(dir, id string, all bool) (int, error) { return settle(dir, id, ".denied", all) }
