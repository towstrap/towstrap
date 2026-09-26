package server

// POST /passwd —— 自助改 SSH/登录密码（towstrap passwd 走这里）。
// 鉴权和 /totp/* 同一条链（totpCaller）：X-Agent-Token 反查账号 + 请求体
// 旧密码证明本人 + agent 来源白名单 + 登录锁；已绑 TOTP 的账号还要当前
// 动态码——光偷到密码不能把锁换掉。改完走 accounts.SetPassword 重新
// bcrypt 落库，旧哈希即刻作废（进行中的 SSH 会话不受影响）。

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/towstrap/towstrap/internal/proto"
)

func (s *Server) handlePasswd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	needCode := false
	fail := func(code int, _, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(proto.PasswdResp{Err: msg, NeedCode: needCode})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed, "method", "只收 POST")
		return
	}
	var req proto.PasswdReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, registerMaxBody)).Decode(&req); err != nil {
		fail(http.StatusBadRequest, "bad-json", registerBodyErr)
		return
	}
	ip := hostOnly(r.RemoteAddr)
	m, ok := s.totpCaller(w, r, req.Password, fail)
	if !ok {
		return
	}
	denyU := func(code int, reason, msg string) {
		s.audit.Log("PASSWD-DENY", "user", m.Username, "ip", ip, "reason", reason)
		slog.Warn("改密码被拒", "user", m.Username, "ip", ip, "reason", reason)
		fail(code, reason, msg)
	}
	// 已绑账号没给码时回 need_code，客户端补问后重发。
	if acct, ok2 := s.cfg.Users.Get(m.Username); ok2 && acct.TOTPEnabled && req.Code == "" {
		needCode = true
		denyU(http.StatusForbidden, "need-code", "账号已绑 TOTP，改密码要当前 6 位动态码")
		return
	}
	if !s.totpBound(m, req.Code, ip, denyU) {
		return
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		denyU(http.StatusBadRequest, "new-password", "新密码不能为空")
		return
	}
	if err := s.cfg.Users.SetPassword(m.Username, req.NewPassword); err != nil {
		denyU(http.StatusBadRequest, "new-password", "新密码不合格："+err.Error())
		return
	}
	s.guard.pass(m.Username, ip)
	s.audit.Log("PASSWD", "account", m.Username, "ip", ip)
	slog.Info("自助改密码", "account", m.Username, "ip", ip)
	_ = json.NewEncoder(w).Encode(proto.PasswdResp{OK: true})
}
