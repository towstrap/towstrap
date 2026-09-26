package server

// POST /totp/{begin,confirm,remove} —— 自助 TOTP 管理（towstrap totp /
// 注册向导走这里；SSH 里的 @totp 是另一条同效果的路）。
// 鉴权和 /token/refresh 同款：X-Agent-Token 头反查账号（token 证明持有
// 一台已登记机器）+ 请求体密码（证明是本人）；已绑账号换绑/解绑还要
// 当前动态码——对齐 SSH 管理命令的重验门槛，光偷到密码或光登上机器
// 都动不了二因素。密码/码的失败走 s.guard 和 SSH 登录共用一个锁定。
// begin 只发料不落库；confirm 验码过了才 EnrollTOTP；丢了解绑能力
// 走管理员 user totp --remove 恢复。

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/totp"
)

// totpCaller 是三个端点共用的前置鉴权：X-Agent-Token → 机器 → 账号，
// 过调用机器的 agent 来源白名单和登录锁，再验请求体里的密码。
// 返回账号名；false 表示已经回了错误。
func (s *Server) totpCaller(w http.ResponseWriter, r *http.Request, password string, deny func(int, string, string)) (accounts.Machine, bool) {
	ip := hostOnly(r.RemoteAddr)
	m, ok := s.cfg.Users.MachineByToken(r.Header.Get("X-Agent-Token"))
	if !ok {
		s.audit.Log("TOTP-DENY", "ip", ip, "reason", "token")
		deny(http.StatusUnauthorized, "token", "agent token 无效——先在机器上跑 towstrap register")
		return accounts.Machine{}, false
	}
	denyU := func(code int, reason, msg string) {
		s.audit.Log("TOTP-DENY", "user", m.Username, "ip", ip, "reason", reason)
		slog.Warn("TOTP 管理被拒", "user", m.Username, "ip", ip, "reason", reason)
		deny(code, reason, msg)
	}
	if !agentIPAllowed(m, tcpAddr(r.RemoteAddr)) {
		denyU(http.StatusForbidden, "agent-allow", "来源不在这台机器的 agent 白名单里")
		return accounts.Machine{}, false
	}
	if !s.guard.allowed(m.Username, ip) {
		denyU(http.StatusTooManyRequests, "locked", "失败次数过多，暂时锁定，稍后再试")
		return accounts.Machine{}, false
	}
	if !s.cfg.Users.Verify(m.Username, password) {
		s.guard.fail(m.Username, ip)
		denyU(http.StatusUnauthorized, "password", "密码不对或账号已停用")
		return accounts.Machine{}, false
	}
	if acct, ok := s.cfg.Users.Get(m.Username); ok && acct.OAuthOnly {
		// oauth_only = 密码不作数：TOTP 自助端点和注册通道同款口径，
		// 不然标了 oauth_only 的账号照样能用密码绑/解绑二因素。
		s.guard.fail(m.Username, ip)
		denyU(http.StatusForbidden, "oauth-only", "这个账号标记了 oauth_only：密码在这类接口上不作数——TOTP 管理请走 SSH @totp（完整登录）或找管理员")
		return accounts.Machine{}, false
	}
	return m, true
}

// totpBound 已绑账号换绑/解绑的加码检查：当前动态码必须对得上。
func (s *Server) totpBound(m accounts.Machine, code, ip string, denyU func(int, string, string)) bool {
	acct, ok := s.cfg.Users.Get(m.Username)
	if !ok || !acct.TOTPEnabled {
		return true
	}
	if code == "" {
		denyU(http.StatusForbidden, "need-code", "账号已绑 TOTP，操作要当前 6 位动态码")
		return false
	}
	if !s.cfg.Users.VerifyTOTP(m.Username, strings.TrimSpace(code)) {
		s.guard.fail(m.Username, ip)
		denyU(http.StatusUnauthorized, "totp", "当前动态码不对")
		return false
	}
	return true
}

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	fail := func(code int, _, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(proto.TOTPBeginResp{Err: msg})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed, "method", "只收 POST")
		return
	}
	var req proto.TOTPBeginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, registerMaxBody)).Decode(&req); err != nil {
		fail(http.StatusBadRequest, "bad-json", registerBodyErr)
		return
	}
	m, ok := s.totpCaller(w, r, req.Password, fail)
	if !ok {
		return
	}
	ip := hostOnly(r.RemoteAddr)
	acct, _ := s.cfg.Users.Get(m.Username)
	bound := acct.TOTPEnabled
	// 已绑账号在 begin 就要先验当前码——发新秘钥原料本身就是换绑的
	// 第一步，只凭密码放行等于给「偷到密码的人」留了换绑通道。
	// 注意：这里 **不** 调 guard.pass——begin 只验证了密码，完整认证
	// 链（密码+动态码）还没走完，清零会把前面的失败计数抹掉，给
	// 「密码+一次 begin」每轮刷新的爆破口。
	if bound && req.OldCode == "" {
		s.audit.Log("TOTP-DENY", "user", m.Username, "ip", ip, "reason", "need-code")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(proto.TOTPBeginResp{
			Err: "账号已绑 TOTP，换绑要当前 6 位动态码（old_code）", NeedCode: true, Bound: true, Account: m.Username,
		})
		return
	}
	if bound {
		// 用 CheckTOTP 而不是 VerifyTOTP：这里只验身份不消费时间片，
		// 真正消费是 confirm 落库那次——同一个流程里这个码要被验两次。
		if !s.cfg.Users.CheckTOTP(m.Username, strings.TrimSpace(req.OldCode)) {
			s.guard.fail(m.Username, ip)
			s.audit.Log("TOTP-DENY", "user", m.Username, "ip", ip, "reason", "totp")
			fail(http.StatusUnauthorized, "totp", "当前动态码不对")
			return
		}
	}
	secret, uri := totp.Generate("towstrap", m.Username)
	// 不落库、不写审计成功项——begin 只是发料，confirm 过了才算数。
	_ = json.NewEncoder(w).Encode(proto.TOTPBeginResp{
		Secret: totp.SecretString(secret), URI: uri,
		Bound: bound, Account: m.Username,
	})
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	fail := func(code int, _, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(proto.TOTPConfirmResp{Err: msg})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed, "method", "只收 POST")
		return
	}
	var req proto.TOTPConfirmReq
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
		s.audit.Log("TOTP-ENROLL-DENY", "user", m.Username, "ip", ip, "reason", reason)
		fail(code, reason, msg)
	}
	// 换绑要先用旧码证明还是本人——不然偷到密码就能把验证器换成自己的。
	if !s.totpBound(m, req.OldCode, ip, denyU) {
		return
	}
	secret, err := totp.ParseSecret(req.Secret)
	if err != nil || len(secret) != 20 {
		denyU(http.StatusBadRequest, "bad-secret", "秘钥不对——重新走绑定流程")
		return
	}
	step, ok := totp.Verify(secret, strings.TrimSpace(req.Code), 0, time.Now())
	if !ok {
		denyU(http.StatusBadRequest, "bad-code", "验证码不对或过期了，输验证器上现在的 6 位码")
		return
	}
	if err := s.cfg.Users.EnrollTOTP(m.Username, secret, step); err != nil {
		denyU(http.StatusInternalServerError, "store", "绑定写入失败")
		return
	}
	s.guard.pass(m.Username, ip)
	s.audit.Log("TOTP-ENROLL", "account", m.Username, "ip", ip)
	slog.Info("TOTP 自助绑定", "account", m.Username, "ip", ip)
	_ = json.NewEncoder(w).Encode(proto.TOTPConfirmResp{OK: true})
}

func (s *Server) handleTOTPRemove(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	needCode := false
	fail := func(code int, reason, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(proto.TOTPRemoveResp{Err: msg, NeedCode: needCode})
		_ = reason
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed, "method", "只收 POST")
		return
	}
	var req proto.TOTPRemoveReq
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
		s.audit.Log("TOTP-REMOVE-DENY", "user", m.Username, "ip", ip, "reason", reason)
		fail(code, reason, msg)
	}
	// 已绑账号没给码时回 need_code，客户端补问后重发。
	if acct, ok2 := s.cfg.Users.Get(m.Username); ok2 && acct.TOTPEnabled && req.Code == "" {
		needCode = true
		denyU(http.StatusForbidden, "need-code", "账号已绑 TOTP，解绑要当前 6 位动态码")
		return
	}
	if !s.totpBound(m, req.Code, ip, denyU) {
		return
	}
	if err := s.cfg.Users.RemoveTOTP(m.Username); err != nil {
		denyU(http.StatusInternalServerError, "store", "解绑写入失败")
		return
	}
	s.guard.pass(m.Username, ip)
	s.audit.Log("TOTP-REMOVE", "user", m.Username, "ip", ip)
	slog.Info("TOTP 自助解绑", "account", m.Username, "ip", ip)
	_ = json.NewEncoder(w).Encode(proto.TOTPRemoveResp{OK: true})
}
