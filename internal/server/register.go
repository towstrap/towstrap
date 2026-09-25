package server

// POST /register 自助注册：agent 跑 `towstrap register` 时打这里，建账号+
// 机器+发 agent token。server.yaml 里 register: true 才开；register_invite
// 设了要带上邀请码。同一机器指纹只许注册一个账号；每来源 IP 限速防刷。

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/proto"
)

const (
	registerMaxBody   = 4 << 10   // 注册请求体上限，够小了
	registerPerIPMax  = 8         // 每 IP 每小时允许的注册数
	registerPerIPSpan = time.Hour //
	registerBodyErr   = "请求体不是合法 JSON"
)

// registerRL 是按来源 IP 的内存滑动窗口限速器。注册是低频动作，
// 进程重启清零就够用，不进库。
type registerRL struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (r *registerRL) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hits == nil {
		r.hits = map[string][]time.Time{}
	}
	now := time.Now()
	cutoff := now.Add(-registerPerIPSpan)
	keep := r.hits[ip][:0]
	for _, t := range r.hits[ip] {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= registerPerIPMax {
		r.hits[ip] = keep
		return false
	}
	r.hits[ip] = append(keep, now)
	return true
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(proto.RegisterResp{Err: msg})
	}
	ip := ""
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = h
	}
	deny := func(code int, reason, msg string) {
		s.audit.Log("REGISTER-DENY", "ip", ip, "reason", reason)
		slog.Warn("注册被拒", "ip", ip, "reason", reason)
		fail(code, msg)
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		deny(http.StatusMethodNotAllowed, "method", "只收 POST")
		return
	}
	if !s.cfg.Register {
		deny(http.StatusForbidden, "disabled", "这台服务器没开自助注册；找管理员要账号")
		return
	}
	if !s.regRL.allow(ip) {
		deny(http.StatusTooManyRequests, "rate", "这个地址注册太频繁了，一小时后再试")
		return
	}

	var req proto.RegisterReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, registerMaxBody)).Decode(&req); err != nil {
		deny(http.StatusBadRequest, "bad-json", registerBodyErr)
		return
	}
	if s.cfg.RegisterInvite != "" && req.Invite != s.cfg.RegisterInvite {
		deny(http.StatusForbidden, "invite", "邀请码不对（服务器设了 register_invite，注册要带 --invite）")
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	if !proto.ValidName(req.Account) {
		deny(http.StatusBadRequest, "bad-name", "账号名不合法：只能用字母、数字、点、下划线和短横线")
		return
	}
	if !isHexFingerprint(req.Fingerprint) {
		deny(http.StatusBadRequest, "no-fp", "缺机器指纹（升级 towstrap 到带注册的版本）")
		return
	}

	// 指纹先查：已绑过的机器直接 409，把既有账号名回给它做找回提示。
	if owner, err := s.cfg.Users.FingerprintAccount(req.Fingerprint); err == nil && owner != "" {
		s.audit.Log("REGISTER-DENY", "ip", ip, "reason", "fp-taken", "owner", owner)
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(proto.RegisterResp{
			Err:   "这台机器已注册过",
			Owner: owner,
		})
		return
	}

	// 先占指纹再建账号：反过来先建号再占坑，并发下同指纹两个不同账号
	// 都能建出来（只有一个绑得上）。占完建失败要回滚绑定。
	ok, err := s.cfg.Users.BindFingerprint(req.Fingerprint, req.Account)
	if err != nil {
		deny(http.StatusInternalServerError, "store", "账号库写入失败")
		return
	}
	if !ok {
		owner, _ := s.cfg.Users.FingerprintAccount(req.Fingerprint)
		s.audit.Log("REGISTER-DENY", "ip", ip, "reason", "fp-taken", "owner", owner)
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(proto.RegisterResp{Err: "这台机器已注册过", Owner: owner})
		return
	}
	acct, err := s.cfg.Users.Add(req.Account, req.Password, nil, "self-register:"+ip, nil)
	if err != nil {
		_ = s.cfg.Users.ReleaseFingerprint(req.Fingerprint, req.Account)
		code := http.StatusInternalServerError
		switch {
		case errors.Is(err, accounts.ErrExists):
			code = http.StatusConflict
		case strings.Contains(err.Error(), "密码"):
			code = http.StatusBadRequest
		}
		deny(code, "add", err.Error())
		return
	}

	machine := acct.Machines[0]
	token := machine.Token
	// 自定义机器名：Add 顺手建的 default 没人用（token 没处交付），换成
	// 请求里的名字后把它删掉，别留一台谁都登不上的机器。
	if req.Machine != "" && req.Machine != accounts.DefaultMachine && proto.ValidName(req.Machine) {
		if m2, err := s.cfg.Users.AddMachine(req.Account, req.Machine, nil); err == nil {
			machine, token = m2, m2.Token
			_ = s.cfg.Users.RemoveMachine(req.Account, accounts.DefaultMachine)
		}
	}

	s.audit.Log("REGISTER", "account", req.Account, "machine", machine.ID(), "ip", ip)
	slog.Info("自助注册", "account", req.Account, "machine", machine.ID(), "ip", ip)
	_ = json.NewEncoder(w).Encode(proto.RegisterResp{
		Token:   token,
		Account: req.Account,
		Machine: machine.ID(),
		SSHPort: s.sshPort(),
	})
}

// isHexFingerprint 校验指纹是 64 位十六进制（SHA256 的外形），挡住明显
// 不是哈希的乱填值。
func isHexFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, c := range fp {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// handleMachineRegister 是 POST /register/machine：已有账号的"登录加机"——
// 账号+密码验证后把这台机器挂到名下拿 token。和 SSH 登录后 @machine add
// 等价，所以不受 register: 开关管（register 只管建新账号）；照样吃每 IP
// 限速，防拿它当密码爆破口。机器名已存在视为重装：换新 token（旧 token
// 作废）。指纹已绑别的账号 → 409。
func (s *Server) handleMachineRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(proto.RegisterResp{Err: msg})
	}
	ip := ""
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = h
	}
	deny := func(code int, reason, msg string) {
		s.audit.Log("MACHINE-REGISTER-DENY", "ip", ip, "reason", reason)
		slog.Warn("登录加机被拒", "ip", ip, "reason", reason)
		fail(code, msg)
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		deny(http.StatusMethodNotAllowed, "method", "只收 POST")
		return
	}
	if !s.regRL.allow(ip) {
		deny(http.StatusTooManyRequests, "rate", "操作太频繁了，一小时后再试")
		return
	}

	var req proto.RegisterReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, registerMaxBody)).Decode(&req); err != nil {
		deny(http.StatusBadRequest, "bad-json", registerBodyErr)
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	if !proto.ValidName(req.Account) || req.Password == "" {
		deny(http.StatusBadRequest, "bad-name", "账号名/密码不对")
		return
	}
	if !isHexFingerprint(req.Fingerprint) {
		deny(http.StatusBadRequest, "no-fp", "缺机器指纹（升级 towstrap 到带注册的版本）")
		return
	}

	// 先验密码：指纹/机器的归属信息不能漏给没通过认证的人。
	if !s.cfg.Users.Verify(req.Account, req.Password) {
		deny(http.StatusForbidden, "auth", "账号名或密码不对")
		return
	}

	// 指纹归属：绑了别的账号拒；没绑过就占下（占失败=并发被抢，按冲突处理）。
	owner, _ := s.cfg.Users.FingerprintAccount(req.Fingerprint)
	if owner != "" && owner != req.Account {
		s.audit.Log("MACHINE-REGISTER-DENY", "ip", ip, "reason", "fp-taken", "owner", owner)
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(proto.RegisterResp{Err: "这台机器已绑到别的账号", Owner: owner})
		return
	}
	if owner == "" {
		ok, err := s.cfg.Users.BindFingerprint(req.Fingerprint, req.Account)
		if err != nil {
			deny(http.StatusInternalServerError, "store", "账号库写入失败")
			return
		}
		if !ok {
			owner, _ = s.cfg.Users.FingerprintAccount(req.Fingerprint)
			s.audit.Log("MACHINE-REGISTER-DENY", "ip", ip, "reason", "fp-taken", "owner", owner)
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(proto.RegisterResp{Err: "这台机器已绑到别的账号", Owner: owner})
			return
		}
	}

	machine := req.Machine
	if machine == "" {
		machine = accounts.DefaultMachine
	}
	if !proto.ValidName(machine) {
		deny(http.StatusBadRequest, "bad-machine", "机器名不合法")
		return
	}
	var token string
	if _, exists := s.cfg.Users.GetMachine(req.Account, machine); exists {
		// 同名机器已存在 = 这台机器重装/重注册：换发新 token，旧的作废。
		tok, err := s.cfg.Users.RegenMachineToken(req.Account, machine)
		if err != nil {
			deny(http.StatusInternalServerError, "store", "换 token 失败")
			return
		}
		token = tok
	} else {
		m2, err := s.cfg.Users.AddMachine(req.Account, machine, nil)
		if err != nil {
			deny(http.StatusInternalServerError, "store", "建机器失败")
			return
		}
		token = m2.Token
	}

	s.audit.Log("MACHINE-REGISTER", "account", req.Account, "machine", req.Account+"+"+machine, "ip", ip)
	slog.Info("登录加机", "account", req.Account, "machine", req.Account+"+"+machine, "ip", ip)
	_ = json.NewEncoder(w).Encode(proto.RegisterResp{
		Token:   token,
		Account: req.Account,
		Machine: req.Account + "+" + machine,
		SSHPort: s.sshPort(),
	})
}
