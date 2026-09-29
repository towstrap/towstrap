package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/towstrap/towstrap/internal/auth"
)

type UserStatus struct {
	User     string `json:"user"`    // 账号名
	Machine  string `json:"machine"` // 机器完整 ID（账号+机器名）
	Online   bool   `json:"online"`
	Disabled bool   `json:"disabled,omitempty"`
}

type StatusReport struct {
	OK    bool         `json:"ok"`
	HTTP  string       `json:"http"`
	SSH   string       `json:"ssh"`
	Users []UserStatus `json:"users"`
	// 以下仅 Snapshot（管理口令路径）填，机器 token 的窄视图不给这些全局量。
	UptimeS        int64 `json:"uptime_s,omitempty"`
	SessionsActive int64 `json:"sessions_active,omitempty"`
	AuthOK         int64 `json:"auth_ok,omitempty"`
	AuthFail       int64 `json:"auth_fail,omitempty"`
	RelayToAgent   int64 `json:"relay_to_agent,omitempty"`
	RelayFromAgent int64 `json:"relay_from_agent,omitempty"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	rep, ok, locked := s.statusReport(r)
	switch {
	case locked:
		http.Error(w, "locked", http.StatusTooManyRequests)
		return
	case !ok:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !rep.OK {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(rep)
}

// statusReport 决定看什么：管理口令看全量；机器 token 只看自己那一台
// （普通用户没有枚举整个机群的道理，那是信息泄露）。
// 第三个返回值是「来源 IP 已锁」：错试管理口令/机器 token 记进匿名端点
// 的独立预算——/status 零凭据可达，刷它不能烧掉 SSH/登录的 IP 预算。
func (s *Server) statusReport(r *http.Request) (StatusReport, bool, bool) {
	ip := hostOnly(r.RemoteAddr)
	if !s.guard.ipAllowedAnon(ip) {
		return StatusReport{}, false, true
	}
	if tok := r.Header.Get("X-Admin-Token"); tok != "" {
		if s.cfg.AdminToken != "" && auth.Equal(tok, s.cfg.AdminToken) {
			return s.Snapshot(), true, false
		}
		s.guard.failIPAnon(ip)
		s.audit.Log("STATUS-DENY", "ip", ip, "reason", "admin-token")
		return StatusReport{}, false, false
	}
	m, ok := s.cfg.Users.MachineByToken(r.Header.Get("X-Agent-Token"))
	if !ok {
		s.guard.failIPAnon(ip)
		return StatusReport{}, false, false
	}
	// 机器设了 agent 来源白名单就只认名单里的来源（和 /agent、
	// /token/refresh、/totp/*、/oauth/* 同一条闸门）。
	if !agentIPAllowed(m, tcpAddr(r.RemoteAddr)) {
		return StatusReport{}, false, false
	}
	rep := StatusReport{HTTP: s.cfg.HTTPAddr, SSH: s.cfg.SSHAddr}
	on := s.Hub.Has(m.ID())
	rep.Users = []UserStatus{{User: m.Username, Machine: m.ID(), Online: on}}
	rep.OK = on
	return rep, true, false
}

func (s *Server) Snapshot() StatusReport {
	rep := StatusReport{HTTP: s.cfg.HTTPAddr, SSH: s.cfg.SSHAddr, OK: true}
	online := 0
	// ListMachinesBasic 不解密 token——高频路径别为每台机器跑一遍 AES。
	for _, b := range s.cfg.Users.ListMachinesBasic() {
		on := s.Hub.Has(b.ID)
		if on {
			online++
		}
		rep.Users = append(rep.Users, UserStatus{User: b.Username, Machine: b.ID, Online: on, Disabled: b.Disabled})
	}
	rep.OK = online > 0
	rep.UptimeS = int64(time.Since(s.started) / time.Second)
	rep.SessionsActive = s.Hub.SessionCount()
	rep.AuthOK = s.authOK.Load()
	rep.AuthFail = s.authFail.Load()
	rep.RelayToAgent = s.Hub.BytesToAgent()
	rep.RelayFromAgent = s.Hub.BytesFromAgent()
	return rep
}
