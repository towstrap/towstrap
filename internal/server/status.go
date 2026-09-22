package server

import (
	"encoding/json"
	"net/http"

	"towstrap/internal/auth"
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
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.statusReport(r)
	if !ok {
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
func (s *Server) statusReport(r *http.Request) (StatusReport, bool) {
	if s.cfg.AdminToken != "" && auth.Equal(r.Header.Get("X-Admin-Token"), s.cfg.AdminToken) {
		return s.Snapshot(), true
	}
	m, ok := s.cfg.Users.MachineByToken(r.Header.Get("X-Agent-Token"))
	if !ok {
		return StatusReport{}, false
	}
	rep := StatusReport{HTTP: s.cfg.HTTPAddr, SSH: s.cfg.SSHAddr}
	on := s.Hub.Has(m.ID())
	rep.Users = []UserStatus{{User: m.Username, Machine: m.ID(), Online: on}}
	rep.OK = on
	return rep, true
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
	return rep
}
