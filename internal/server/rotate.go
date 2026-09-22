package server

// POST /token/refresh：在 agent 机器上发起的 token 换发。
// 鉴权 = 调用方机器的 agent token（证明在一台已登记机器上）+ 账号密码 +
// TOTP（证明是账号主人）。新 token 走目标 agent 现有的 WebSocket 连接
// 下推，agent 写进自己的 token 文件回 ack 后才落库——没 ack 就不换。

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"towstrap/internal/accounts"
	"towstrap/internal/allow"
)

type refreshReq struct {
	Password string   `json:"password"`
	TOTP     string   `json:"totp"`
	Machines []string `json:"machines"`
	All      bool     `json:"all"`
}

type refreshResult struct {
	Machine string `json:"machine"`
	Status  string `json:"status"` // ok / offline / no-file / timeout / not-found / error
	Detail  string `json:"detail,omitempty"`
}

// rotateTimeout 等 agent ack 的时长：写个本地文件是毫秒级的事，超时基本
// 就是 agent 卡了或消息丢了。
const rotateTimeout = 10 * time.Second

func (s *Server) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	ip := hostOnly(r.RemoteAddr)
	deny := func(code int, reason, msg string) {
		s.audit.Log("TOKEN-REFRESH-DENY", "ip", ip, "reason", reason)
		http.Error(w, msg, code)
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		deny(http.StatusBadRequest, "content-type", "需要 application/json")
		return
	}
	caller, ok := s.cfg.Users.MachineByToken(r.Header.Get("X-Agent-Token"))
	if !ok {
		deny(http.StatusUnauthorized, "token", "agent token 无效")
		return
	}
	account := caller.Username
	denyUser := func(code int, reason, msg string) {
		s.audit.Log("TOKEN-REFRESH-DENY", "user", account, "ip", ip, "reason", reason)
		http.Error(w, msg, code)
	}
	// 调用方机器设了 agent 来源白名单时，这个接口也只认名单里的来源。
	if len(caller.AgentAllowIPs) > 0 {
		list, err := allow.Parse(caller.AgentAllowIPs)
		if err != nil || !list.AllowsAddr(tcpAddr(r.RemoteAddr)) {
			denyUser(http.StatusForbidden, "agent-allow", "来源不在调用机器的 agent 白名单里")
			return
		}
	}
	if !s.guard.allowed(account, ip) {
		denyUser(http.StatusTooManyRequests, "locked", "失败次数过多，暂时锁定，稍后再试")
		return
	}
	var req refreshReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		denyUser(http.StatusBadRequest, "body", "请求体不是合法 JSON")
		return
	}
	if !s.cfg.Users.Verify(account, req.Password) {
		s.guard.fail(account, ip)
		denyUser(http.StatusUnauthorized, "password", "密码不对或账号已停用")
		return
	}
	if acct, ok := s.cfg.Users.Get(account); ok && acct.TOTPEnabled {
		if !s.cfg.Users.VerifyTOTP(account, req.TOTP) {
			s.guard.fail(account, ip)
			denyUser(http.StatusUnauthorized, "totp", "验证码不对")
			return
		}
	}
	s.guard.pass(account, ip)

	// 目标机器集合：--all 全账号；否则点名列表（机器名，不带账号前缀）；
	// 都不给就只换调用方自己这台。
	var names []string
	if req.All {
		for _, m := range s.cfg.Users.Machines(account) {
			names = append(names, m.Name)
		}
	} else if len(req.Machines) > 0 {
		names = req.Machines
	} else {
		names = []string{caller.Name}
	}

	from := "agent:" + caller.ID() + "@" + ip
	results := make([]refreshResult, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		id := account + "+" + name
		if seen[id] {
			continue
		}
		seen[id] = true
		res := refreshResult{Machine: id}
		if _, exists := s.cfg.Users.GetMachine(account, name); !exists {
			res.Status, res.Detail = "not-found", "机器不存在"
		} else if agent, err := s.Hub.Agent(id); err != nil {
			res.Status, res.Detail = "offline", "agent 不在线"
		} else {
			newTok := accounts.NewAgentToken()
			switch err := s.Hub.RotateToken(agent, newTok, rotateTimeout); {
			case err == nil:
				if err := s.cfg.Users.SetMachineToken(account, name, newTok); err != nil {
					// agent 文件已是新 token 但库里没换：两边不一致，
					// 必须人工处理——这条告警要醒目。
					slog.Error("TOKEN 换发不一致：agent 已写新 token 但数据库更新失败，需人工处理",
						"machine", id, "err", err)
					res.Status, res.Detail = "error", "agent 已写入新 token 但服务器更新数据库失败，需人工处理"
				} else {
					agent.setToken(newTok)
					res.Status, res.Detail = "ok", "新 token 已写入该机器的 token 文件"
				}
			case err.Error() == "timeout":
				res.Status, res.Detail = "timeout", "agent 没有在时限内确认"
			case strings.Contains(err.Error(), "不是从文件读"):
				res.Status, res.Detail = "no-file", "该机器的 token 不是从文件读的，无法远程更换"
			default:
				res.Status, res.Detail = "error", err.Error()
			}
		}
		s.audit.Log("TOKEN-REFRESH", "user", account, "machine", res.Machine,
			"from", from, "status", res.Status)
		results = append(results, res)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
}
