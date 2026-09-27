package server

// POST /sshkey —— 自助公钥管理（towstrap ssh-key 走这里；SSH 会话里的
// @sshkey 是同效果的另一条路）。
// 鉴权和 /passwd 同一条链（totpCaller）：X-Agent-Token 反查账号 + 请求体
// 密码证明本人 + agent 来源白名单 + 登录锁 + oauth_only 拦截；已绑 TOTP
// 的账号再要一道当前动态码——光偷到密码不能给账号多挂一把钥匙。
// action：list 列已登记公钥 / add 登记一把（authorized_keys 行）/
// remove 删一把（公钥行或 SHA256 指纹）。加钥匙=多开一扇门，所以
// add/remove 和密码变更同级看护。

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/proto"
)

// sshKeyInfo 把库里存的 authorized_keys 行拆成展示信息；解析不了的行
// 原样回（指纹留空），不让一条坏行毁掉整个列表。
func sshKeyInfo(line string) proto.SSHKeyInfo {
	pk, comment, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return proto.SSHKeyInfo{Line: line}
	}
	return proto.SSHKeyInfo{
		Fingerprint: gossh.FingerprintSHA256(pk),
		Comment:     comment,
		Line:        strings.TrimSpace(line),
	}
}

func (s *Server) handleSSHKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	needCode := false
	fail := func(code int, _, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(proto.SSHKeyResp{Err: msg, NeedCode: needCode})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed, "method", "只收 POST")
		return
	}
	var req proto.SSHKeyReq
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
		s.audit.Log("SSHKEY-DENY", "user", m.Username, "ip", ip, "action", req.Action, "reason", reason)
		slog.Warn("公钥管理被拒", "user", m.Username, "ip", ip, "action", req.Action, "reason", reason)
		fail(code, reason, msg)
	}
	// 已绑账号没给码时回 need_code，客户端补问后重发。
	if acct, ok2 := s.cfg.Users.Get(m.Username); ok2 && acct.TOTPEnabled && req.Code == "" {
		needCode = true
		denyU(http.StatusForbidden, "need-code", "账号已绑 TOTP，公钥管理要当前 6 位动态码")
		return
	}
	if !s.totpBound(m, req.Code, ip, denyU) {
		return
	}
	switch req.Action {
	case "list":
		acct, _ := s.cfg.Users.Get(m.Username)
		var keys []proto.SSHKeyInfo
		for _, line := range acct.SSHKeys {
			keys = append(keys, sshKeyInfo(line))
		}
		_ = json.NewEncoder(w).Encode(proto.SSHKeyResp{OK: true, Keys: keys})
	case "add":
		if strings.TrimSpace(req.Key) == "" {
			denyU(http.StatusBadRequest, "key", "没带公钥")
			return
		}
		if err := s.cfg.Users.AddSSHKey(m.Username, req.Key); err != nil {
			if errors.Is(err, accounts.ErrBadInput) {
				denyU(http.StatusBadRequest, "key", err.Error())
			} else {
				denyU(http.StatusInternalServerError, "store", "公钥写入失败")
			}
			return
		}
		fp := sshKeyInfo(req.Key).Fingerprint
		s.guard.pass(m.Username, ip)
		s.audit.Log("SSHKEY-ADD", "user", m.Username, "ip", ip, "fp", fp)
		slog.Info("自助登记公钥", "user", m.Username, "ip", ip, "fp", fp)
		_ = json.NewEncoder(w).Encode(proto.SSHKeyResp{OK: true})
	case "remove":
		if strings.TrimSpace(req.Key) == "" {
			denyU(http.StatusBadRequest, "key", "没给要删的公钥或指纹")
			return
		}
		if err := s.cfg.Users.RemoveSSHKey(m.Username, req.Key); err != nil {
			if errors.Is(err, accounts.ErrNotFound) || errors.Is(err, accounts.ErrBadInput) {
				denyU(http.StatusBadRequest, "key", err.Error())
			} else {
				denyU(http.StatusInternalServerError, "store", "公钥删除失败")
			}
			return
		}
		s.guard.pass(m.Username, ip)
		s.audit.Log("SSHKEY-REMOVE", "user", m.Username, "ip", ip, "key", auditCmd(req.Key))
		slog.Info("自助删除公钥", "user", m.Username, "ip", ip)
		_ = json.NewEncoder(w).Encode(proto.SSHKeyResp{OK: true})
	default:
		denyU(http.StatusBadRequest, "action", "action 只认 list/add/remove")
	}
}
