package server

// OAuth/OIDC 接入：agent 调 /oauth/request 拿一条授权链接交给机器前的用户，
// 用户在浏览器里打开 → /oauth/begin 302 到 IdP → IdP 回调 /oauth/callback
// 验身份 → 预先绑定的身份匹配上就给这台机器发一个短时效 SSH 凭据 → agent
// 轮询 /oauth/result 取回凭据展示给用户。
//
// 凭据落库走 accounts.CreateSSHGrant（库里只存 bcrypt），SSH 登录时在密码
// 校验里消费。audit 只记机器/身份标识，不记 code、token、secret。

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/oidc"
)

// OAuthConfig 对应 server.yaml 的 oauth: 小节。Issuer/ClientID/ClientSecret
// 必填；RedirectURL 空 = 按 public_url（再不然按请求 Host）推导
// <base>/oauth/callback。
type OAuthConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       string // 默认 "openid email"
}

// oauthPending 是一笔进行中的授权：agent 要链接时建，回调成功后挂上
// 一次性 SSH 凭据，agent 取走即删。
type oauthPending struct {
	id       string
	machine  string // 完整机器名 alice+default
	username string // 机器所属账号
	state    string // /oauth/begin 第一次被打开时生成
	nonce    string
	expires  time.Time
	done     bool
	failed   string // done 后非空 = 失败原因
	secret   string // done 后成功时的 SSH 凭据（被取走后随条目一起删）
}

const (
	oauthPendingTTL   = 5 * time.Minute // 授权链接有效期
	oauthPendMax      = 512             // 全局在册授权上限（防刷爆内存）
	oauthPendPerMach  = 3               // 每台机器同时挂起的授权数
	oauthProvErrRetry = time.Minute     // IdP 发现失败后的重试间隔
)

// oauthFlow 持有 OIDC 提供方（懒初始化）和全部进行中的授权。
// redirect_uri 不记忆：没配 redirect_url/public_url 时按每次请求各自
// 推导——首个请求把它钉死的话，谁抢到第一次谁就能把所有人的回调
// 指到自己的域名（审计证实：宽容 IdP 会真把 code 送去）。
type oauthFlow struct {
	s *Server

	mu        sync.Mutex
	prov      *oidc.Provider
	provErrAt time.Time // 上次发现失败的时间；一分钟内不重复打 IdP
	pend      map[string]*oauthPending
	byState   map[string]*oauthPending
}

func newOAuthFlow(s *Server) *oauthFlow {
	return &oauthFlow{
		s:       s,
		pend:    map[string]*oauthPending{},
		byState: map[string]*oauthPending{},
	}
}

func randURL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// oauthBase 推导对外可达的 HTTP 基址：redirect_url 的 origin > public_url
// （ws→http）> 请求 Host。浏览器打开的链接和 IdP 回调都用它。
func (f *oauthFlow) oauthBase(r *http.Request) string {
	if f.s.cfg.OAuth.RedirectURL != "" {
		if u, err := url.Parse(f.s.cfg.OAuth.RedirectURL); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
		return strings.TrimSuffix(f.s.cfg.OAuth.RedirectURL, "/")
	}
	if f.s.cfg.PublicURL != "" {
		base := f.s.cfg.PublicURL
		if strings.HasPrefix(base, "wss://") {
			return "https://" + base[len("wss://"):]
		}
		return "http://" + strings.TrimPrefix(base, "ws://")
	}
	scheme := "http"
	if r != nil && r.TLS != nil {
		scheme = "https"
	}
	// Host 头是客户端给的，redirect_uri 会带去 IdP——只认干净主机名，
	// 不干净的退回监听地址（让管理员配 public_url 才是正道）。
	if r != nil {
		if host := cleanHost(r.Host); host != "" {
			return scheme + "://" + host
		}
	}
	return "http://" + f.s.cfg.HTTPAddr
}

// provider 懒初始化 OIDC 发现；失败结果缓存一分钟，避免每个回调都去
// 打挂掉的 IdP。返回的 Provider 已按本次请求套上 redirect_uri。
func (f *oauthFlow) provider(r *http.Request) (*oidc.Provider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.provErrAt) < oauthProvErrRetry {
		return nil, fmt.Errorf("IdP 发现暂不可用")
	}
	if f.prov == nil {
		cfg := f.s.cfg.OAuth
		p, err := oidc.Discover(r.Context(), oidc.Config{
			Issuer:       cfg.Issuer,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       cfg.Scopes,
		})
		if err != nil {
			f.provErrAt = time.Now()
			return nil, err
		}
		f.prov = p
	}
	return f.prov.WithRedirect(f.oauthBase(r) + "/oauth/callback"), nil
}

// sweep 清掉过期的授权条目（随请求惰性执行，不起后台协程）。
func (f *oauthFlow) sweepLocked(now time.Time) {
	for id, p := range f.pend {
		if now.After(p.expires) {
			delete(f.pend, id)
			if p.state != "" {
				delete(f.byState, p.state)
			}
		}
	}
}

// handleOAuthRequest 是 agent 的入口：POST + X-Agent-Token，返回授权链接。
func (s *Server) handleOAuthRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m, ok := s.cfg.Users.MachineByToken(r.Header.Get("X-Agent-Token"))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// 和 /token/refresh、/totp/* 同一条闸门：这台机器设了 agent 来源
	// 白名单就也约束 OAuth 发起——token 挪到名单外的来源用一样拒。
	if !agentIPAllowed(m, tcpAddr(r.RemoteAddr)) {
		s.audit.Log("OAUTH-DENY", "machine", m.ID(), "ip", hostOnly(r.RemoteAddr), "reason", "agent-allow")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	f := s.oauth
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(time.Now())
	perMachine := 0
	for _, p := range f.pend {
		if p.machine == m.ID() {
			perMachine++
		}
	}
	if perMachine >= oauthPendPerMach || len(f.pend) >= oauthPendMax {
		s.audit.Log("OAUTH-DENY", "machine", m.ID(), "ip", hostOnly(r.RemoteAddr),
			"reason", "too-many-pending")
		http.Error(w, "too many pending authorizations", http.StatusTooManyRequests)
		return
	}
	p := &oauthPending{
		id:       "oar-" + randURL(18),
		machine:  m.ID(),
		username: m.Username,
		expires:  time.Now().Add(oauthPendingTTL),
	}
	f.pend[p.id] = p
	s.audit.Log("OAUTH-REQUEST", "machine", m.ID(), "ip", hostOnly(r.RemoteAddr))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"request_id": p.id,
		"url":        f.oauthBase(r) + "/oauth/begin?r=" + p.id,
		"expires_in": int(oauthPendingTTL / time.Second),
	})
}

// handleOAuthBegin 是浏览器打开的入口：校验请求在册且没过期，生成
// state/nonce，302 到 IdP 授权页。
func (s *Server) handleOAuthBegin(w http.ResponseWriter, r *http.Request) {
	f := s.oauth
	f.mu.Lock()
	p := f.pend[r.URL.Query().Get("r")]
	if p == nil || time.Now().After(p.expires) || p.done {
		f.mu.Unlock()
		f.oauthPage(w, http.StatusGone, "链接已失效", "这条授权链接不存在或已过期，请回到终端重新发起。")
		return
	}
	if p.state == "" {
		p.state = "st-" + randURL(18)
		p.nonce = randURL(18)
		f.byState[p.state] = p
	}
	state, nonce := p.state, p.nonce
	machine := p.machine
	f.mu.Unlock()

	prov, err := f.provider(r)
	if err != nil {
		s.audit.Log("OAUTH-FAIL", "machine", machine, "reason", "idp-discovery")
		f.oauthPage(w, http.StatusBadGateway, "身份服务暂时不可用", "服务器连不上身份提供方，请稍后在终端重试。")
		return
	}
	http.Redirect(w, r, prov.AuthorizeURL(state, nonce), http.StatusFound)
}

// handleOAuthCallback 是 IdP 回调：state 找授权条目 → code 换 token →
// 验身份 → 预绑定比对 → 发 SSH 凭据。任何一步失败都标 failed 并让
// agent 的轮询拿到原因。
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	f := s.oauth
	q := r.URL.Query()
	state, code, oerr := q.Get("state"), q.Get("code"), q.Get("error")

	f.mu.Lock()
	p := f.byState[state]
	f.mu.Unlock()
	ip := hostOnly(r.RemoteAddr)
	fail := func(code int, title, reason string) {
		f.mu.Lock()
		if p != nil && !p.done {
			p.done, p.failed = true, reason
		}
		f.mu.Unlock()
		if p != nil {
			s.audit.Log("OAUTH-FAIL", "machine", p.machine, "ip", ip, "reason", reason)
		}
		f.oauthPage(w, code, title, "请回到终端查看结果。")
	}
	if p == nil || p.done || time.Now().After(p.expires) {
		f.oauthPage(w, http.StatusGone, "授权会话已失效", "这条授权不存在或已过期。")
		return
	}
	if oerr != "" {
		fail(http.StatusForbidden, "授权被拒绝", "idp:"+oerr)
		return
	}
	if code == "" {
		fail(http.StatusBadRequest, "回调缺少参数", "no-code")
		return
	}
	prov, err := f.provider(r)
	if err != nil {
		fail(http.StatusBadGateway, "身份服务暂时不可用", "idp-discovery")
		return
	}
	tr, err := prov.Exchange(r.Context(), code)
	if err != nil {
		fail(http.StatusBadGateway, "授权码交换失败", "exchange")
		return
	}
	id, err := prov.VerifyIdentity(r.Context(), tr, p.nonce)
	if err != nil {
		fail(http.StatusForbidden, "身份校验失败", "verify:"+err.Error())
		return
	}
	// 预先绑定：(issuer, sub) 必须指向这台机器所属的账号。
	owner, bound := s.cfg.Users.OAuthLookup(s.cfg.OAuth.Issuer, id.Sub)
	switch {
	case !bound:
		fail(http.StatusForbidden, "身份未绑定", "unbound-sub")
		return
	case owner != p.username:
		fail(http.StatusForbidden, "身份不属于此账号", "wrong-account")
		return
	}
	// 账号可能被停用/机器可能被删，发凭据前复核。
	acct, ok := s.cfg.Users.Get(p.username)
	if !ok || acct.Disabled {
		fail(http.StatusForbidden, "账号不可用", "account-disabled")
		return
	}
	if _, ok := s.cfg.Users.GetMachine(p.username, mustMachineName(p.machine)); !ok {
		fail(http.StatusNotFound, "机器不存在", "machine-gone")
		return
	}
	secret, err := s.cfg.Users.CreateSSHGrant(p.machine, accounts.GrantTTL, accounts.GrantUses)
	if err != nil {
		fail(http.StatusInternalServerError, "凭据签发失败", "grant")
		return
	}
	f.mu.Lock()
	p.done, p.secret = true, secret
	f.mu.Unlock()
	s.audit.Log("OAUTH-OK", "machine", p.machine, "ip", ip, "sub", id.Sub, "email", id.Email)
	f.oauthPage(w, http.StatusOK, "授权成功",
		"已为 "+html.EscapeString(p.machine)+" 签发 SSH 登录凭据，请回到终端查看。")
}

// mustMachineName 从 "alice+default" 取机器名；授权条目里的 machine 一定带 +。
func mustMachineName(id string) string {
	_, name := accounts.SplitMachineID(id)
	return name
}

// handleOAuthResult 是 agent 的轮询口：同一个 agent token 才能查自己
// 发起的授权。approved 时返回一次性 SSH 凭据，取走即删条目。
func (s *Server) handleOAuthResult(w http.ResponseWriter, r *http.Request) {
	m, ok := s.cfg.Users.MachineByToken(r.Header.Get("X-Agent-Token"))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// 取回的是 SSH 凭据——同样受机器 agent 白名单约束。
	if !agentIPAllowed(m, tcpAddr(r.RemoteAddr)) {
		s.audit.Log("OAUTH-DENY", "machine", m.ID(), "ip", hostOnly(r.RemoteAddr), "reason", "agent-allow")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	f := s.oauth
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(time.Now())
	p := f.pend[r.URL.Query().Get("r")]
	if p == nil || p.machine != m.ID() {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "unknown"})
		return
	}
	out := map[string]any{"status": "pending"}
	switch {
	case p.done && p.failed != "":
		out = map[string]any{"status": "failed", "reason": p.failed}
	case p.done:
		out = map[string]any{
			"status":    "approved",
			"machine":   p.machine,
			"password":  p.secret,
			"ssh_addr":  s.cfg.SSHAddr,
			"expire_in": int(accounts.GrantTTL / time.Second),
			"uses":      accounts.GrantUses,
		}
	}
	// 终态一次性下发后删掉条目（secret 不再留在内存）。
	if p.done {
		delete(f.pend, p.id)
		if p.state != "" {
			delete(f.byState, p.state)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// oauthPage 是给浏览器看的极简结果页（授权过程没有前端，够用就行）。
func (f *oauthFlow) oauthPage(w http.ResponseWriter, code int, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%s</title>
<body style="font-family:system-ui;max-width:32em;margin:4em auto">
<h2>%s</h2><p>%s</p></body>`,
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(detail))
}
