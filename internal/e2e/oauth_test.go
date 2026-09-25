package e2e

// OAuth 全流程端到端：假 IdP（httptest，自动批准）→ server 的
// /oauth/request|begin|callback|result → SSH 用换来的凭据登录。
// 覆盖：链接下发、state/nonce、身份绑定比对、一次性凭据、oauth_only 拦截。

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/towstrap/towstrap/internal/server"

	gossh "golang.org/x/crypto/ssh"
)

// mkSSHPass 组一个纯密码认证的 SSH 客户端配置。
func mkSSHPass(user, password string) *gossh.ClientConfig {
	return &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.Password(password)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
}

// sshEchoErr 走 exec 模式执行命令：认证或执行失败返回 error，成功返回输出。
func sshEchoErr(sshPort int, cfg *gossh.ClientConfig, cmd string) (string, error) {
	c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
	if err != nil {
		return "", err
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

// oauthIdP 是测试用的最小 IdP：发现文档 + /auth 自动批准 + /token 签
// id_token + /jwks。
type oauthIdP struct {
	*httptest.Server
	key *rsa.PrivateKey
	sub string
}

func newOAuthIdP(t *testing.T, sub string) *oauthIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &oauthIdP{key: key, sub: sub}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 p.URL,
			"authorization_endpoint": p.URL + "/auth",
			"token_endpoint":         p.URL + "/token",
			"userinfo_endpoint":      p.URL + "/userinfo",
			"jwks_uri":               p.URL + "/jwks",
		})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		// 自动批准：立刻跳回 redirect_uri。nonce 编进 code 带回——
		// 真 IdP 会记住授权请求里的 nonce 并签进 id_token，这里用
		// code 当载体达到同样效果。
		q := r.URL.Query()
		cb, _ := url.QueryUnescape(q.Get("redirect_uri"))
		http.Redirect(w, r, fmt.Sprintf("%s?code=code-%s&state=%s", cb,
			url.QueryEscape(q.Get("nonce")), url.QueryEscape(q.Get("state"))), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || !strings.HasPrefix(r.Form.Get("code"), "code-") {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "bad_grant"})
			return
		}
		nonce := strings.TrimPrefix(r.Form.Get("code"), "code-")
		head, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
		pay, _ := json.Marshal(map[string]any{
			"iss": p.URL, "sub": p.sub, "aud": "towstrap",
			"nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(),
			"email": "u@example.com",
		})
		signed := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(pay)
		digest := sha256.Sum256([]byte(signed))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "at-x",
			"id_token":     signed + "." + base64.RawURLEncoding.EncodeToString(sig),
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.PublicKey.E)).Bytes()),
			}},
		})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// noRedirectClient 不自动跟 302 的 HTTP 客户端（逐步验证跳转链）。
var noRedirectClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Timeout:       10 * time.Second,
}

func TestOAuthFlowEndToEnd(t *testing.T) {
	idp := newOAuthIdP(t, "sub-alice")
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{
		OAuth: &server.OAuthConfig{
			Issuer:       idp.URL,
			ClientID:     "towstrap",
			ClientSecret: "s3cret",
		},
	})
	acct, err := users.Add("alice", "alicepw12345", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.BindOAuthIdentity("alice", idp.URL, "sub-alice", "a@x.com"); err != nil {
		t.Fatal(err)
	}
	token := acct.Machines[0].Token
	startAgent(t, httpPort, token, "alice-host")
	waitAgent(t, srv.Hub, "alice+default")
	base := fmt.Sprintf("http://127.0.0.1:%d", httpPort)

	// 1. agent 请求授权链接
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/request", nil)
	req.Header.Set("X-Agent-Token", token)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var start struct {
		RequestID string `json:"request_id"`
		URL       string `json:"url"`
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("request 返回 %d: %s", resp.StatusCode, b)
	}
	json.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()
	if start.RequestID == "" || !strings.HasPrefix(start.URL, base+"/oauth/begin?r=") {
		t.Fatalf("授权链接不对: %+v", start)
	}

	// 2. 浏览器打开链接 → 302 到 IdP
	resp, err = noRedirectClient.Get(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := resp.Location()
	resp.Body.Close()
	if resp.StatusCode != 302 || loc == nil || !strings.HasPrefix(loc.String(), idp.URL+"/auth") {
		t.Fatalf("begin 应 302 到 IdP，实际 %d %v", resp.StatusCode, loc)
	}

	// 3. IdP 自动批准 → 302 回服务器 callback
	resp, err = noRedirectClient.Get(loc.String())
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := resp.Location()
	resp.Body.Close()
	if cb == nil || !strings.HasPrefix(cb.String(), base+"/oauth/callback") {
		t.Fatalf("IdP 应跳回 callback，实际 %v", cb)
	}
	resp, err = noRedirectClient.Get(cb.String())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "授权成功") {
		t.Fatalf("callback 应成功，实际 %d %s", resp.StatusCode, body)
	}

	// 4. agent 轮询取凭据
	req, _ = http.NewRequest(http.MethodGet, base+"/oauth/result?r="+start.RequestID, nil)
	req.Header.Set("X-Agent-Token", token)
	resp, err = noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Status   string `json:"status"`
		Machine  string `json:"machine"`
		Password string `json:"password"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if res.Status != "approved" || !strings.HasPrefix(res.Password, "tso-") {
		t.Fatalf("应下发凭据，实际 %+v", res)
	}

	// 5. 用 OAuth 凭据走真 SSH 登录
	out := sshEcho(t, sshPort, "alice+default", res.Password, "echo oauth-works")
	if !strings.Contains(out, "oauth-works") {
		t.Fatalf("grant 登录应成功，实际 %q", out)
	}
}

func TestOAuthOnlyBlocksNormalAuth(t *testing.T) {
	idp := newOAuthIdP(t, "sub-bob")
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{
		OAuth: &server.OAuthConfig{Issuer: idp.URL, ClientID: "towstrap"},
	})
	acct, err := users.Add("bob", "bobpw123456", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.BindOAuthIdentity("bob", idp.URL, "sub-bob", ""); err != nil {
		t.Fatal(err)
	}
	if err := users.SetMachineOAuthOnly("bob", "default", true); err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "bob-host")
	waitAgent(t, srv.Hub, "bob+default")
	base := fmt.Sprintf("http://127.0.0.1:%d", httpPort)

	// 普通密码被拒（oauth_only）
	cfg := mkSSHPass("bob+default", "bobpw123456")
	if _, err := sshEchoErr(sshPort, cfg, "echo x"); err == nil {
		t.Fatal("oauth_only 机器不应收账号密码")
	}
	// 登记的公钥同样被拒
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.AddSSHKey("bob", strings.TrimSpace(
		string(gossh.MarshalAuthorizedKey(signer.PublicKey())))); err != nil {
		t.Fatal(err)
	}
	pkCfg := &gossh.ClientConfig{
		User:            "bob+default",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if _, err := sshEchoErr(sshPort, pkCfg, "echo x"); err == nil {
		t.Fatal("oauth_only 机器不应收公钥")
	}
	// 走一遍完整 OAuth 拿凭据 → SSH 放行
	secret := oauthGrantFor(t, base, acct.Machines[0].Token)
	cfg = mkSSHPass("bob+default", secret)
	out, err := sshEchoErr(sshPort, cfg, "echo grant-ok")
	if err != nil || !strings.Contains(out, "grant-ok") {
		t.Fatalf("grant 应能登录，err=%v out=%q", err, out)
	}
	// 次数用尽后凭据失效：GrantUses=5，再耗掉剩余次数
	for i := 1; i < 5; i++ {
		_, _ = sshEchoErr(sshPort, mkSSHPass("bob+default", secret), "true")
	}
	if _, err := sshEchoErr(sshPort, mkSSHPass("bob+default", secret), "true"); err == nil {
		t.Fatal("次数用尽后的凭据必须失效")
	}
}

func TestOAuthUnboundIdentityDenied(t *testing.T) {
	idp := newOAuthIdP(t, "sub-stranger") // 没绑定的身份
	srv, httpPort, _, users := startServerOpt(t, server.Config{
		OAuth: &server.OAuthConfig{Issuer: idp.URL, ClientID: "towstrap"},
	})
	acct, _ := users.Add("carol", "carolpw123", nil, "", nil)
	startAgent(t, httpPort, acct.Machines[0].Token, "carol-host")
	waitAgent(t, srv.Hub, "carol+default")
	base := fmt.Sprintf("http://127.0.0.1:%d", httpPort)

	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/request", nil)
	req.Header.Set("X-Agent-Token", acct.Machines[0].Token)
	resp, _ := noRedirectClient.Do(req)
	var start struct {
		RequestID string `json:"request_id"`
		URL       string `json:"url"`
	}
	json.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()
	resp, _ = noRedirectClient.Get(start.URL)
	loc, _ := resp.Location()
	resp.Body.Close()
	resp, _ = noRedirectClient.Get(loc.String())
	cb, _ := resp.Location()
	resp.Body.Close()
	resp, _ = noRedirectClient.Get(cb.String())
	resp.Body.Close() // 403 未绑定页

	req, _ = http.NewRequest(http.MethodGet, base+"/oauth/result?r="+start.RequestID, nil)
	req.Header.Set("X-Agent-Token", acct.Machines[0].Token)
	resp, _ = noRedirectClient.Do(req)
	var res struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if res.Status != "failed" || res.Reason != "unbound-sub" {
		t.Fatalf("未绑定身份应失败，实际 %+v", res)
	}
}

// oauthGrantFor 走一遍完整授权流程，返回下发的 tso- 凭据。
func oauthGrantFor(t *testing.T, base, token string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/request", nil)
	req.Header.Set("X-Agent-Token", token)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var start struct {
		RequestID string `json:"request_id"`
		URL       string `json:"url"`
	}
	json.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()
	resp, _ = noRedirectClient.Get(start.URL)
	loc, _ := resp.Location()
	resp.Body.Close()
	resp, _ = noRedirectClient.Get(loc.String())
	cb, _ := resp.Location()
	resp.Body.Close()
	resp, _ = noRedirectClient.Get(cb.String())
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	req, _ = http.NewRequest(http.MethodGet, base+"/oauth/result?r="+start.RequestID, nil)
	req.Header.Set("X-Agent-Token", token)
	resp, _ = noRedirectClient.Do(req)
	var res struct {
		Status   string `json:"status"`
		Password string `json:"password"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if res.Status != "approved" {
		t.Fatalf("授权应通过，实际 %+v", res)
	}
	return res.Password
}
