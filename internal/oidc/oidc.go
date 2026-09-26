// Package oidc 是一个最小的通用 OIDC 客户端：发现文档、拼授权 URL、
// code 换 token、验 id_token（RS256/ES256，JWKS 带缓存）、userinfo 兜底。
// 只实现「授权码流程里服务器该做的那部分」，不接 refresh、不搞 PKCE——
// client_secret 在 server 手里，confidential client 不需要 PKCE。
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	httpTimeout  = 10 * time.Second
	clockSkew    = 60 * time.Second
	maxRespBytes = 1 << 20
)

// Config 是 server.yaml 里 oauth: 小节翻译后的参数。
type Config struct {
	Issuer       string // IdP issuer，发现文档取 issuer + /.well-known/openid-configuration
	ClientID     string
	ClientSecret string
	RedirectURL  string // IdP 回调地址；空 = 调用方按 public_url/请求 Host 推导后塞进来
	Scopes       string // 默认 "openid email"
}

// Provider 是做完发现的 IdP 句柄。
type Provider struct {
	cfg         Config
	authURL     string
	tokenURL    string
	userinfoURL string
	jwksURL     string
	hc          *http.Client
	jwks        *jwksStore // JWKS 缓存；WithRedirect 的副本共享同一份
}

// jwksStore 单独成指针结构体：WithRedirect 要值拷贝 Provider，锁和
// 缓存表不能跟着复制。
type jwksStore struct {
	mu   sync.Mutex
	keys map[string]crypto.PublicKey
}

// Identity 是校验通过的IdP身份：sub 是稳定唯一标识，email 可能没有。
type Identity struct {
	Sub   string
	Email string
}

type discoveryDoc struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	UserinfoURL string `json:"userinfo_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
}

// Discover 拉 IdP 发现文档并装配 Provider。issuer 必须是 http(s) URL，
// 末尾 / 会被剥掉再拼 /.well-known/openid-configuration。
func Discover(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("oauth 需要 issuer 和 client_id")
	}
	if cfg.Scopes == "" {
		cfg.Scopes = "openid email"
	}
	iss := strings.TrimSuffix(cfg.Issuer, "/")
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		iss+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: httpTimeout}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("拉 IdP 发现文档失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IdP 发现文档返回 %d", resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("解析 IdP 发现文档失败: %w", err)
	}
	if doc.AuthURL == "" || doc.TokenURL == "" {
		return nil, errors.New("IdP 发现文档缺 authorization_endpoint/token_endpoint")
	}
	// issuer 串必须和文档自报的一致（防把 A 家的端点当 B 家用）
	if doc.Issuer != "" && doc.Issuer != iss {
		return nil, fmt.Errorf("发现文档 issuer %q 和配置的 %q 不一致", doc.Issuer, iss)
	}
	return &Provider{
		cfg:         cfg,
		authURL:     doc.AuthURL,
		tokenURL:    doc.TokenURL,
		userinfoURL: doc.UserinfoURL,
		jwksURL:     doc.JWKSURL,
		hc:          hc,
		jwks:        &jwksStore{},
	}, nil
}

// WithRedirect 返回一个换了 redirect_uri 的浅副本：端点、HTTP 客户端、
// JWKS 缓存都共享。redirect_uri 按请求现算的场景用（配置没钉死时每个
// 请求各自推导，不能把第一个请求的 Host 记一辈子）。
func (p *Provider) WithRedirect(redirect string) *Provider {
	q := *p
	q.cfg.RedirectURL = redirect
	return &q
}

// AuthorizeURL 拼浏览器跳转地址。state 防 CSRF、nonce 防 id_token 重放，
// 都由调用方生成并各自存好。
func (p *Provider) AuthorizeURL(state, nonce string) string {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {p.cfg.ClientID},
		"redirect_uri":  {p.cfg.RedirectURL},
		"scope":         {p.cfg.Scopes},
		"state":         {state},
		"nonce":         {nonce},
	}
	return p.authURL + "?" + q.Encode()
}

type tokenResp struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	Err         string `json:"error"`
	ErrDesc     string `json:"error_description"`
}

// Exchange 拿 callback 带回的 code 去 token 端点换 token。
func (p *Provider) Exchange(ctx context.Context, code string) (*tokenResp, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {p.cfg.RedirectURL},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("code 换 token 失败: %w", err)
	}
	defer resp.Body.Close()
	var tr tokenResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("token 响应解析失败: %w", err)
	}
	if tr.Err != "" {
		return nil, fmt.Errorf("IdP 拒绝换 token: %s %s", tr.Err, tr.ErrDesc)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token 端点返回 %d", resp.StatusCode)
	}
	return &tr, nil
}

// VerifyIdentity 从 token 响应里拿身份：优先验 id_token（本地验签，
// 不依赖网络），没有就退到 userinfo（TLS 信道信任）。
func (p *Provider) VerifyIdentity(ctx context.Context, tr *tokenResp, nonce string) (Identity, error) {
	if tr.IDToken != "" {
		return p.verifyIDToken(ctx, tr.IDToken, nonce)
	}
	if tr.AccessToken != "" && p.userinfoURL != "" {
		return p.userinfo(ctx, tr.AccessToken)
	}
	return Identity{}, errors.New("token 响应里既没有 id_token 也没有可用的 userinfo")
}

// userinfo 用 access_token 拉用户信息兜底。
func (p *Provider) userinfo(ctx context.Context, accessToken string) (Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userinfoURL, nil)
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := p.hc.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("userinfo 请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("userinfo 返回 %d", resp.StatusCode)
	}
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&claims); err != nil {
		return Identity{}, fmt.Errorf("userinfo 解析失败: %w", err)
	}
	if claims.Sub == "" {
		return Identity{}, errors.New("userinfo 里没有 sub")
	}
	return Identity{Sub: claims.Sub, Email: claims.Email}, nil
}

// verifyIDToken 验签 id_token：RS256/ES256 签名 + iss/aud/exp/nonce。
func (p *Provider) verifyIDToken(ctx context.Context, raw, nonce string) (Identity, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Identity{}, errors.New("id_token 不是 JWT 格式")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil {
		return Identity{}, errors.New("id_token 头解析失败")
	}
	var claims struct {
		Iss   string `json:"iss"`
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Nonce string `json:"nonce"`
		Exp   int64  `json:"exp"`
		Aud   any    `json:"aud"` // string 或数组
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &claims) != nil {
		return Identity{}, errors.New("id_token 载荷解析失败")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, errors.New("id_token 签名解析失败")
	}
	key, err := p.jwksKey(ctx, header.Kid)
	if err != nil {
		return Identity{}, err
	}
	signed := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signed))
	switch header.Alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return Identity{}, fmt.Errorf("id_token alg=RS256 但 JWKS 里 kid=%s 不是 RSA 钥匙", header.Kid)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return Identity{}, errors.New("id_token 签名验证失败")
		}
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return Identity{}, fmt.Errorf("id_token alg=ES256 但 JWKS 里 kid=%s 不是 P-256 钥匙", header.Kid)
		}
		if len(sig) != 64 {
			return Identity{}, errors.New("ES256 签名长度不对")
		}
		r := new(big.Int).SetBytes(sig[:32])
		sv := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, sv) {
			return Identity{}, errors.New("id_token 签名验证失败")
		}
	default:
		return Identity{}, fmt.Errorf("不支持的 id_token 签名算法 %s（只支持 RS256/ES256）", header.Alg)
	}
	if claims.Iss != strings.TrimSuffix(p.cfg.Issuer, "/") {
		return Identity{}, fmt.Errorf("id_token issuer 不符: %q", claims.Iss)
	}
	if !audMatch(claims.Aud, p.cfg.ClientID) {
		return Identity{}, errors.New("id_token aud 不含本 client_id")
	}
	if time.Now().Unix() > claims.Exp+int64(clockSkew/time.Second) {
		return Identity{}, errors.New("id_token 已过期")
	}
	if nonce != "" && claims.Nonce != nonce {
		return Identity{}, errors.New("id_token nonce 不符")
	}
	if claims.Sub == "" {
		return Identity{}, errors.New("id_token 没有 sub")
	}
	return Identity{Sub: claims.Sub, Email: claims.Email}, nil
}

// audMatch 处理 aud 是字符串或数组两种写法。
func audMatch(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// jwksKey 从 JWKS 里取 kid 对应的公钥；没找到就强制刷新一次再找
// （应对 IdP 换钥——刷完还没有就是真没有）。
func (p *Provider) jwksKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if p.jwksURL == "" {
		return nil, errors.New("IdP 没给 jwks_uri，无法验签 id_token")
	}
	if k, err := p.jwksKeyCached(kid); err == nil {
		return k, nil
	}
	if err := p.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	return p.jwksKeyCached(kid)
}

func (p *Provider) jwksKeyCached(kid string) (crypto.PublicKey, error) {
	p.jwks.mu.Lock()
	defer p.jwks.mu.Unlock()
	if k, ok := p.jwks.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("JWKS 里没有 kid=%s", kid)
}

type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

func (p *Provider) refreshJWKS(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return fmt.Errorf("拉 JWKS 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS 返回 %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&doc); err != nil {
		return fmt.Errorf("JWKS 解析失败: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil {
				continue
			}
			eInt := 0
			for _, b := range e {
				eInt = eInt<<8 | int(b)
			}
			keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: eInt}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			}
		}
	}
	p.jwks.mu.Lock()
	p.jwks.keys = keys
	p.jwks.mu.Unlock()
	return nil
}
