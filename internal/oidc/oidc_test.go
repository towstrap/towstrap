package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeIdP 是一个 httptest 上的最小 OIDC 提供方：发现文档、token 端点
// （code 换签名的 id_token）、JWKS、userinfo。
type fakeIdP struct {
	*httptest.Server
	key *rsa.PrivateKey
	sub string
}

func newFakeIdP(t *testing.T, sub string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeIdP{key: key, sub: sub}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "", // 占位，启动后回填
			"authorization_endpoint": fp.URL + "/auth",
			"token_endpoint":         fp.URL + "/token",
			"userinfo_endpoint":      fp.URL + "/userinfo",
			"jwks_uri":               fp.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("code") == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "bad_request"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "at-" + r.Form.Get("code"),
			"id_token":     fp.signIDToken(r.Form.Get("nonce-ignored")),
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"sub": fp.sub, "email": "u@example.com"})
	})
	fp.Server = httptest.NewServer(mux)
	t.Cleanup(fp.Close)
	return fp
}

// signIDToken 签一个 RS256 id_token；nonce 由 signIDTokenWith 填。
func (fp *fakeIdP) signIDToken(nonce string) string {
	return fp.signWith(fp.sub, nonce, "towstrap", time.Now().Add(time.Hour).Unix())
}

func (fp *fakeIdP) signWith(sub, nonce, aud string, exp int64) string {
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	pay, _ := json.Marshal(map[string]any{
		"iss": fp.URL, "sub": sub, "aud": aud, "nonce": nonce,
		"exp": exp, "email": "u@example.com",
	})
	signed := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(pay)
	digest := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, fp.key, crypto.SHA256, digest[:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func discover(t *testing.T, fp *fakeIdP) *Provider {
	t.Helper()
	p, err := Discover(context.Background(), Config{
		Issuer: fp.URL, ClientID: "towstrap", ClientSecret: "s3cret",
		RedirectURL: "http://127.0.0.1/cb",
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiscoverAndExchange(t *testing.T) {
	fp := newFakeIdP(t, "sub-123")
	p := discover(t, fp)
	tr, err := p.Exchange(context.Background(), "code-1")
	if err != nil {
		t.Fatal(err)
	}
	if tr.IDToken == "" {
		t.Fatal("应返回 id_token")
	}
	id, err := p.VerifyIdentity(context.Background(), tr, "")
	if err != nil {
		t.Fatal(err)
	}
	if id.Sub != "sub-123" || id.Email != "u@example.com" {
		t.Fatalf("身份不对: %+v", id)
	}
}

func TestIDTokenNonceMismatch(t *testing.T) {
	fp := newFakeIdP(t, "sub-123")
	p := discover(t, fp)
	tr := &tokenResp{IDToken: fp.signIDToken("nonce-A")}
	if _, err := p.VerifyIdentity(context.Background(), tr, "nonce-B"); err == nil {
		t.Fatal("nonce 不符必须拒")
	}
}

func TestIDTokenBadSignature(t *testing.T) {
	fp := newFakeIdP(t, "sub-123")
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := discover(t, fp)
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
	pay, _ := json.Marshal(map[string]any{"iss": fp.URL, "sub": "x", "aud": "towstrap", "exp": time.Now().Add(time.Hour).Unix()})
	signed := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(pay)
	digest := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, digest[:])
	tr := &tokenResp{IDToken: signed + "." + base64.RawURLEncoding.EncodeToString(sig)}
	if _, err := p.VerifyIdentity(context.Background(), tr, ""); err == nil {
		t.Fatal("假签名必须拒")
	}
}

func TestIDTokenExpired(t *testing.T) {
	fp := newFakeIdP(t, "sub-123")
	p := discover(t, fp)
	tr := &tokenResp{IDToken: fp.signWith("sub-123", "", "towstrap", time.Now().Add(-time.Hour).Unix())}
	if _, err := p.VerifyIdentity(context.Background(), tr, ""); err == nil {
		t.Fatal("过期的 id_token 必须拒")
	}
}

func TestUserinfoFallback(t *testing.T) {
	fp := newFakeIdP(t, "sub-999")
	p := discover(t, fp)
	// 不给 id_token：走 userinfo
	id, err := p.VerifyIdentity(context.Background(), &tokenResp{AccessToken: "at-x"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if id.Sub != "sub-999" {
		t.Fatalf("userinfo sub 不对: %+v", id)
	}
}

func TestIssuerMismatchRejected(t *testing.T) {
	fp := newFakeIdP(t, "sub-1")
	// 伪造一个 issuer 不匹配的 token
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
	pay, _ := json.Marshal(map[string]any{"iss": "https://evil.example.com", "sub": "x", "aud": "towstrap", "exp": time.Now().Add(time.Hour).Unix()})
	signed := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(pay)
	digest := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, fp.key, crypto.SHA256, digest[:])
	p := discover(t, fp)
	if _, err := p.VerifyIdentity(context.Background(),
		&tokenResp{IDToken: signed + "." + base64.RawURLEncoding.EncodeToString(sig)}, ""); err == nil {
		t.Fatal("issuer 不符必须拒")
	}
}
