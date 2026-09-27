package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/totp"
)

// TestSSHKey POST /sshkey：agent token 认机器 + 密码证本人；list/add/remove
// 全链路；已绑 TOTP 要当前动态码；oauth_only 账号密码不作数（反正公钥
// 登录对这类账号也不认，加了也没用）。
func TestSSHKey(t *testing.T) {
	users, err := accounts.Open(filepath.Join(t.TempDir(), "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Close()
	s := New(Config{Users: users})
	ts := httptest.NewServer(s.routes())
	defer ts.Close()

	acct, err := users.Add("alice", "alicepw1234", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := acct.Machines[0].Token

	signer := testSigner(t)
	keyLine := string(gossh.MarshalAuthorizedKey(signer.PublicKey()))
	fp := sshKeyInfo(keyLine).Fingerprint

	post := func(token string, req proto.SSHKeyReq) (int, proto.SSHKeyResp) {
		t.Helper()
		b, _ := json.Marshal(req)
		r, _ := http.NewRequest(http.MethodPost, ts.URL+"/sshkey", bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("X-Agent-Token", token)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out proto.SSHKeyResp
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	t.Run("没 token / 错密码 → 401", func(t *testing.T) {
		if code, _ := post("", proto.SSHKeyReq{Action: "list", Password: "alicepw1234"}); code != http.StatusUnauthorized {
			t.Fatalf("没 token 该 401，got %d", code)
		}
		if code, _ := post(tok, proto.SSHKeyReq{Action: "list", Password: "wrongwrong9"}); code != http.StatusUnauthorized {
			t.Fatalf("密码错该 401，got %d", code)
		}
	})

	t.Run("list 空账号", func(t *testing.T) {
		code, res := post(tok, proto.SSHKeyReq{Action: "list", Password: "alicepw1234"})
		if code != 200 || !res.OK || len(res.Keys) != 0 {
			t.Fatalf("空 list 该 200 且 0 把，got %d %+v", code, res)
		}
	})

	t.Run("add → list → remove 全链路", func(t *testing.T) {
		code, res := post(tok, proto.SSHKeyReq{Action: "add", Password: "alicepw1234", Key: keyLine})
		if code != 200 || !res.OK {
			t.Fatalf("add 该成: %d %+v", code, res)
		}
		code, res = post(tok, proto.SSHKeyReq{Action: "list", Password: "alicepw1234"})
		if code != 200 || len(res.Keys) != 1 || res.Keys[0].Fingerprint != fp {
			t.Fatalf("list 该有一把且指纹对上: %d %+v", code, res)
		}
		// 用指纹删
		code, res = post(tok, proto.SSHKeyReq{Action: "remove", Password: "alicepw1234", Key: fp})
		if code != 200 || !res.OK {
			t.Fatalf("remove 该成: %d %+v", code, res)
		}
		code, res = post(tok, proto.SSHKeyReq{Action: "list", Password: "alicepw1234"})
		if len(res.Keys) != 0 {
			t.Fatalf("删完该空了，got %+v", res.Keys)
		}
	})

	t.Run("坏公钥行 → 400", func(t *testing.T) {
		code, _ := post(tok, proto.SSHKeyReq{Action: "add", Password: "alicepw1234", Key: "not-a-key"})
		if code != http.StatusBadRequest {
			t.Fatalf("坏公钥该 400，got %d", code)
		}
	})

	t.Run("已绑 TOTP → need_code → 带码成功", func(t *testing.T) {
		secret, _ := totp.Generate("towstrap", "alice")
		if err := users.EnrollTOTP("alice", secret, 0); err != nil {
			t.Fatal(err)
		}
		code, res := post(tok, proto.SSHKeyReq{Action: "add", Password: "alicepw1234", Key: keyLine})
		if code != http.StatusForbidden || !res.NeedCode {
			t.Fatalf("已绑不带码该 403+need_code: %d %+v", code, res)
		}
		code, res = post(tok, proto.SSHKeyReq{
			Action: "add", Password: "alicepw1234", Key: keyLine,
			Code: totp.Code(secret, time.Now()),
		})
		if code != 200 || !res.OK {
			t.Fatalf("带对码该成: %d %+v", code, res)
		}
	})

	t.Run("oauth_only 账号 → 403", func(t *testing.T) {
		acct2, err := users.Add("bob", "bobpassword1", nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := users.SetOAuthOnly("bob", true); err != nil {
			t.Fatal(err)
		}
		code, res := post(acct2.Machines[0].Token, proto.SSHKeyReq{Action: "list", Password: "bobpassword1"})
		if code != http.StatusForbidden || res.OK {
			t.Fatalf("oauth_only 该 403，got %d %+v", code, res)
		}
	})
}
