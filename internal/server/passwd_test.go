package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/totp"
)

// TestPasswd POST /passwd：agent token 认机器 + 旧密码证本人；已绑 TOTP
// 要当前动态码；oauth_only 账号密码不作数。改完旧密码即刻失效。
func TestPasswd(t *testing.T) {
	users, err := accounts.Open(filepath.Join(t.TempDir(), "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Close()
	s := New(Config{Users: users})
	ts := httptest.NewServer(s.routes())
	defer ts.Close()

	acct, err := users.Add("alice", "oldpassword1", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := acct.Machines[0].Token

	post := func(token string, req proto.PasswdReq) (int, proto.PasswdResp) {
		t.Helper()
		b, _ := json.Marshal(req)
		r, _ := http.NewRequest(http.MethodPost, ts.URL+"/passwd", bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("X-Agent-Token", token)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out proto.PasswdResp
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	t.Run("没 token / 错旧密码 → 401", func(t *testing.T) {
		if code, _ := post("", proto.PasswdReq{Password: "oldpassword1", NewPassword: "newpassword1"}); code != http.StatusUnauthorized {
			t.Fatalf("没 token 该 401，got %d", code)
		}
		if code, _ := post(tok, proto.PasswdReq{Password: "wrongwrong9", NewPassword: "newpassword1"}); code != http.StatusUnauthorized {
			t.Fatalf("旧密码错该 401，got %d", code)
		}
	})

	t.Run("新密码太短 → 400", func(t *testing.T) {
		code, res := post(tok, proto.PasswdReq{Password: "oldpassword1", NewPassword: "short"})
		if code != http.StatusBadRequest || res.OK {
			t.Fatalf("短密码该 400，got %d %+v", code, res)
		}
	})

	t.Run("正常改密 → 旧密码作废新密码生效", func(t *testing.T) {
		code, res := post(tok, proto.PasswdReq{Password: "oldpassword1", NewPassword: "newpassword1"})
		if code != 200 || !res.OK {
			t.Fatalf("改密该成: %d %+v", code, res)
		}
		if users.Verify("alice", "oldpassword1") {
			t.Fatal("旧密码不该再验过")
		}
		if !users.Verify("alice", "newpassword1") {
			t.Fatal("新密码该验过")
		}
	})

	t.Run("已绑 TOTP → need_code → 带码成功", func(t *testing.T) {
		secret, _ := totp.Generate("towstrap", "alice")
		if err := users.EnrollTOTP("alice", secret, 0); err != nil {
			t.Fatal(err)
		}
		code, res := post(tok, proto.PasswdReq{Password: "newpassword1", NewPassword: "newpassword2"})
		if code != http.StatusForbidden || !res.NeedCode {
			t.Fatalf("已绑不带码该 403+need_code: %d %+v", code, res)
		}
		code, _ = post(tok, proto.PasswdReq{Password: "newpassword1", NewPassword: "newpassword2", Code: "000000"})
		if code != http.StatusUnauthorized {
			t.Fatalf("错码该 401，got %d", code)
		}
		code, res = post(tok, proto.PasswdReq{
			Password: "newpassword1", NewPassword: "newpassword2",
			Code: totp.Code(secret, time.Now()),
		})
		if code != 200 || !res.OK {
			t.Fatalf("带对码该成: %d %+v", code, res)
		}
		if !users.Verify("alice", "newpassword2") {
			t.Fatal("新密码该生效")
		}
	})

	t.Run("oauth_only 账号 → 403", func(t *testing.T) {
		acct2, err := users.Add("bob", "oldpassword1", nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := users.SetOAuthOnly("bob", true); err != nil {
			t.Fatal(err)
		}
		code, res := post(acct2.Machines[0].Token, proto.PasswdReq{Password: "oldpassword1", NewPassword: "newpassword1"})
		if code != http.StatusForbidden || res.OK {
			t.Fatalf("oauth_only 该 403，got %d %+v", code, res)
		}
	})
}
