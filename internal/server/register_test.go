package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/totp"
)

func newRegisterSrv(t *testing.T, cfg Config) (*accounts.Store, *httptest.Server) {
	t.Helper()
	users, err := accounts.Open(filepath.Join(t.TempDir(), "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })
	cfg.Users = users
	if cfg.SSHAddr == "" {
		cfg.SSHAddr = ":7822"
	}
	s := New(cfg)
	return users, httptest.NewServer(s.routes())
}

func postRegister(t *testing.T, url string, req proto.RegisterReq) (int, proto.RegisterResp) {
	return postRegisterURL(t, url+"/register", req)
}

func postRegisterURL(t *testing.T, url string, req proto.RegisterReq) (int, proto.RegisterResp) {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out proto.RegisterResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestRegister(t *testing.T) {
	fp := strings.Repeat("a", 64)

	t.Run("没开 register 返回 403", func(t *testing.T) {
		_, ts := newRegisterSrv(t, Config{})
		defer ts.Close()
		code, res := postRegister(t, ts.URL, proto.RegisterReq{Account: "alice", Password: "0123456789", Fingerprint: fp})
		if code != http.StatusForbidden || !strings.Contains(res.Err, "没开自助注册") {
			t.Fatalf("want 403 disabled, got %d %+v", code, res)
		}
	})

	t.Run("正常注册+同机指纹拒绝重复", func(t *testing.T) {
		_, ts := newRegisterSrv(t, Config{Register: true})
		defer ts.Close()

		code, res := postRegister(t, ts.URL, proto.RegisterReq{
			Account: "alice", Password: "0123456789", Fingerprint: fp,
		})
		if code != 200 || res.Token == "" || res.Machine != "alice+default" {
			t.Fatalf("注册失败: %d %+v", code, res)
		}
		if res.SSHPort != "7822" {
			t.Fatalf("SSH 端口没带上: %q", res.SSHPort)
		}

		// 同指纹换账号名再注册 → 409 + 既有账号名
		code, res = postRegister(t, ts.URL, proto.RegisterReq{
			Account: "mallory", Password: "0123456789", Fingerprint: fp,
		})
		if code != http.StatusConflict || res.Owner != "alice" {
			t.Fatalf("同指纹该 409+owner, got %d %+v", code, res)
		}
	})

	t.Run("邀请码校验", func(t *testing.T) {
		_, ts := newRegisterSrv(t, Config{Register: true, RegisterInvite: "secret7"})
		defer ts.Close()
		req := proto.RegisterReq{Account: "bob", Password: "0123456789", Fingerprint: strings.Repeat("b", 64)}
		code, _ := postRegister(t, ts.URL, req)
		if code != http.StatusForbidden {
			t.Fatalf("没邀请码该拒，got %d", code)
		}
		req.Invite = "wrong"
		code, _ = postRegister(t, ts.URL, req)
		if code != http.StatusForbidden {
			t.Fatalf("错邀请码该拒，got %d", code)
		}
		req.Invite = "secret7"
		code, res := postRegister(t, ts.URL, req)
		if code != 200 || res.Token == "" {
			t.Fatalf("对邀请码该过，got %d %+v", code, res)
		}
	})

	t.Run("自定义机器名", func(t *testing.T) {
		users, ts := newRegisterSrv(t, Config{Register: true})
		defer ts.Close()
		code, res := postRegister(t, ts.URL, proto.RegisterReq{
			Account: "carol", Password: "0123456789",
			Machine: "work", Fingerprint: strings.Repeat("c", 64),
		})
		if code != 200 || res.Machine != "carol+work" {
			t.Fatalf("自定义机器名没落上: %d %+v", code, res)
		}
		// 自动建的 default 应被清掉，不留没人能登的空机器
		for _, a := range users.List() {
			if a.Username == "carol" && len(a.Machines) != 1 {
				t.Fatalf("carol 的机器数应为 1（只留 work）: %+v", a.Machines)
			}
		}
	})

	t.Run("登录加机（register 关了也能用）", func(t *testing.T) {
		users, ts := newRegisterSrv(t, Config{Register: false})
		defer ts.Close()
		if _, err := users.Add("dave", "0123456789", nil, "", nil); err != nil {
			t.Fatal(err)
		}
		fpD := strings.Repeat("d", 64)

		// 密码错 → 403
		code, _ := postRegisterURL(t, ts.URL+"/register/machine", proto.RegisterReq{
			Account: "dave", Password: "wrongwrong", Machine: "laptop", Fingerprint: fpD})
		if code != http.StatusForbidden {
			t.Fatalf("密码错该 403，got %d", code)
		}
		// 密码对 → 建 laptop 机器，指纹绑到 dave
		code, res := postRegisterURL(t, ts.URL+"/register/machine", proto.RegisterReq{
			Account: "dave", Password: "0123456789", Machine: "laptop", Fingerprint: fpD})
		if code != 200 || res.Machine != "dave+laptop" || res.Token == "" {
			t.Fatalf("登录加机失败: %d %+v", code, res)
		}
		// 同名机器再来一次 → 重装语义，换新 token（和上一个不同）
		code, res2 := postRegisterURL(t, ts.URL+"/register/machine", proto.RegisterReq{
			Account: "dave", Password: "0123456789", Machine: "laptop", Fingerprint: fpD})
		if code != 200 || res2.Token == "" || res2.Token == res.Token {
			t.Fatalf("重装该换新 token: %d %+v", code, res2)
		}
		// 指纹绑给了 dave
		if owner, _ := users.FingerprintAccount(fpD); owner != "dave" {
			t.Fatalf("指纹该绑 dave, got %q", owner)
		}
	})

	t.Run("登录加机-指纹被别的账号占", func(t *testing.T) {
		users, ts := newRegisterSrv(t, Config{})
		defer ts.Close()
		if _, err := users.Add("eve", "0123456789", nil, "", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := users.Add("fred", "0123456789", nil, "", nil); err != nil {
			t.Fatal(err)
		}
		fpE := strings.Repeat("e", 64)
		if _, err := users.BindFingerprint(fpE, "eve"); err != nil {
			t.Fatal(err)
		}
		code, res := postRegisterURL(t, ts.URL+"/register/machine", proto.RegisterReq{
			Account: "fred", Password: "0123456789", Machine: "laptop", Fingerprint: fpE})
		if code != http.StatusConflict || res.Owner != "eve" {
			t.Fatalf("跨账号指纹该 409+owner, got %d %+v", code, res)
		}
	})

	t.Run("指纹必须是 64 位 hex", func(t *testing.T) {
		_, ts := newRegisterSrv(t, Config{Register: true})
		defer ts.Close()
		code, _ := postRegister(t, ts.URL, proto.RegisterReq{
			Account: "grace", Password: "0123456789",
			Fingerprint: "not-a-hex-fingerprint",
		})
		if code != http.StatusBadRequest {
			t.Fatalf("乱填的指纹该 400，got %d", code)
		}
	})

	t.Run("TOTP 自助管理（begin/confirm/remove）", func(t *testing.T) {
		users, ts := newRegisterSrv(t, Config{})
		defer ts.Close()
		acct, err := users.Add("ivy", "0123456789", nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		tok := acct.Machines[0].Token
		post := func(path, token string, body, out any) int {
			b, _ := json.Marshal(body)
			req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			if token != "" {
				req.Header.Set("X-Agent-Token", token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			_ = json.NewDecoder(resp.Body).Decode(out)
			return resp.StatusCode
		}
		// 没 token / 错密码 → 401
		var beg proto.TOTPBeginResp
		if code := post("/totp/begin", "", proto.TOTPBeginReq{Password: "0123456789"}, &beg); code != http.StatusUnauthorized {
			t.Fatalf("没 token 该 401，got %d", code)
		}
		if code := post("/totp/begin", tok, proto.TOTPBeginReq{Password: "nope"}, &beg); code != http.StatusUnauthorized {
			t.Fatalf("密码错该 401，got %d", code)
		}
		// token+密码 → 拿秘钥
		if code := post("/totp/begin", tok, proto.TOTPBeginReq{Password: "0123456789"}, &beg); code != 200 || beg.Secret == "" || !strings.HasPrefix(beg.URI, "otpauth://") || beg.Account != "ivy" {
			t.Fatalf("begin 失败: %d %+v", code, beg)
		}
		if beg.Bound {
			t.Fatal("还没绑就说 bound=true")
		}
		// begin 完没落库——confirm 一个错码 → 400，账号仍没绑
		secret, _ := totp.ParseSecret(beg.Secret)
		good := totp.Code(secret, time.Now())
		bad := "000000"
		if good == bad {
			bad = "111111" // 极小概率撞码，显式避开
		}
		var cf proto.TOTPConfirmResp
		if code := post("/totp/confirm", tok, proto.TOTPConfirmReq{
			Password: "0123456789", Secret: beg.Secret, Code: bad,
		}, &cf); code != http.StatusBadRequest {
			t.Fatalf("错码该 400，got %d", code)
		}
		if a, _ := users.Get("ivy"); a.TOTPEnabled {
			t.Fatal("confirm 没过不该绑上")
		}
		// 算真码 confirm → 200 且已绑
		if code := post("/totp/confirm", tok, proto.TOTPConfirmReq{
			Password: "0123456789", Secret: beg.Secret, Code: good,
		}, &cf); code != 200 || !cf.OK {
			t.Fatalf("正确码该绑上: %d %+v", code, cf)
		}
		if a, _ := users.Get("ivy"); !a.TOTPEnabled {
			t.Fatal("confirm 过了应已绑")
		}
		// 已绑：换绑必须给当前码——不给 → 403，错码 → 401
		beg = proto.TOTPBeginResp{}
		if code := post("/totp/begin", tok, proto.TOTPBeginReq{Password: "0123456789"}, &beg); code != 200 || !beg.Bound {
			t.Fatalf("已绑该 bound=true: %d %+v", code, beg)
		}
		newSecret, _ := totp.ParseSecret(beg.Secret)
		newGood := totp.Code(newSecret, time.Now())
		// 旧秘钥的"新"码要用下一个时间片——绑定确认用掉的那片不能重放。
		oldNext := totp.Code(secret, time.Now().Add(30*time.Second))
		if code := post("/totp/confirm", tok, proto.TOTPConfirmReq{
			Password: "0123456789", Secret: beg.Secret, Code: newGood,
		}, &cf); code != http.StatusForbidden {
			t.Fatalf("换绑不给旧码该 403，got %d", code)
		}
		if code := post("/totp/confirm", tok, proto.TOTPConfirmReq{
			Password: "0123456789", Secret: beg.Secret, Code: newGood, OldCode: bad,
		}, &cf); code != http.StatusUnauthorized {
			t.Fatalf("换绑旧码错该 401，got %d", code)
		}
		// 旧码对 → 换绑成功，旧秘钥作废
		if code := post("/totp/confirm", tok, proto.TOTPConfirmReq{
			Password: "0123456789", Secret: beg.Secret, Code: newGood, OldCode: oldNext,
		}, &cf); code != 200 || !cf.OK {
			t.Fatalf("换绑该成: %d %+v", code, cf)
		}
		if users.VerifyTOTP("ivy", totp.Code(secret, time.Now())) {
			t.Fatal("换绑后旧秘钥不该再验过")
		}
		// 解绑：没码 → 403 need_code；带码（新秘钥的下一时间片）→ 200
		var rm proto.TOTPRemoveResp
		if code := post("/totp/remove", tok, proto.TOTPRemoveReq{Password: "0123456789"}, &rm); code != http.StatusForbidden || !rm.NeedCode {
			t.Fatalf("解绑不给码该 403+need_code: %d %+v", code, rm)
		}
		if code := post("/totp/remove", tok, proto.TOTPRemoveReq{Password: "0123456789", Code: totp.Code(newSecret, time.Now().Add(30*time.Second))}, &rm); code != 200 || !rm.OK {
			t.Fatalf("带码解绑该成: %d %+v", code, rm)
		}
		if a, _ := users.Get("ivy"); a.TOTPEnabled {
			t.Fatal("解绑后不应再绑")
		}
		// 没绑过的账号解绑只要密码
		if code := post("/totp/remove", tok, proto.TOTPRemoveReq{Password: "0123456789"}, &rm); code != 200 || !rm.OK {
			t.Fatalf("未绑账号解绑该直接成: %d %+v", code, rm)
		}
	})

	t.Run("每 IP 限速", func(t *testing.T) {
		_, ts := newRegisterSrv(t, Config{Register: true})
		defer ts.Close()
		last := 0
		for i := 0; i < registerPerIPMax+2; i++ {
			code, _ := postRegister(t, ts.URL, proto.RegisterReq{
				Account:  "ratelimit" + string(rune('a'+i)),
				Password: "0123456789", Fingerprint: strings.Repeat(string(rune('d'+i)), 64),
			})
			last = code
		}
		if last != http.StatusTooManyRequests {
			t.Fatalf("超限额该 429，got %d", last)
		}
	})
}
