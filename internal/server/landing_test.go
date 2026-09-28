package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/towstrap/towstrap/internal/accounts"
)

// TestLanding 落地页渲染：所有占位符都必须被替换（模板里漏配的 {{X}}
// 会直接漏给浏览器），关键区块要在。
func TestLanding(t *testing.T) {
	users, err := accounts.Open(filepath.Join(t.TempDir(), "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Close()

	for _, register := range []bool{false, true} {
		s := New(Config{Users: users, PublicURL: "wss://ts.example.com", SSHAddr: ":7922", Register: register})
		ts := httptest.NewServer(s.routes())

		get := func(url, acceptLang string) string {
			req, _ := http.NewRequest("GET", url, nil)
			if acceptLang != "" {
				req.Header.Set("Accept-Language", acceptLang)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return string(body)
		}

		page := get(ts.URL+"/", "")
		if i := strings.Index(page, "{{"); i >= 0 {
			t.Fatalf("register=%v：页面还有未替换的占位符：…%s", register, page[i:i+40])
		}
		for _, want := range []string{"安装 agent", "SSH 客户端推荐", "自行部署", "/install-server.sh", "Termius", "mirror"} {
			if !strings.Contains(page, want) {
				t.Fatalf("register=%v：落地页缺 %q", register, want)
			}
		}
		// 注册开关改变安装指引：开=register 步、无 token 参；关=带 --token。
		if register {
			if !strings.Contains(page, "towstrap register") || strings.Contains(page, "--token tsa-") {
				t.Fatal("开注册的页面该引导 register 且不出现 --token")
			}
		} else if !strings.Contains(page, "--token tsa-") {
			t.Fatal("关注册的页面该带 --token 提示")
		}

		// 英文版：?lang=en 显式参数与 Accept-Language 偏好都要命中；
		// 占位符同样必须全部替换，且不能混入中文界面文字。
		for _, enPage := range []string{
			get(ts.URL+"/?lang=en", ""),
			get(ts.URL+"/", "en-US,en;q=0.9"),
		} {
			if i := strings.Index(enPage, "{{"); i >= 0 {
				t.Fatalf("register=%v：英文页还有未替换的占位符：…%s", register, enPage[i:i+40])
			}
			for _, want := range []string{"Install the agent", "SSH clients", "Self-host", "/install-server.sh", "Copy"} {
				if !strings.Contains(enPage, want) {
					t.Fatalf("register=%v：英文落地页缺 %q", register, want)
				}
			}
			if strings.Contains(enPage, "安装 agent") {
				t.Fatalf("register=%v：英文页混入了中文标题", register)
			}
			if register {
				if !strings.Contains(enPage, "towstrap register") || strings.Contains(enPage, "--token tsa-") {
					t.Fatal("英文开注册页该引导 register 且不出现 --token")
				}
			} else if !strings.Contains(enPage, "--token tsa-") {
				t.Fatal("英文关注册页该带 --token 提示")
			}
		}

		// 显式 ?lang=zh 压过英文 Accept-Language
		if zh := get(ts.URL+"/?lang=zh", "en-US"); !strings.Contains(zh, "安装 agent") {
			t.Fatal("?lang=zh 应优先于 Accept-Language")
		}
		ts.Close()
	}
}
