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

// TestInstallEndpoints /install.sh、/install.ps1 公开返回一键安装脚本，
// 占位符换成这台服务器的地址：public_url 优先，否则按请求推导。
func TestInstallEndpoints(t *testing.T) {
	users, err := accounts.Open(filepath.Join(t.TempDir(), "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Close()

	get := func(t *testing.T, base, path string) (int, string) {
		t.Helper()
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	t.Run("public_url 优先", func(t *testing.T) {
		s := New(Config{Users: users, PublicURL: "wss://ts.example.com:8443"})
		ts := httptest.NewServer(s.routes())
		defer ts.Close()

		code, body := get(t, ts.URL, "/install.sh")
		if code != 200 {
			t.Fatalf("GET /install.sh = %d", code)
		}
		if !strings.Contains(body, `DEFAULT_SERVER="wss://ts.example.com:8443"`) {
			t.Fatal("脚本里没填上 public_url")
		}
		if strings.Contains(body, "__TOWSTRAP_DEFAULT_SERVER__") {
			t.Fatal("占位符没被替换")
		}
		if strings.Contains(body, "__TOWSTRAP_DEFAULT_VERSION__") {
			t.Fatal("版本占位符没被替换")
		}
		if !strings.Contains(body, "--token") {
			t.Fatal("脚本不像 install.sh")
		}

		code, body = get(t, ts.URL, "/install.ps1")
		if code != 200 || !strings.Contains(body, "wss://ts.example.com:8443") {
			t.Fatalf("install.ps1 code=%d 或没填地址", code)
		}
	})

	t.Run("没配 public_url 按请求推导", func(t *testing.T) {
		s := New(Config{Users: users})
		ts := httptest.NewServer(s.routes()) // 无 TLS → ws://
		defer ts.Close()

		host := strings.TrimPrefix(ts.URL, "http://")
		code, body := get(t, ts.URL, "/install.sh")
		if code != 200 {
			t.Fatalf("GET /install.sh = %d", code)
		}
		if !strings.Contains(body, `DEFAULT_SERVER="ws://`+host+`"`) {
			t.Fatalf("脚本该填 ws://%s，实际脚本头：\n%.300s", host, body)
		}
	})

	t.Run("TLS 请求推导出 wss", func(t *testing.T) {
		s := New(Config{Users: users})
		ts := httptest.NewTLSServer(s.routes())
		defer ts.Close()
		c := ts.Client()

		host := strings.TrimPrefix(ts.URL, "https://")
		resp, err := c.Get(ts.URL + "/install.sh")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), `DEFAULT_SERVER="wss://`+host+`"`) {
			t.Fatalf("TLS 下该填 wss://%s", host)
		}
	})

	t.Run("非 GET/HEAD 405", func(t *testing.T) {
		s := New(Config{Users: users})
		ts := httptest.NewServer(s.routes())
		defer ts.Close()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/install.sh", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST /install.sh = %d，想要 405", resp.StatusCode)
		}
	})
}
