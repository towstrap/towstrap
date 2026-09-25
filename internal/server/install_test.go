package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

	t.Run("预设配置和 SSH 端口填进脚本", func(t *testing.T) {
		s := New(Config{
			Users:         users,
			PublicURL:     "wss://ts.example.com",
			SSHAddr:       ":7922",
			AgentDefaults: "mirror_idle: 48h\nquiet: true\n",
		})
		ts := httptest.NewServer(s.routes())
		defer ts.Close()

		code, body := get(t, ts.URL, "/install.sh")
		if code != 200 {
			t.Fatalf("GET /install.sh = %d", code)
		}
		for _, marker := range []string{
			"__TOWSTRAP_DEFAULT_SERVER__", "__TOWSTRAP_DEFAULT_VERSION__",
			"__TOWSTRAP_AGENT_CONFIG__", "__TOWSTRAP_SSH_PORT__",
		} {
			if strings.Contains(body, marker) {
				t.Fatalf("占位符 %s 没被替换", marker)
			}
		}
		if !strings.Contains(body, "mirror_idle: 48h") || !strings.Contains(body, "quiet: true") {
			t.Fatal("agent_defaults 预设没进 install.sh")
		}
		if !strings.Contains(body, `SSH_PORT="7922"`) {
			t.Fatal("SSH 端口没按服务器配置填")
		}

		// 回归：占位符是全文件替换，运行时的"未替换"检测必须只认
		// __TOWSTRAP 前缀——否则下发的真值会被误判后重置回默认值。
		// 光看文本发现不了，把脚本 --check 真跑一遍验解析结果。
		if runtime.GOOS != "windows" {
			sh := filepath.Join(t.TempDir(), "install.sh")
			if err := os.WriteFile(sh, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("sh", sh, "--check").Output()
			if err != nil {
				t.Fatalf("install.sh --check 跑挂了: %v", err)
			}
			checks := map[string]string{
				"server=":   "wss://ts.example.com",
				"ssh_port=": "7922",
				"ssh_host=": "ts.example.com",
				"version=":  "v", // v0.3.0 之类，前缀是 v
			}
			for k, want := range checks {
				got := ""
				for _, line := range strings.Split(string(out), "\n") {
					if strings.HasPrefix(line, k) {
						got = strings.TrimPrefix(line, k)
					}
				}
				if !strings.HasPrefix(got, want) {
					t.Fatalf("--check 里 %s 该是 %s 开头，实得 %q", k, want, got)
				}
			}
			if !strings.Contains(string(out), "agent_conf=mirror_idle: 48h") {
				t.Fatalf("--check 里 agent_conf 丢了预设: %s", out)
			}

			// GitHub raw 直拉的脚本（占位符原样）：回落到官方服务器 +
			// latest + 默认 SSH 口、无预设。
			raw, err := os.ReadFile("../../scripts/install.sh")
			if err != nil {
				t.Fatal(err)
			}
			rawSh := filepath.Join(t.TempDir(), "install.sh")
			if err := os.WriteFile(rawSh, raw, 0o700); err != nil {
				t.Fatal(err)
			}
			out, err = exec.Command("sh", rawSh, "--check").Output()
			if err != nil {
				t.Fatalf("raw install.sh --check 跑挂了: %v", err)
			}
			s := string(out)
			for _, want := range []string{
				"server=wss://towstrap.vast-plan.com",
				"version=latest", "ssh_port=7822",
				"ssh_host=towstrap.vast-plan.com", "agent_conf=\n",
			} {
				if !strings.Contains(s, want) {
					t.Fatalf("raw 脚本 --check 缺 %s:\n%s", want, s)
				}
			}
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
