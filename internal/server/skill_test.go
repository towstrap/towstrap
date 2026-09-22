package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/skills"
)

// TestSkillEndpoint /skill 公开返回随项目发布的 LLM skill 原文，
// 让不装 towstrap-mcp 的用户也能 curl 下来手工安装。
func TestSkillEndpoint(t *testing.T) {
	users, err := accounts.Open(filepath.Join(t.TempDir(), "u.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Close()
	s := New(Config{Users: users})
	ts := httptest.NewServer(s.routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/skill")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /skill = %d，想要 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/markdown") {
		t.Fatalf("Content-Type = %q，想要含 text/markdown", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != string(skills.SkillMD()) {
		t.Fatal("body 和内嵌的 SKILL.md 不一致")
	}

	// HEAD 同样放行（不写 body 由 net/http 处理）。
	req, _ := http.NewRequest(http.MethodHead, ts.URL+"/skill", nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("HEAD /skill = %d，想要 200", resp2.StatusCode)
	}

	// 非 GET/HEAD → 405。
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/skill", nil)
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /skill = %d，想要 405", resp3.StatusCode)
	}
}
