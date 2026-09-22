package e2e

// POST /token/refresh：在 agent 机器上发起 token 换发。服务器把新 token
// 经目标 agent 的 WebSocket 下推，agent 写进 token 文件回 ack 后才落库。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"towstrap/internal/client"
	"towstrap/internal/server"
	"towstrap/internal/totp"
)

func gosshPassword() gossh.AuthMethod { return gossh.Password("alicepw123") }

// startAgentFile 起一个 token 从文件读的 agent（远程换发的前提：服务器
// 下推的新 token 要写进这个文件）。返回 agent 审计日志路径。
func startAgentFile(t *testing.T, httpPort int, tokenPath, token, helloName string) string {
	t.Helper()
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(t.TempDir(), "audit.log")
	go func() {
		_ = client.ConnectOnce(client.Config{
			ID:         helloName,
			Server:     fmt.Sprintf("ws://127.0.0.1:%d", httpPort),
			AgentToken: token,
			TokenFile:  tokenPath,
			Shell:      "/bin/bash",
			Quiet:      true,
			AuditLog:   audit,
		})
	}()
	return audit
}

// postRefresh 直接打 /token/refresh 端点，返回状态码和解析后的 results。
func postRefresh(t *testing.T, httpPort int, token string, body map[string]any) (int, []map[string]string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/token/refresh", httpPort), bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Agent-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var parsed struct {
		Results []map[string]string `json:"results"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&parsed)
	return resp.StatusCode, parsed.Results
}

// TestTokenRefreshE2E 换发主流程：A 机器发起，all=true 换全账号两台；两个
// token 文件都写成新值、库里也换了、旧 token 失效、连接不断且凭据已更新。
func TestTokenRefreshE2E(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "server-audit.log")
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{AuditLog: audit})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	build, err := users.AddMachine("alice", "build", nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fileA := filepath.Join(dir, "token-a")
	fileB := filepath.Join(dir, "token-b")
	startAgentFile(t, httpPort, fileA, acct.Machines[0].Token, "host-a")
	startAgentFile(t, httpPort, fileB, build.Token, "host-b")
	waitAgent(t, srv.Hub, "alice+default")
	waitAgent(t, srv.Hub, "alice+build")

	var out bytes.Buffer
	code := client.TokenRefresh(client.RefreshOpts{
		Server: fmt.Sprintf("ws://127.0.0.1:%d", httpPort),
		Token:  acct.Machines[0].Token, // 用 A 的 token 发起
		All:    true,
	}, strings.NewReader("alicepw123\n\n"), &out)
	if code != 0 {
		t.Fatalf("换发应成功: code=%d out=%q", code, out.String())
	}
	for _, id := range []string{"alice+default", "alice+build"} {
		if !strings.Contains(out.String(), id+"  ok") {
			t.Fatalf("输出应有 %s ok: %q", id, out.String())
		}
	}

	// 两个文件都写成新 token，库里也换了
	for i, p := range []string{fileA, fileB} {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		newTok := strings.TrimSpace(string(raw))
		if !strings.HasPrefix(newTok, "tsa-") {
			t.Fatalf("文件 %d 里应是新 token: %q", i, newTok)
		}
		m, ok := users.MachineByToken(newTok)
		if !ok {
			t.Fatalf("文件 %d 的新 token 库里查不到", i)
		}
		want := "alice+default"
		if i == 1 {
			want = "alice+build"
		}
		if m.ID() != want {
			t.Fatalf("文件 %d 的 token 应对应 %s，实际 %s", i, want, m.ID())
		}
	}
	// 旧 token 失效
	if _, ok := users.MachineByToken(acct.Machines[0].Token); ok {
		t.Fatal("A 的旧 token 应已失效")
	}
	if _, ok := users.MachineByToken(build.Token); ok {
		t.Fatal("B 的旧 token 应已失效")
	}
	// 连接没断，agent 记住的凭据也换了：不然开会话时复核会把它们当失效踢掉
	if !srv.Hub.Has("alice+default") || !srv.Hub.Has("alice+build") {
		t.Fatal("换发不该断开现有连接")
	}
	// 换发后两台都还能开 shell（exec 通道，命令转发给 agent 执行）
	for _, id := range []string{"alice+default", "alice+build"} {
		c := mgmtDial(t, sshPort, id, gosshPassword())
		out, se, code := runMgmt(t, c, "echo hello-"+id, "")
		if code != 0 || !strings.Contains(out, "hello-"+id) {
			t.Fatalf("%s 换发后应仍能开 shell: code=%d out=%q stderr=%q", id, code, out, se)
		}
	}
	raw, _ := os.ReadFile(audit)
	if n := strings.Count(string(raw), "TOKEN-REFRESH"); n < 2 || strings.Count(string(raw), "status=ok") < 2 {
		t.Fatalf("审计应有两台机器的 TOKEN-REFRESH status=ok:\n%s", raw)
	}
}

// TestTokenRefreshBadPassword 密码错 → 401 + 审计 reason=password；
// 连错 5 次后第 6 次 429 locked（和登录同一个限速器）。
func TestTokenRefreshBadPassword(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "server-audit.log")
	srv, httpPort, _, users := startServerOpt(t, server.Config{AuditLog: audit})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	for i := 0; i < 5; i++ {
		code, _ := postRefresh(t, httpPort, acct.Machines[0].Token,
			map[string]any{"password": "wrong-password", "totp": ""})
		if code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次错密码应 401: %d", i+1, code)
		}
	}
	code, _ := postRefresh(t, httpPort, acct.Machines[0].Token,
		map[string]any{"password": "alicepw123", "totp": ""})
	if code != http.StatusTooManyRequests {
		t.Fatalf("连错 5 次后应 429: %d", code)
	}
	raw, _ := os.ReadFile(audit)
	if !strings.Contains(string(raw), "TOKEN-REFRESH-DENY") || !strings.Contains(string(raw), "reason=password") {
		t.Fatalf("审计应有 TOKEN-REFRESH-DENY reason=password:\n%s", raw)
	}
	if !strings.Contains(string(raw), "reason=locked") {
		t.Fatalf("审计应有 reason=locked:\n%s", raw)
	}
}

// TestTokenRefreshTOTP 绑了 TOTP 的账号：码错 401 reason=totp；当前码 + 密码 ok。
func TestTokenRefreshTOTP(t *testing.T) {
	srv, httpPort, _, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fileA := filepath.Join(dir, "token-a")
	startAgentFile(t, httpPort, fileA, acct.Machines[0].Token, "host-a")
	waitAgent(t, srv.Hub, "alice+default")

	secret, _ := totp.Generate("towstrap", "alice")
	if err := users.EnrollTOTP("alice", secret, time.Now().Unix()/30-1); err != nil {
		t.Fatal(err)
	}
	bad := totp.Code(secret, time.Now())
	bad = string(map[bool]byte{true: '1', false: '0'}[bad[0] == '0']) + bad[1:]
	code, _ := postRefresh(t, httpPort, acct.Machines[0].Token,
		map[string]any{"password": "alicepw123", "totp": bad})
	if code != http.StatusUnauthorized {
		t.Fatalf("码错应 401: %d", code)
	}
	code, results := postRefresh(t, httpPort, acct.Machines[0].Token,
		map[string]any{"password": "alicepw123", "totp": totp.Code(secret, time.Now())})
	if code != http.StatusOK || len(results) != 1 || results[0]["status"] != "ok" {
		t.Fatalf("正确码应换发成功: code=%d results=%v", code, results)
	}
	raw, _ := os.ReadFile(fileA)
	if strings.TrimSpace(string(raw)) == acct.Machines[0].Token {
		t.Fatal("token 文件应已换成新值")
	}
}

// TestTokenRefreshNoFileTarget 目标（build）用非文件 token 起 → no-file，
// token 不变、agent 仍在线。
func TestTokenRefreshNoFileTarget(t *testing.T) {
	srv, httpPort, _, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	build, err := users.AddMachine("alice", "build", nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fileA := filepath.Join(dir, "token-a")
	startAgentFile(t, httpPort, fileA, acct.Machines[0].Token, "host-a")
	startAgent(t, httpPort, build.Token, "host-b") // build 的 token 是内嵌的，不是文件
	waitAgent(t, srv.Hub, "alice+default")
	waitAgent(t, srv.Hub, "alice+build")

	code, results := postRefresh(t, httpPort, acct.Machines[0].Token,
		map[string]any{"password": "alicepw123", "totp": "", "machines": []string{"build"}})
	if code != http.StatusOK {
		t.Fatalf("应返回 200（逐台给状态）: %d", code)
	}
	if len(results) != 1 || results[0]["status"] != "no-file" {
		t.Fatalf("build 应 no-file: %v", results)
	}
	m, _ := users.GetMachine("alice", "build")
	if m.Token != build.Token {
		t.Fatal("no-file 的机器 token 不该变")
	}
	if !srv.Hub.Has("alice+build") {
		t.Fatal("被拒的机器不该掉线")
	}
}

// TestTokenRefreshOfflineAndMissing 目标离线 → offline；不存在的名字 → not-found。
func TestTokenRefreshOfflineAndMissing(t *testing.T) {
	srv, httpPort, _, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.AddMachine("alice", "build", nil); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fileA := filepath.Join(dir, "token-a")
	startAgentFile(t, httpPort, fileA, acct.Machines[0].Token, "host-a")
	waitAgent(t, srv.Hub, "alice+default")

	code, results := postRefresh(t, httpPort, acct.Machines[0].Token,
		map[string]any{"password": "alicepw123", "totp": "", "machines": []string{"build", "ghost"}})
	if code != http.StatusOK || len(results) != 2 {
		t.Fatalf("应 200 且两台都有回执: %d %v", code, results)
	}
	status := map[string]string{}
	for _, r := range results {
		status[r["machine"]] = r["status"]
	}
	if status["alice+build"] != "offline" || status["alice+ghost"] != "not-found" {
		t.Fatalf("状态不对: %v", status)
	}
}

// TestTokenRefreshAgentAllow 调用方机器设了 agent_allow_ips，来源不在
// 名单里 → 403。
func TestTokenRefreshAgentAllow(t *testing.T) {
	srv, httpPort, _, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", []string{"10.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	// agent 自己连不上没关系（白名单也会拦它的 /agent），这个用例只打
	// refresh 端点——403 应在鉴权前返回。
	code, _ := postRefresh(t, httpPort, acct.Machines[0].Token,
		map[string]any{"password": "alicepw123", "totp": ""})
	if code != http.StatusForbidden {
		t.Fatalf("来源不在白名单应 403: %d", code)
	}
	_ = srv
}
