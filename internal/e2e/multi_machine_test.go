package e2e

// 一个账号挂多台机器（账号+机器名）的端到端测试。

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ws2ssh/internal/mcpsrv"
	"ws2ssh/internal/server"
)

// sshExec 无 PTY 执行一条命令并拿回 stdout（机器路由是否走对就看它）。
func sshExec(t *testing.T, sshPort int, user, password, cmd string) (string, error) {
	t.Helper()
	cfg := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.Password(password)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
	if err != nil {
		return "", err
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(cmd)
	return string(out), err
}

// auditHasCmd 轮询 agent 审计日志直到出现包含 sub 的行（agent 异步落盘）。
func auditHasCmd(path, sub string) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(path)
		if strings.Contains(string(raw), sub) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// TestMultiMachineCoexist 一个账号两台机器同时在线：互不顶替
// （不出 AGENT-REPLACE），指名登录各自落在各自的 agent 上。
func TestMultiMachineCoexist(t *testing.T) {
	srvAudit := filepath.Join(t.TempDir(), "server-audit.log")
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{AuditLog: srvAudit})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	build, err := users.AddMachine("alice", "build", nil)
	if err != nil {
		t.Fatal(err)
	}

	defAudit := startAgent(t, httpPort, acct.Machines[0].Token, "host-default")
	buildAudit := startAgent(t, httpPort, build.Token, "host-build")
	waitAgent(t, srv.Hub, "alice+default")
	waitAgent(t, srv.Hub, "alice+build")

	// 两台都挂着，谁也没顶掉谁
	if !srv.Hub.Has("alice+default") || !srv.Hub.Has("alice+build") {
		t.Fatalf("两台机器都应在线: %v", srv.Hub.Names())
	}
	if got := srv.Hub.MachinesOf("alice"); len(got) != 2 {
		t.Fatalf("MachinesOf(alice) = %v", got)
	}

	// 指名执行：命令落到对应那台的 agent 审计里（同一测试机上
	// 两个 agent 进程只能靠各自的审计日志区分）
	if _, err := sshExec(t, sshPort, "alice+default", "alicepw123", "echo marker-default"); err != nil {
		t.Fatalf("alice+default 执行失败: %v", err)
	}
	if _, err := sshExec(t, sshPort, "alice+build", "alicepw123", "echo marker-build"); err != nil {
		t.Fatalf("alice+build 执行失败: %v", err)
	}
	if !auditHasCmd(defAudit, "marker-default") {
		raw, _ := os.ReadFile(defAudit)
		t.Fatalf("default 的 agent 审计应记 marker-default:\n%s", raw)
	}
	if !auditHasCmd(buildAudit, "marker-build") {
		raw, _ := os.ReadFile(buildAudit)
		t.Fatalf("build 的 agent 审计应记 marker-build:\n%s", raw)
	}
	if raw, _ := os.ReadFile(defAudit); strings.Contains(string(raw), "marker-build") {
		t.Fatalf("build 的命令串到了 default 的 agent 上:\n%s", raw)
	}
	if raw, _ := os.ReadFile(buildAudit); strings.Contains(string(raw), "marker-default") {
		t.Fatalf("default 的命令串到了 build 的 agent 上:\n%s", raw)
	}

	// 服务器审计里上线的是两个机器 ID，且没有 AGENT-REPLACE
	deadline := time.Now().Add(2 * time.Second)
	var srvRaw string
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(srvAudit)
		srvRaw = string(raw)
		if strings.Contains(srvRaw, "alice+default") && strings.Contains(srvRaw, "alice+build") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Contains(srvRaw, "AGENT-REPLACE") {
		t.Fatalf("同账号两台机器不应互相顶替:\n%s", srvRaw)
	}
}

// TestMultiMachineAmbiguousLogin 多台机器时不带后缀的登录被拒并列出候选；
// 删到只剩一台后不带后缀恢复可用。
func TestMultiMachineAmbiguousLogin(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.AddMachine("alice", "build", nil); err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")
	// build 故意不上线，错误里应标（离线）

	msg := sshTry(t, sshPort, "alice", "alicepw123")
	if !strings.Contains(msg, "多台机器") || !strings.Contains(msg, "alice+default") || !strings.Contains(msg, "alice+build") {
		t.Fatalf("不带后缀应列出机器候选: %q", msg)
	}
	if !strings.Contains(msg, "在线") || !strings.Contains(msg, "离线") {
		t.Fatalf("应带在线状态: %q", msg)
	}

	// 删掉 build 后回到单机语义
	if err := users.RemoveMachine("alice", "build"); err != nil {
		t.Fatal(err)
	}
	if _, err := sshExec(t, sshPort, "alice", "alicepw123", "echo hello-solo"); err != nil {
		t.Fatalf("单机后不带后缀应能进: %v", err)
	}
}

// TestPerMachineTokenRevoke 换 build 的 token：build 的已连接 agent
// 立刻不能接会话，default 不受影响。
func TestPerMachineTokenRevoke(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	build, err := users.AddMachine("alice", "build", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	startAgent(t, httpPort, build.Token, "h2")
	waitAgent(t, srv.Hub, "alice+default")
	waitAgent(t, srv.Hub, "alice+build")

	if _, err := users.RegenMachineToken("alice", "build"); err != nil {
		t.Fatal(err)
	}
	// 新会话复核凭据：build 拒，default 通
	if msg := sshTry(t, sshPort, "alice+build", "alicepw123"); !strings.Contains(msg, "凭据已失效") {
		t.Fatalf("build 换 token 后新会话应被拒: %q", msg)
	}
	if _, err := sshExec(t, sshPort, "alice+default", "alicepw123", "echo still-here"); err != nil {
		t.Fatalf("default 不应受牵连: %v", err)
	}
	if !srv.Hub.Has("alice+default") {
		t.Fatal("default 应仍在线")
	}
}

// TestMultiMachineMCPGrants MCP 的 --machine 四种写法：alice+* 看两台，
// alice+build 只看一台，run_command 指名落到 build。
func TestMultiMachineMCPGrants(t *testing.T) {
	dir := t.TempDir()
	mc := &mcpsrv.Config{
		Machines:     map[string]*mcpsrv.Machine{},
		ApprovalsDir: filepath.Join(dir, "approvals"),
	}
	mc.Policy.Default = "run"
	mc.ApplyDefaults()
	if err := mc.Validate(); err != nil {
		t.Fatal(err)
	}
	srv, httpPort, _, users := startServerOpt(t, server.Config{MCP: mc, AuditLog: filepath.Join(dir, "audit.log")})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	build, err := users.AddMachine("alice", "build", nil)
	if err != nil {
		t.Fatal(err)
	}
	defAudit := startAgent(t, httpPort, acct.Machines[0].Token, "h-def")
	buildAudit := startAgent(t, httpPort, build.Token, "h-build")
	waitAgent(t, srv.Hub, "alice+default")
	waitAgent(t, srv.Hub, "alice+build")

	listNames := func(tok string) []string {
		t.Helper()
		cs, err := mcpHTTPConnect(t, httpPort, tok, nil)
		if err != nil {
			t.Fatalf("连接失败: %v", err)
		}
		defer cs.Close()
		res := callTool(t, cs, "list_machines", nil)
		var lo struct {
			Machines []struct {
				Name      string `json:"name"`
				Connected bool   `json:"connected"`
			} `json:"machines"`
		}
		decodeStructured(t, res, &lo)
		var names []string
		for _, m := range lo.Machines {
			names = append(names, m.Name)
			if !m.Connected {
				t.Fatalf("%s 应在线", m.Name)
			}
		}
		return names
	}

	// alice+* → 两台
	_, tokAll, err := users.MCPAdd("all-alice", []string{"alice+*"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := listNames(tokAll)
	if len(names) != 2 {
		t.Fatalf("alice+* 应看到两台: %v", names)
	}

	// alice+build → 只有一台
	_, tokBuild, err := users.MCPAdd("only-build", []string{"alice+build"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	names = listNames(tokBuild)
	if len(names) != 1 || names[0] != "alice+build" {
		t.Fatalf("alice+build 应只看到一台: %v", names)
	}

	// run_command 指名 alice+build → 落到 build 那台的 agent 审计
	cs, err := mcpHTTPConnect(t, httpPort, tokBuild, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res := callTool(t, cs, "run_command", map[string]any{
		"machine": "alice+build", "command": "echo mcp-build-marker",
	})
	if res.IsError {
		t.Fatalf("run_command alice+build 失败: %s", resultText(res))
	}
	if !auditHasCmd(buildAudit, "mcp-build-marker") {
		raw, _ := os.ReadFile(buildAudit)
		t.Fatalf("命令应落在 build 的 agent 上:\n%s", raw)
	}
	if raw, _ := os.ReadFile(defAudit); strings.Contains(string(raw), "mcp-build-marker") {
		t.Fatalf("命令串到了 default 的 agent 上:\n%s", raw)
	}
}

// TestMultiMachineStatus /status：机器 token 只看自己那一台，管理口令看全部。
func TestMultiMachineStatus(t *testing.T) {
	srv, httpPort, _, users := startServerOpt(t, server.Config{AdminToken: "admin-secret-1"})
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	build, err := users.AddMachine("alice", "build", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")
	// build 保持离线

	get := func(hdr, val string) string {
		t.Helper()
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/status", httpPort), nil)
		req.Header.Set(hdr, val)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	// build 的机器 token：只看自己（离线的自己也看得到，503 不拦 body）
	body := get("X-Agent-Token", build.Token)
	if !strings.Contains(body, "alice+build") || strings.Contains(body, "alice+default") {
		t.Fatalf("机器 token 应只看自己那一台: %s", body)
	}

	// 管理口令：两台都在（含离线的）
	body = get("X-Admin-Token", "admin-secret-1")
	if !strings.Contains(body, "alice+default") || !strings.Contains(body, "alice+build") {
		t.Fatalf("管理口令应看到两台: %s", body)
	}
}
