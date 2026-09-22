package e2e

// 服务器内嵌 MCP（Streamable HTTP，/mcp）的端到端测试：
// 真 HTTP 口 + Bearer 认证 + Hub 直连执行，不走 SSH 回环。

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"towstrap/internal/accounts"
	"towstrap/internal/mcpsrv"
	"towstrap/internal/server"
)

// bearerRT 给每个请求挂上 Authorization: Bearer。
type bearerRT struct{ token string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// startMCPHTTP 起一台开了 /mcp 的服务器 + 一个叫 bot 的账号和它的 agent。
// 回环地址上的明文 HTTP 是允许的（mcpPlainHTTPAllowed 放行 loopback）。
func startMCPHTTP(t *testing.T) (srv *server.Server, httpPort int, users *accounts.Store, audit, approvalsDir, rootsDir string) {
	t.Helper()
	dir := t.TempDir()
	audit = filepath.Join(dir, "server-audit.log")
	approvalsDir = filepath.Join(dir, "approvals")
	rootsDir = t.TempDir()

	mc := &mcpsrv.Config{
		Machines: map[string]*mcpsrv.Machine{
			"bot+default": {Description: "测试机", Roots: []string{rootsDir}},
		},
		ApprovalsDir: approvalsDir,
	}
	mc.Policy.Default = "ask"
	mc.Policy.AskTimeout = 5 * time.Second
	mc.ApplyDefaults()
	if err := mc.Validate(); err != nil {
		t.Fatal(err)
	}

	srv, httpPort, _, users = startServerOpt(t, server.Config{
		MCP:      mc,
		AuditLog: audit,
	})
	acct, err := users.Add("bot", "unused-pw-12345", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h-mcp-http")
	waitAgent(t, srv.Hub, "bot+default")
	return srv, httpPort, users, audit, approvalsDir, rootsDir
}

// mcpHTTPConnect 用 Bearer token 连 /mcp；handler 非 nil 时客户端声明
// elicitation 能力。
func mcpHTTPConnect(t *testing.T, httpPort int, token string, opts *mcp.ClientOptions) (*mcp.ClientSession, error) {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "mcp-http-test", Version: "v0"}, opts)
	tr := &mcp.StreamableClientTransport{
		Endpoint:   fmt.Sprintf("http://127.0.0.1:%d/mcp", httpPort),
		HTTPClient: &http.Client{Transport: bearerRT{token}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.Connect(ctx, tr, nil)
}

func auditContains(path, sub string) bool {
	raw, _ := os.ReadFile(path)
	return strings.Contains(string(raw), sub)
}

func waitAudit(t *testing.T, path, sub string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if auditContains(path, sub) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	raw, _ := os.ReadFile(path)
	t.Fatalf("审计里没有 %q；现有内容:\n%s", sub, raw)
}

func TestMCPHTTPAuth(t *testing.T) {
	_, httpPort, users, audit, _, _ := startMCPHTTP(t)

	// 无 token、错 token 都过不去
	if _, err := mcpHTTPConnect(t, httpPort, "", nil); err == nil {
		t.Fatal("没 token 居然连上了")
	}
	if _, err := mcpHTTPConnect(t, httpPort, "tsm-错的", nil); err == nil {
		t.Fatal("错 token 居然连上了")
	}
	waitAudit(t, audit, "MCP-AUTH-FAIL")

	// 客户端自己的 allow_ips 不匹配也拒
	if _, _, err := users.MCPAdd("vpn-only", []string{"bot"}, []string{"10.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	_, tok, err := users.MCPAdd("laptop", []string{"bot"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 先验证好 token 能连
	cs, err := mcpHTTPConnect(t, httpPort, tok, nil)
	if err != nil {
		t.Fatalf("正确 token 连不上: %v", err)
	}
	_ = cs.Close()

	c2, tok2, err := users.MCPAdd("locked", []string{"bot"}, []string{"10.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	_ = c2
	if _, err := mcpHTTPConnect(t, httpPort, tok2, nil); err == nil {
		t.Fatal("allow_ips 不匹配的客户端居然连上了")
	}

	// 停用后拒
	tru := true
	if err := users.MCPSet("laptop", nil, nil, &tru); err != nil {
		t.Fatal(err)
	}
	if _, err := mcpHTTPConnect(t, httpPort, tok, nil); err == nil {
		t.Fatal("停用客户端居然连上了")
	}
}

func TestMCPHTTPTools(t *testing.T) {
	_, httpPort, users, audit, _, rootsDir := startMCPHTTP(t)
	_, tok, err := users.MCPAdd("laptop", []string{"bot"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	calls := &atomic.Int32{}
	opts := &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			calls.Add(1)
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
		},
	}
	cs, err := mcpHTTPConnect(t, httpPort, tok, opts)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer cs.Close()

	// list_machines：只有 bot，在线
	res := callTool(t, cs, "list_machines", nil)
	var lo struct {
		Machines []struct {
			Name      string `json:"name"`
			Connected bool   `json:"connected"`
		} `json:"machines"`
	}
	decodeStructured(t, res, &lo)
	if len(lo.Machines) != 1 || lo.Machines[0].Name != "bot+default" || !lo.Machines[0].Connected {
		t.Fatalf("list_machines: %+v", lo)
	}

	// allow 名单内的命令直接跑
	res, out := runHTTP(t, cs, "echo hi", nil)
	if res.IsError || out.ExitCode != 0 || out.Stdout != "hi\n" {
		t.Fatalf("echo hi: IsError=%v out=%+v", res.IsError, out)
	}
	if out.Approval != "allowed" || calls.Load() != 0 {
		t.Fatalf("echo hi 不该弹批准: approval=%q calls=%d", out.Approval, calls.Load())
	}

	// 不在名单内的命令 → 弹窗 → 批准 → 执行
	target := filepath.Join(t.TempDir(), "x")
	res, out = runHTTP(t, cs, "touch "+target, nil)
	if res.IsError || out.Approval != "approved" {
		t.Fatalf("批准后 touch 应成功: %s %+v", resultText(res), out)
	}
	if calls.Load() != 1 {
		t.Fatalf("touch 应弹 1 次批准，弹了 %d", calls.Load())
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("文件应已创建: %v", err)
	}

	// write_file 到 roots 内不弹窗；read_file 读回
	in := filepath.Join(rootsDir, "a.txt")
	res = callTool(t, cs, "write_file", map[string]any{
		"machine": "bot+default", "path": in, "content": "你好",
	})
	if res.IsError {
		t.Fatalf("roots 内 write_file 应自动放行: %s", resultText(res))
	}
	res = callTool(t, cs, "read_file", map[string]any{"machine": "bot+default", "path": in})
	var ro struct {
		Content string `json:"content"`
	}
	decodeStructured(t, res, &ro)
	if ro.Content != "你好" {
		t.Fatalf("read_file 内容不对: %q", ro.Content)
	}

	// roots 外 write_file → 弹窗
	outside := filepath.Join(t.TempDir(), "b.txt")
	res = callTool(t, cs, "write_file", map[string]any{
		"machine": "bot+default", "path": outside, "content": "x",
	})
	if res.IsError {
		t.Fatalf("批准后 roots 外 write 应成功: %s", resultText(res))
	}
	if calls.Load() != 2 {
		t.Fatalf("roots 外 write 应再弹一次，共 %d", calls.Load())
	}

	// 审计：SESSION-START 带 mode=mcp 和 mcp: 前缀来源，批准事件齐
	waitAudit(t, audit, "mode=mcp")
	waitAudit(t, audit, "from=mcp:laptop@")
	if !auditContains(audit, "MCP-ASK") || !auditContains(audit, "MCP-APPROVED") {
		raw, _ := os.ReadFile(audit)
		t.Fatalf("批准审计缺失:\n%s", raw)
	}
}

func TestMCPHTTPDecline(t *testing.T) {
	_, httpPort, users, _, _, _ := startMCPHTTP(t)
	_, tok, _ := users.MCPAdd("laptop", []string{"bot"}, nil)
	opts := &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": false}}, nil
		},
	}
	cs, err := mcpHTTPConnect(t, httpPort, tok, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, _ := runHTTP(t, cs, "touch /tmp/mcp-decline-x", nil)
	if !res.IsError || !strings.Contains(resultText(res), "拒绝") {
		t.Fatalf("用户拒绝应是错误结果: %v %s", res.IsError, resultText(res))
	}
}

func TestMCPHTTPTimeout(t *testing.T) {
	_, httpPort, users, _, _, _ := startMCPHTTP(t)
	_, tok, _ := users.MCPAdd("laptop", []string{"bot"}, nil)
	opts := &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
		},
	}
	cs, err := mcpHTTPConnect(t, httpPort, tok, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, out := runHTTP(t, cs, "sleep 5", map[string]any{"timeout_seconds": 1})
	if res.IsError || !out.TimedOut {
		t.Fatalf("sleep 应超时: %v %+v", res.IsError, out)
	}
	if out.DurationMs > 3000 {
		t.Fatalf("超时后还耗了 %dms", out.DurationMs)
	}
}

// TestMCPHTTPCLIApproval 客户端不声明 elicitation：批准落到
// approvals_dir，由 towstrap-server mcp approve 兜底。
func TestMCPHTTPCLIApproval(t *testing.T) {
	_, httpPort, users, _, approvalsDir, _ := startMCPHTTP(t)
	_, tok, _ := users.MCPAdd("laptop", []string{"bot"}, nil)
	cs, err := mcpHTTPConnect(t, httpPort, tok, nil) // 无 elicitation 能力
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	target := filepath.Join(t.TempDir(), "cli-approved")
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		res, _ := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "run_command",
			Arguments: map[string]any{"machine": "bot+default", "command": "touch " + target},
		})
		done <- res
	}()

	// 等批准文件出现，然后批准
	deadline := time.Now().Add(10 * time.Second)
	var id string
	for time.Now().Before(deadline) {
		list, _ := mcpsrv.Pending(approvalsDir)
		if len(list) > 0 {
			id = list[0].ID
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("批准文件没出现")
	}
	if _, err := mcpsrv.ApprovePending(approvalsDir, id, false); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res == nil || res.IsError {
		t.Fatalf("CLI 批准后命令应成功: %+v", res)
	}
	var out runResult
	decodeStructured(t, res, &out)
	if out.Approval != "approved" {
		t.Fatalf("结果不对: %+v", out)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("文件应已创建: %v", err)
	}
}

// TestMCPHTTPScope machines 不含 bot 的客户端：看不到也碰不了。
func TestMCPHTTPScope(t *testing.T) {
	_, httpPort, users, _, _, _ := startMCPHTTP(t)
	_, tok, _ := users.MCPAdd("narrow", []string{"other"}, nil)
	cs, err := mcpHTTPConnect(t, httpPort, tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res := callTool(t, cs, "list_machines", nil)
	var lo struct {
		Machines []struct{ Name string } `json:"machines"`
	}
	decodeStructured(t, res, &lo)
	if len(lo.Machines) != 0 {
		t.Fatalf("不该看到任何机器: %+v", lo)
	}
	res, _ = runHTTP(t, cs, "echo hi", nil)
	if !res.IsError {
		t.Fatal("没权限的机器不该能跑命令")
	}
}

func runHTTP(t *testing.T, cs *mcp.ClientSession, cmd string, extra map[string]any) (*mcp.CallToolResult, runResult) {
	t.Helper()
	args := map[string]any{"machine": "bot+default", "command": cmd}
	for k, v := range extra {
		args[k] = v
	}
	res := callTool(t, cs, "run_command", args)
	var out runResult
	if !res.IsError {
		decodeStructured(t, res, &out)
	}
	return res, out
}
