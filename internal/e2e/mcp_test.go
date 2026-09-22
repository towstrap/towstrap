package e2e

// towstrap-mcp 的端到端测试：真服务器 + 真 agent + 真 SSH（公钥登录），
// MCP 这层用 in-memory transport 连一个可编程 elicitation handler 的客户端。

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/towstrap/towstrap/internal/mcpsrv"
	"github.com/towstrap/towstrap/internal/server"
)

// mcpEnv 是一套跑起来的 towstrap + MCP server。
type mcpEnv struct {
	client       *mcp.ClientSession
	approvalsDir string
	rootsDir     string
	elicitCalls  *atomic.Int32
}

// startMCP 起服务器、agent、MCP server，返回连好的测试客户端。
// handler 为 nil 时客户端不声明 elicitation 能力（走本地批准回退）。
func startMCP(t *testing.T, handler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcpEnv {
	return startMCPProto(t, handler, "")
}

// startMCPProto 同上，protoVersion 非空时让客户端按旧版 MCP 协议握手
// （验证 elicitation 的兼容路径：服务器中间件把 InputRequests 转成传统
// elicitation/create 请求）。
func startMCPProto(t *testing.T, handler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error), protoVersion string) *mcpEnv {
	return startMCPProtoShell(t, handler, protoVersion, "/bin/bash")
}

// startMCPProtoShell 同上，可指定 agent 的 shell（zsh 的 NoExpand 测试用）。
func startMCPProtoShell(t *testing.T, handler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error), protoVersion, shell string) *mcpEnv {
	t.Helper()
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "host_key")
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{HostKeyPath: hostKeyPath})

	// 给测试账号登记一把生成的 ed25519 公钥。
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := users.Add("bot", "unused-pw-12345", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.AddSSHKey("bot", strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))); err != nil {
		t.Fatal(err)
	}
	startAgentOpt(t, httpPort, acct.Machines[0].Token, "mcp-test-host", nil, shell)
	waitAgent(t, srv.Hub, "bot+default")

	// 私钥落盘；服务器主机密钥指纹从生成的 host key 文件算，写进 host_key 钉死。
	keyPath := filepath.Join(dir, "id_ed25519")
	pemBlk, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlk), 0600); err != nil {
		t.Fatal(err)
	}
	hkBytes, err := os.ReadFile(hostKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	hkSigner, err := gossh.ParsePrivateKey(hkBytes)
	if err != nil {
		t.Fatal(err)
	}
	fp := gossh.FingerprintSHA256(hkSigner.PublicKey())

	rootsDir := t.TempDir()
	approvalsDir := filepath.Join(dir, "approvals")
	yaml := fmt.Sprintf(`server: 127.0.0.1:%d
key: %s
host_key: %s
machines:
  bot:
    description: 测试机
    roots: [%s]
policy:
  default: ask
  ask_timeout: 5s
approvals_dir: %s
`, sshPort, keyPath, fp, rootsDir, approvalsDir)
	cfgPath := filepath.Join(dir, "mcp.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := mcpsrv.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := mcpsrv.NewPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mcpSrv, err := mcpsrv.New(cfg, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mcpSrv.Close)

	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	if _, err := mcpSrv.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	calls := &atomic.Int32{}
	opts := &mcp.ClientOptions{}
	if handler != nil {
		opts.ElicitationHandler = func(ctx context.Context, r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			calls.Add(1)
			return handler(ctx, r)
		}
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "mcp-test", Version: "v0"}, opts)
	cs, err := c.Connect(ctx, ct, &mcp.ClientSessionOptions{ProtocolVersion: protoVersion})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return &mcpEnv{client: cs, approvalsDir: approvalsDir, rootsDir: rootsDir, elicitCalls: calls}
}

// runResult 是 run_command 结构化输出的测试侧镜像。
type runResult struct {
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	TimedOut        bool   `json:"timed_out"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	DurationMs      int64  `json:"duration_ms"`
	Approval        string `json:"approval"`
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

func decodeStructured(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("解码 structuredContent: %v", err)
	}
}

func resultText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func runCmd(t *testing.T, env *mcpEnv, cmd string, extra map[string]any) (*mcp.CallToolResult, runResult) {
	t.Helper()
	args := map[string]any{"machine": "bot", "command": cmd}
	for k, v := range extra {
		args[k] = v
	}
	res := callTool(t, env.client, "run_command", args)
	var out runResult
	if !res.IsError {
		decodeStructured(t, res, &out)
	}
	return res, out
}

// acceptAll 是「总是允许」的 elicitation handler。
func acceptAll(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
}

func TestMCPTools(t *testing.T) {
	env := startMCP(t, acceptAll)

	// allow 名单内的命令直接跑，不触发批准。
	res, out := runCmd(t, env, "echo hi", nil)
	if res.IsError || out.ExitCode != 0 || out.Stdout != "hi\n" {
		t.Fatalf("echo hi: IsError=%v out=%+v", res.IsError, out)
	}
	if n := env.elicitCalls.Load(); n != 0 {
		t.Fatalf("echo hi 不该触发批准，弹了 %d 次", n)
	}
	if out.Approval != "allowed" {
		t.Errorf("approval = %q, want allowed", out.Approval)
	}

	// 不在名单内的命令触发 elicitation；accept 后执行成功。
	target := filepath.Join(t.TempDir(), "x")
	res, _ = runCmd(t, env, "touch "+target, nil)
	if res.IsError {
		t.Fatalf("批准后 touch 应成功: %s", resultText(res))
	}
	if n := env.elicitCalls.Load(); n != 1 {
		t.Fatalf("touch 应弹 1 次批准，弹了 %d 次", n)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("文件应已创建: %v", err)
	}
}

// TestMCPElicitLegacyProtocol 旧协议（2025-11-25，还没有 MRTR）客户端：
// handler 返回的 InputRequests 由服务器侧中间件转成传统 elicitation/create
// 请求，客户端 ElicitationHandler 照样收到，答复经二次调用回到 handler。
func TestMCPElicitLegacyProtocol(t *testing.T) {
	env := startMCPProto(t, acceptAll, "2025-11-25")
	res, out := runCmd(t, env, "echo hi", nil)
	if res.IsError || out.Stdout != "hi\n" {
		t.Fatalf("echo hi: %v %+v", res.IsError, out)
	}
	target := filepath.Join(t.TempDir(), "x")
	res, _ = runCmd(t, env, "touch "+target, nil)
	if res.IsError {
		t.Fatalf("旧协议下批准后 touch 应成功: %s", resultText(res))
	}
	if n := env.elicitCalls.Load(); n != 1 {
		t.Fatalf("旧协议下 handler 应被调 1 次，调了 %d 次", n)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("文件应已创建: %v", err)
	}
}

func TestMCPDenyNoElicit(t *testing.T) {
	env := startMCP(t, acceptAll)
	res, _ := runCmd(t, env, "sudo ls", nil)
	if !res.IsError {
		t.Fatal("sudo ls 应被策略拒绝")
	}
	if !strings.Contains(resultText(res), "拒绝") {
		t.Errorf("错误文本应含「拒绝」: %s", resultText(res))
	}
	if n := env.elicitCalls.Load(); n != 0 {
		t.Fatalf("deny 不该触发批准，弹了 %d 次", n)
	}
}

func TestMCPDeclineAndRemember(t *testing.T) {
	// 第一次拒绝、第二次 accept+remember、第三次不弹窗。
	var mode atomic.Int32 // 0=decline 1=accept+remember
	env := startMCP(t, func(_ context.Context, r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		if !strings.Contains(r.Params.Message, "touch") {
			t.Errorf("弹窗消息应含命令: %q", r.Params.Message)
		}
		if mode.Load() == 0 {
			return &mcp.ElicitResult{Action: "decline"}, nil
		}
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true, "remember": true}}, nil
	})

	res, _ := runCmd(t, env, "touch /tmp/mcp-dec-a", nil)
	if !res.IsError || !strings.Contains(resultText(res), "拒绝") {
		t.Fatalf("decline 应返回含「拒绝」的错误: %v %s", res.IsError, resultText(res))
	}

	mode.Store(1)
	res, _ = runCmd(t, env, "touch /tmp/mcp-dec-b", nil)
	if res.IsError {
		t.Fatalf("accept 后应执行: %s", resultText(res))
	}
	res, out := runCmd(t, env, "touch /tmp/mcp-dec-b", nil)
	if res.IsError {
		t.Fatalf("记住批准后重跑应成功: %s", resultText(res))
	}
	if out.Approval != "remembered" {
		t.Errorf("approval = %q, want remembered", out.Approval)
	}
	if n := env.elicitCalls.Load(); n != 2 {
		t.Fatalf("记住批准后同命令不应再弹窗，共弹了 %d 次", n)
	}
}

func TestMCPReadWriteFile(t *testing.T) {
	env := startMCP(t, acceptAll)
	inRoots := filepath.Join(env.rootsDir, "hello.txt")

	res := callTool(t, env.client, "write_file", map[string]any{
		"machine": "bot", "path": inRoots, "content": "你好 towstrap\n"})
	if res.IsError {
		t.Fatalf("roots 内 write_file 应直接放行: %s", resultText(res))
	}
	if n := env.elicitCalls.Load(); n != 0 {
		t.Fatalf("roots 内写入不该弹窗，弹了 %d 次", n)
	}

	res = callTool(t, env.client, "read_file", map[string]any{"machine": "bot", "path": inRoots})
	if res.IsError {
		t.Fatalf("read_file: %s", resultText(res))
	}
	var ro struct {
		Content string `json:"content"`
	}
	decodeStructured(t, res, &ro)
	if ro.Content != "你好 towstrap\n" {
		t.Fatalf("回读不一致: %q", ro.Content)
	}

	// roots 外写入要批准；批准了就真写。
	outside := filepath.Join(t.TempDir(), "outside.txt")
	res = callTool(t, env.client, "write_file", map[string]any{
		"machine": "bot", "path": outside, "content": "x"})
	if res.IsError {
		t.Fatalf("批准后 roots 外写入应成功: %s", resultText(res))
	}
	if n := env.elicitCalls.Load(); n != 1 {
		t.Fatalf("roots 外写入应弹 1 次，弹了 %d 次", n)
	}
	if b, _ := os.ReadFile(outside); string(b) != "x" {
		t.Fatalf("写入内容不对: %q", b)
	}

	// deny_paths 命中的直接拒。
	res = callTool(t, env.client, "read_file", map[string]any{"machine": "bot", "path": "~/.ssh/config"})
	if !res.IsError || !strings.Contains(resultText(res), "拒绝") {
		t.Fatalf("读 ~/.ssh/config 应被拒: %v %s", res.IsError, resultText(res))
	}
}

func TestMCPTimeout(t *testing.T) {
	env := startMCP(t, acceptAll)
	res, out := runCmd(t, env, "sleep 5", map[string]any{"timeout_seconds": 1})
	if res.IsError {
		t.Fatalf("超时应返回结果而不是错误: %s", resultText(res))
	}
	if !out.TimedOut {
		t.Fatalf("sleep 5 + 1s 超时应 timed_out: %+v", out)
	}
}

// ---- 客户端不支持 elicitation：走 approvals_dir 的本地批准回退 ----

// waitPending 等 approvals_dir 里出现一个待批 .json，返回 id。
func waitPending(t *testing.T, dir string) string {
	t.Helper()
	for i := 0; i < 60; i++ {
		list, err := mcpsrv.Pending(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) > 0 {
			return list[0].ID
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("没出现待批文件")
	return ""
}

func TestMCPApproveViaCLI(t *testing.T) {
	env := startMCP(t, nil) // 无 handler：客户端不支持弹窗
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		done <- callTool(t, env.client, "run_command",
			map[string]any{"machine": "bot", "command": "touch /tmp/mcp-cli-ok"})
	}()
	id := waitPending(t, env.approvalsDir)
	if _, err := mcpsrv.ApprovePending(env.approvalsDir, id, false); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.IsError {
		t.Fatalf("命令行批准后应执行成功: %s", resultText(res))
	}
	if _, err := os.Stat("/tmp/mcp-cli-ok"); err != nil {
		t.Fatalf("文件应已创建: %v", err)
	}
}

func TestMCPDenyViaCLI(t *testing.T) {
	env := startMCP(t, nil)
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		done <- callTool(t, env.client, "run_command",
			map[string]any{"machine": "bot", "command": "touch /tmp/mcp-cli-no"})
	}()
	id := waitPending(t, env.approvalsDir)
	if _, err := mcpsrv.DenyPending(env.approvalsDir, id, false); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if !res.IsError || !strings.Contains(resultText(res), "拒绝") {
		t.Fatalf("deny 应返回含「拒绝」的错误: %v %s", res.IsError, resultText(res))
	}
	if _, err := os.Stat("/tmp/mcp-cli-no"); err == nil {
		t.Fatal("被拒的命令不该执行")
	}
}

func TestMCPApprovalTimeout(t *testing.T) {
	env := startMCP(t, nil)
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		done <- callTool(t, env.client, "run_command",
			map[string]any{"machine": "bot", "command": "touch /tmp/mcp-cli-timeout"})
	}()
	_ = waitPending(t, env.approvalsDir) // 文件出现了但没人批
	res := <-done                        // 等过 ask_timeout（5s）
	if !res.IsError || !strings.Contains(resultText(res), "超时") {
		t.Fatalf("超时后应返回含「超时」的错误: %v %s", res.IsError, resultText(res))
	}
	if _, err := os.Stat("/tmp/mcp-cli-timeout"); err == nil {
		t.Fatal("超时的命令不该执行")
	}
}

// TestMCPSessionStdio stdio 路径（Pool.OpenShell 走 SSH shell 通道）的
// 常驻会话：同名 session 共享远端 shell，exit 后自动重开。
func TestMCPSessionStdio(t *testing.T) {
	env := startMCP(t, acceptAll)

	res, out := runCmd(t, env, "export SESS_V=keep42 && cd /", map[string]any{"session": "s"})
	if res.IsError || out.ExitCode != 0 {
		t.Fatalf("建会话失败: %s", resultText(res))
	}
	res, out = runCmd(t, env, "pwd; echo V=$SESS_V", map[string]any{"session": "s"})
	if res.IsError || !strings.Contains(out.Stdout, "V=keep42") {
		t.Fatalf("stdio 会话状态没保留: %s %+v", resultText(res), out)
	}
	var raw map[string]any
	decodeStructured(t, res, &raw)
	if raw["session"] != "s" {
		t.Fatalf("输出应带 session 名: %v", raw)
	}
	// stdin 在 session 模式被拒
	res = callTool(t, env.client, "run_command", map[string]any{
		"machine": "bot", "command": "cat", "session": "s", "stdin": "x",
	})
	if !res.IsError || !strings.Contains(resultText(res), "stdin") {
		t.Fatalf("session+stdin 应报错: %v %s", res.IsError, resultText(res))
	}
	// exit 终结 → 同名命令自动新开会话
	res, _ = runCmd(t, env, "exit", map[string]any{"session": "s"})
	if !res.IsError {
		t.Fatal("exit 应报会话中断")
	}
	res = callTool(t, env.client, "run_command", map[string]any{
		"machine": "bot", "command": "echo V=[$SESS_V]", "session": "s",
	})
	var out2 struct {
		Stdout    string `json:"stdout"`
		Restarted bool   `json:"session_restarted"`
	}
	decodeStructured(t, res, &out2)
	if res.IsError || !out2.Restarted || !strings.Contains(out2.Stdout, "V=[]") {
		t.Fatalf("应重启且状态丢失: %s %+v", resultText(res), out2)
	}
}

// TestMCPSessionZshStdio stdio 路径 + agent 用 zsh：env 标记经 SSH 透传
// NoExpand，zsh 起成 +o nomatch +o banghist——items[0] 这种写法不杀会话、
// ! 不做历史展开，都按字面量输出。
func TestMCPSessionZshStdio(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("机器上没有 zsh")
	}
	env := startMCPProtoShell(t, acceptAll, "", zsh)

	res, out := runCmd(t, env, "export Z=1; echo items[0] bang:!", map[string]any{"session": "z"})
	if res.IsError || out.ExitCode != 0 || !strings.Contains(out.Stdout, "items[0] bang:!") {
		t.Fatalf("zsh 会话应把 glob/! 按字面量输出: %s %+v", resultText(res), out)
	}
	res, out = runCmd(t, env, "echo alive-$Z", map[string]any{"session": "z"})
	if res.IsError || !strings.Contains(out.Stdout, "alive-1") {
		t.Fatalf("zsh 会话应活着且状态保留: %s %+v", resultText(res), out)
	}
}
