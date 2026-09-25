package mcpsrv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// elicitClient 起一对真的 HTTP MCP 服务/客户端，客户端声明 elicitation
// 能力（老协议版本），收到 elicitation/create 就往 elicitGot 丢一条。
func elicitClient(t *testing.T, s *Server) (sess *mcp.ClientSession, elicitGot chan *mcp.ElicitRequest) {
	t.Helper()
	httpSrv := httptest.NewServer(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.MCP() }, nil))
	t.Cleanup(httpSrv.Close)

	elicitGot = make(chan *mcp.ElicitRequest, 1)
	cl := mcp.NewClient(&mcp.Implementation{Name: "fake-client", Version: "0.0"},
		&mcp.ClientOptions{
			ElicitationHandler: func(ctx context.Context, r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				elicitGot <- r
				return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
			},
		})
	sess, err := cl.Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: httpSrv.URL},
		&mcp.ClientSessionOptions{ProtocolVersion: "2025-06-18"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess, elicitGot
}

// TestElicitRoundTrip：auto 模式下客户端声明了 elicitation，批准请求必须
// 真的变成客户端收到的 elicitation/create，且应答回到服务端后命令执行——
// 弹窗通道整个往返不能退化。
// 注意：一定要等到 CallTool 返回再结束测试——收到 elicit 事件就返回的话，
// 清理里的 sess.Close 会和客户端回写应答抢跑（connClosing 先置位会丢应答）。
func TestElicitRoundTrip(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	sess, elicitGot := elicitClient(t, s)

	type res struct {
		r   *mcp.CallToolResult
		err error
	}
	done := make(chan res, 1)
	go func() {
		r, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "run_command",
			Arguments: map[string]any{"machine": "m", "command": "rm -rf /tmp/x"},
		})
		done <- res{r, err}
	}()

	select {
	case er := <-elicitGot:
		t.Logf("客户端收到 elicitation/create: %v", er.Params.Message)
	case r := <-done:
		t.Fatalf("工具调用直接返回了（没等批准）: %+v err=%v", r.r, r.err)
	case <-time.After(10 * time.Second):
		t.Fatal("10 秒内客户端没收到 elicitation/create——批准弹窗请求被吞了")
	}
	select {
	case r := <-done:
		if r.err != nil || r.r == nil || r.r.IsError {
			t.Fatalf("批准后应执行成功: %+v %v", r.r, r.err)
		}
		if op.count() != 1 {
			t.Fatal("命令没真的执行")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("应答回去后调用没完成——弹窗往返断了")
	}
}

// TestAskViaLocalOverridesElicitation：ask_via=local 必须压过客户端的弹窗
// 能力——有的客户端声明了 elicitation 却渲染不出弹窗，操作员要能绕开。
func TestAskViaLocalOverridesElicitation(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "local"
	s.cfg.ApprovalsDir = t.TempDir()
	s.cfg.Policy.AskTimeout = 5 * time.Second
	sess, elicitGot := elicitClient(t, s)

	type res struct {
		r   *mcp.CallToolResult
		err error
	}
	done := make(chan res, 1)
	go func() {
		r, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "run_command",
			Arguments: map[string]any{"machine": "m", "command": "rm -rf /tmp/x"},
		})
		done <- res{r, err}
	}()

	// 等本地待批文件出现；期间出现弹窗请求就是没绕开
	var id string
	deadline := time.Now().Add(3 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		select {
		case er := <-elicitGot:
			t.Fatalf("ask_via=local 不该走弹窗: %v", er.Params.Message)
		default:
		}
		if pend, _ := Pending(s.cfg.ApprovalsDir); len(pend) > 0 {
			id = pend[0].ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("3 秒内没出现本地待批文件")
	}

	// 终端命令批准后，命令真的执行、调用正常返回
	if _, err := ApprovePending(s.cfg.ApprovalsDir, id, false, false); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.r == nil || r.r.IsError {
			t.Fatalf("批准后应执行成功: %+v %v", r.r, r.err)
		}
		if op.count() != 1 {
			t.Fatal("命令没真的执行")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("批准后调用没返回")
	}
	select {
	case er := <-elicitGot:
		t.Fatalf("全程不该出现弹窗请求: %v", er.Params.Message)
	default:
	}
}

// TestAskViaLLMOverridesElicitation：ask_via=llm 同样压过弹窗能力——
// 第一轮就回「需要用户确认」的指引，不发 elicitation/create。
func TestAskViaLLMOverridesElicitation(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "llm"
	sess, elicitGot := elicitClient(t, s)

	r, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "run_command",
		Arguments: map[string]any{"machine": "m", "command": "rm -rf /tmp/x"},
	})
	if err != nil || r == nil || !r.IsError {
		t.Fatalf("ask 命令应返回需确认的提示: %+v %v", r, err)
	}
	select {
	case er := <-elicitGot:
		t.Fatalf("ask_via=llm 不该走弹窗: %v", er.Params.Message)
	default:
	}
	if op.count() != 0 {
		t.Fatal("没确认不该执行")
	}
}
