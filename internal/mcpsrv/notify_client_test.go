package mcpsrv

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// notifyClient 起一对真的 HTTP MCP 服务/客户端：客户端把收到的
// notifications/message（logging）和 notifications/progress 各丢进
// channel 供断言——这两条就是「待批提示能不能真的递到调用方」的通道。
func notifyClient(t *testing.T, s *Server) (*mcp.ClientSession, chan *mcp.LoggingMessageRequest, chan *mcp.ProgressNotificationClientRequest) {
	t.Helper()
	httpSrv := httptest.NewServer(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.MCP() }, nil))
	t.Cleanup(httpSrv.Close)

	logs := make(chan *mcp.LoggingMessageRequest, 8)
	prog := make(chan *mcp.ProgressNotificationClientRequest, 8)
	cl := mcp.NewClient(&mcp.Implementation{Name: "fake-client", Version: "0.0"},
		&mcp.ClientOptions{
			LoggingMessageHandler: func(_ context.Context, r *mcp.LoggingMessageRequest) {
				logs <- r
			},
			ProgressNotificationHandler: func(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
				prog <- r
			},
		})
	sess, err := cl.Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: httpSrv.URL},
		&mcp.ClientSessionOptions{ProtocolVersion: "2025-06-18"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess, logs, prog
}

// waitPendingFile 等 approvals 目录里冒出待批文件并返回其 id。
func waitPendingFile(t *testing.T, dir string, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if pend, _ := Pending(dir); len(pend) > 0 {
			return pend[0].ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s 内没出现待批文件", d)
	return ""
}

// callAskCommand 起一个会被批准的 run_command（ask_via=local + rm 命令必中
// ask 规则），返回结果的 channel——调用会阻塞在批准上。
func callAskCommand(sess *mcp.ClientSession, meta mcp.Meta) chan struct {
	r   *mcp.CallToolResult
	err error
} {
	done := make(chan struct {
		r   *mcp.CallToolResult
		err error
	}, 1)
	go func() {
		r, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "run_command",
			Arguments: map[string]any{"machine": "m", "command": "rm -rf /tmp/x"},
			Meta:      meta,
		})
		done <- struct {
			r   *mcp.CallToolResult
			err error
		}{r, err}
	}()
	return done
}

// TestPendingNoticeViaLogging：待批挂上时提示要经 notifications/message
// 递到调用方会话——SDK 里有级别门（客户端没发过 logging/setLevel 就静默
// 丢弃），这里先 setLevel 再断言收得到；批准后落定提示带同一个 ap- 编号。
func TestPendingNoticeViaLogging(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "local"
	s.cfg.ApprovalsDir = t.TempDir()
	s.cfg.Policy.AskTimeout = 5 * time.Second

	sess, logs, _ := notifyClient(t, s)
	if err := sess.SetLoggingLevel(context.Background(), &mcp.SetLoggingLevelParams{Level: "warning"}); err != nil {
		t.Fatal(err)
	}
	done := callAskCommand(sess, nil)

	// 第一条：待批提示——必须带 ap- 授权编号，审批人拿它去 mcp approve。
	var id string
	select {
	case ask := <-logs:
		msg := fmt.Sprint(ask.Params.Data)
		if !strings.Contains(msg, "ap-") {
			t.Fatalf("待批提示没带授权编号: %s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("5 秒内没收到待批的 logging 通知——setLevel 后这条通道不该丢")
	}
	id = waitPendingFile(t, s.cfg.ApprovalsDir, 3*time.Second)

	if _, err := ApprovePending(s.cfg.ApprovalsDir, id, false, false); err != nil {
		t.Fatal(err)
	}
	// 第二条：落定提示，指回同一个批准编号。
	select {
	case settled := <-logs:
		if m := fmt.Sprint(settled.Params.Data); !strings.Contains(m, id) {
			t.Fatalf("落定提示没带同一个批准编号 %s: %s", id, m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("批准后没收到落定通知")
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
}

// TestPendingNoticeViaProgress：请求 _meta 带 progressToken 时，挂起即刻
// 发 notifications/progress（这条没级别门——logging 没开也能到）；反过来
// 不发 setLevel 时 logging 通道确实是哑的、不带 token 时 progress 也确实是
// 哑的——顺带把「尽力投递」的边界钉死。
func TestPendingNoticeViaProgress(t *testing.T) {
	op := &countingRunner{}
	s := newTestServer(t, op, 4)
	s.cfg.Policy.AskVia = "local"
	s.cfg.ApprovalsDir = t.TempDir()
	s.cfg.Policy.AskTimeout = 5 * time.Second

	sess, logs, prog := notifyClient(t, s)

	// 第一次调用带 progressToken：progress 该到，logging（没 setLevel）不该到。
	done := callAskCommand(sess, mcp.Meta{"progressToken": "tok-7"})
	select {
	case p := <-prog:
		if m := p.Params.Message; !strings.Contains(m, "ap-") {
			t.Fatalf("progress 通知没带授权编号: %q", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("带 progressToken 的调用挂起时该收到 progress 通知")
	}
	id := waitPendingFile(t, s.cfg.ApprovalsDir, 3*time.Second)
	select {
	case l := <-logs:
		t.Fatalf("没发 setLevel 不该收到 logging 通知: %v", l.Params.Data)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := ApprovePending(s.cfg.ApprovalsDir, id, false, false); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.r == nil || r.r.IsError {
			t.Fatalf("批准后应执行成功: %+v %v", r.r, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("批准后调用没返回")
	}

	// 第二次不带 progressToken：progress 不该再到。
	done = callAskCommand(sess, nil)
	id = waitPendingFile(t, s.cfg.ApprovalsDir, 3*time.Second)
	select {
	case p := <-prog:
		t.Fatalf("不带 progressToken 不该收到 progress: %q", p.Params.Message)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := ApprovePending(s.cfg.ApprovalsDir, id, false, false); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.r == nil || r.r.IsError {
			t.Fatalf("批准后应执行成功: %+v %v", r.r, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("批准后调用没返回")
	}
	if op.count() != 2 {
		t.Fatalf("两次批准都该执行，实际跑了 %d 次", op.count())
	}
}
