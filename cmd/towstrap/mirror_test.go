package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/towstrap/towstrap/internal/client"
)

// relayHarness 一头是 relayMirror（客户端），一头是测试扮演的 agent。
type relayHarness struct {
	agentDec *json.Decoder
	agentEnc *json.Encoder
	agent    net.Conn
	keys     *io.PipeWriter
	out      *bytes.Buffer
	outMu    *sync.Mutex
	alt      *client.AltScreen
	done     chan relayResult
}

type relayResult struct {
	code int
	end  relayEnd
	err  error
}

type lockedBuf struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (l lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func startRelay(t *testing.T) *relayHarness {
	t.Helper()
	cli, agent := net.Pipe()
	t.Cleanup(func() { _ = cli.Close(); _ = agent.Close() })
	kr, kw := io.Pipe()
	h := &relayHarness{agentDec: json.NewDecoder(agent), agentEnc: json.NewEncoder(agent), agent: agent,
		keys: kw, out: &bytes.Buffer{}, outMu: &sync.Mutex{}, alt: &client.AltScreen{}, done: make(chan relayResult, 1)}
	enc := json.NewEncoder(cli)
	var mu sync.Mutex
	send := func(m mirrorMsg) error { mu.Lock(); defer mu.Unlock(); return enc.Encode(m) }
	go func() {
		code, end, err := relayMirror(json.NewDecoder(cli), send, kr, lockedBuf{h.outMu, h.out}, h.alt)
		h.done <- relayResult{code, end, err}
	}()
	return h
}

func (h *relayHarness) wait(t *testing.T) relayResult {
	t.Helper()
	select {
	case r := <-h.done:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("relayMirror 没结束")
	}
	return relayResult{}
}

// 按 Ctrl-\ 脱离：同一批里它前面的按键照样送出，结束方式是「脱离」
// （以前 agent 一断连就被当成「镜像已退出 exit=0」）。
func TestRelayDetach(t *testing.T) {
	h := startRelay(t)
	go func() { _, _ = h.keys.Write([]byte("ab\x1cZZ")) }()
	var got []mirrorMsg
	for len(got) < 2 {
		var m mirrorMsg
		if err := h.agentDec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		got = append(got, m)
	}
	d, _ := base64.StdEncoding.DecodeString(got[0].D)
	if string(d) != "ab" {
		t.Fatalf("Ctrl-\\ 之前的按键应送出 \"ab\"，实际 %q", d)
	}
	if got[1].Op != "detach" {
		t.Fatalf("第二条应是 detach，实际 %+v", got[1])
	}
	_ = h.agent.Close() // agent 收到 detach 后断连
	if r := h.wait(t); r.end != relayDetached {
		t.Fatalf("应判为脱离，实际 %+v", r)
	}
}

// 收到退出码：程序结束；期间的输出写到终端，并跟踪到备用屏幕状态。
func TestRelayExit(t *testing.T) {
	h := startRelay(t)
	_ = h.agentEnc.Encode(mirrorMsg{D: base64.StdEncoding.EncodeToString([]byte("\x1b[?1049hhello"))})
	code := 7
	_ = h.agentEnc.Encode(mirrorMsg{Code: &code})
	r := h.wait(t)
	if r.end != relayExited || r.code != 7 {
		t.Fatalf("应是退出码 7，实际 %+v", r)
	}
	h.outMu.Lock()
	out := h.out.String()
	h.outMu.Unlock()
	if out != "\x1b[?1049hhello" {
		t.Fatalf("输出不对: %q", out)
	}
	if !h.alt.On() {
		t.Fatal("应跟踪到程序进了备用屏幕")
	}
}

// agent 那边断开（没按脱离也没退出码）：是「连接断开」，不能说成程序退出。
func TestRelayLost(t *testing.T) {
	h := startRelay(t)
	_ = h.agent.Close()
	if r := h.wait(t); r.end != relayLost || r.err == nil {
		t.Fatalf("应判为连接断开，实际 %+v", r)
	}
}

// 行首 ~. 脱离（ssh 同款逃逸）：Ctrl-\ 的字节在 Windows 上可能被终端或
// ConPTY 吃掉送不到，~. 是纯可打印字符谁也拦不住。~ 和 . 都不进镜像。
func TestRelayDetachTildeDot(t *testing.T) {
	h := startRelay(t)
	go func() { _, _ = h.keys.Write([]byte("echo ok\r~.")) }()
	var got []mirrorMsg
	for len(got) < 2 {
		var m mirrorMsg
		if err := h.agentDec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		got = append(got, m)
	}
	d, _ := base64.StdEncoding.DecodeString(got[0].D)
	if string(d) != "echo ok\r" {
		t.Fatalf("~. 之前的按键应原样送出，实际 %q", d)
	}
	if got[1].Op != "detach" {
		t.Fatalf("第二条应是 detach，实际 %+v", got[1])
	}
	_ = h.agent.Close()
	if r := h.wait(t); r.end != relayDetached {
		t.Fatalf("应判为脱离，实际 %+v", r)
	}
}

// 不在行首的 ~. 不是逃逸，原样进镜像；行首 ~~ 发一个字面 ~。
func TestRelayTildeEscapes(t *testing.T) {
	h := startRelay(t)
	go func() {
		_, _ = h.keys.Write([]byte("a~."))     // 非行首：原样
		_, _ = h.keys.Write([]byte("\r~~.\r")) // ~~ → 字面 ~，后面的 . 普通
	}()
	want := "a~.\r~.\r"
	var got string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(got) < len(want) {
		var m mirrorMsg
		if err := h.agentDec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		if m.D != "" {
			d, _ := base64.StdEncoding.DecodeString(m.D)
			got += string(d)
		}
	}
	if got != want {
		t.Fatalf("转义不对：got %q want %q", got, want)
	}
}

// 行首 ~ 后接的不是 . 也不是 ~：~ 落回，俩都进镜像（~x 这类输入不能丢）。
func TestRelayTildeFallback(t *testing.T) {
	h := startRelay(t)
	go func() { _, _ = h.keys.Write([]byte("~\r~x")) }() // 行首~后接 \r，又行首~后接 x
	want := "~\r~x"
	var got string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(got) < len(want) {
		var m mirrorMsg
		if err := h.agentDec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		if m.D != "" {
			d, _ := base64.StdEncoding.DecodeString(m.D)
			got += string(d)
		}
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
