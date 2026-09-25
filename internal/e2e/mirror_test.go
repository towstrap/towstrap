//go:build !windows

package e2e

//镜像终端（接力终端）的端到端测试：真实 agent 进程 + 本机 mirror.sock。
// 覆盖：接入或新建、两个接入方互通（扇出）、脱离后进程继续跑、重放补画面、
// kill 终结、退出码传播。
// MCP 侧不提供镜像终端——多端接力是给人用的，远端走 SSH 上机器再跑
// towstrap mirror <名字>，最终也是落到这个 socket。

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/towstrap/towstrap/internal/server"
)

// mirrorSockClient 是测试里用的本机 socket 客户端（towstrap mirror 的镜像）。
type mirrorSockClient struct {
	c   net.Conn
	dec *json.Decoder
	enc *json.Encoder
}

type mirrorSockMsg struct {
	Op      string `json:"op,omitempty"`
	Name    string `json:"name,omitempty"`
	Cmd     string `json:"cmd,omitempty"`
	Cols    int    `json:"cols,omitempty"`
	Rows    int    `json:"rows,omitempty"`
	D       string `json:"d,omitempty"`
	Code    *int   `json:"code,omitempty"`
	OK      bool   `json:"ok,omitempty"`
	Created bool   `json:"created,omitempty"`
	Err     string `json:"err,omitempty"`
	Mirrors []struct {
		Name     string `json:"name"`
		Attached int    `json:"attached"`
	} `json:"mirrors,omitempty"`
}

// startMirrorEnv 起服务器 + agent；socket 路径由 startAgentOpt 写进
// TOWSTRAP_MIRROR_SOCK 环境变量。
func startMirrorEnv(t *testing.T) {
	t.Helper()
	srv, httpPort, _, users := startServerOpt(t, server.Config{})
	acct, err := users.Add("bot", "unused-pw-12345", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgentOpt(t, httpPort, acct.Machines[0].Token, "mirror-host", nil, "/bin/bash")
	waitAgent(t, srv.Hub, "bot+default")
}

func dialMirrorSock(t *testing.T) *mirrorSockClient {
	t.Helper()
	path := os.Getenv("TOWSTRAP_MIRROR_SOCK")
	if path == "" {
		t.Fatal("TOWSTRAP_MIRROR_SOCK 没设——startAgentOpt 应已配置")
	}
	var c net.Conn
	var err error
	for i := 0; i < 50; i++ {
		c, err = net.DialTimeout("unix", path, 300*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("连 mirror socket %s: %v", path, err)
	}
	return &mirrorSockClient{c: c, dec: json.NewDecoder(c), enc: json.NewEncoder(c)}
}

func (s *mirrorSockClient) send(m mirrorSockMsg) {
	if err := s.enc.Encode(m); err != nil {
		panic(err)
	}
}

func (s *mirrorSockClient) recv() mirrorSockMsg {
	var m mirrorSockMsg
	_ = s.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := s.dec.Decode(&m); err != nil {
		panic(err)
	}
	return m
}

// attach 发 attach 请求并收下 ok 应答，返回是否新建。
func (s *mirrorSockClient) attach(t *testing.T, name, cmd string) bool {
	t.Helper()
	s.send(mirrorSockMsg{Op: "attach", Name: name, Cmd: cmd, Cols: 80, Rows: 24})
	ack := s.recv()
	if !ack.OK {
		t.Fatalf("attach %q 失败: %s", name, ack.Err)
	}
	return ack.Created
}

// writeInput 发一行输入。
func (s *mirrorSockClient) writeInput(line string) {
	s.send(mirrorSockMsg{D: base64.StdEncoding.EncodeToString([]byte(line))})
}

// readUntil 累积输出直到出现 want；code 非 nil 时收到退出码也算命中。
func (s *mirrorSockClient) readUntil(t *testing.T, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var got strings.Builder
	for time.Now().Before(deadline) {
		var m mirrorSockMsg
		_ = s.c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := s.dec.Decode(&m); err != nil {
			t.Fatalf("读输出失败: %v（已收到 %q）", err, got.String())
		}
		if m.D != "" {
			b, _ := base64.StdEncoding.DecodeString(m.D)
			got.Write(b)
		}
		if strings.Contains(got.String(), want) {
			return got.String()
		}
	}
	t.Fatalf("没等到 %q；已收到 %q", want, got.String())
	return ""
}

// waitExit 等到 {"code":N} 返回退出码。
func (s *mirrorSockClient) waitExit(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var m mirrorSockMsg
		_ = s.c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := s.dec.Decode(&m); err != nil {
			t.Fatalf("等退出码时连接断了: %v", err)
		}
		if m.Code != nil {
			return *m.Code
		}
	}
	t.Fatal("没等到退出码")
	return -1
}

// mirrorList 发 ls 拿清单。
func mirrorList(t *testing.T) []string {
	t.Helper()
	c := dialMirrorSock(t)
	defer c.c.Close()
	c.send(mirrorSockMsg{Op: "ls"})
	m := c.recv()
	if !m.OK {
		t.Fatalf("ls 失败: %s", m.Err)
	}
	var names []string
	for _, x := range m.Mirrors {
		names = append(names, x.Name)
	}
	return names
}

// TestMirrorSockRelay 接力主链路：接入或新建 → 第二个接入方靠重放补画面 →
// 双向输入互通 → 脱离后进程照跑 → 再接回 → kill 终结 → 列表清空。
func TestMirrorSockRelay(t *testing.T) {
	startMirrorEnv(t)

	c1 := dialMirrorSock(t)
	defer c1.c.Close()
	if !c1.attach(t, "work", "cat") {
		t.Fatal("首次接入应是新建")
	}
	c1.writeInput("relay-one\n")
	c1.readUntil(t, "relay-one")

	// 第二个接入方（模拟另一台设备 SSH 上来跑 mirror work）：重放补画面
	c2 := dialMirrorSock(t)
	defer c2.c.Close()
	if c2.attach(t, "work", "") {
		t.Fatal("同名接入不应是新建")
	}
	c2.readUntil(t, "relay-one")

	// 扇出：c1 写的 c2 也收得到；反向也通（同一个 PTY，cat 回显）
	c1.writeInput("from-c1\n")
	c2.readUntil(t, "from-c1")
	c2.writeInput("from-c2\n")
	c1.readUntil(t, "from-c2")

	// c1 脱离：连接断开，镜像继续跑
	c1.send(mirrorSockMsg{Op: "detach"})
	c1.c.Close()
	c2.writeInput("still-alive\n")
	c2.readUntil(t, "still-alive")

	// 再接回：重放里有脱离期间的输出
	c3 := dialMirrorSock(t)
	defer c3.c.Close()
	c3.attach(t, "work", "")
	got := c3.readUntil(t, "still-alive")
	if !strings.Contains(got, "relay-one") {
		t.Fatalf("重放应含更早的输出，实际 %q", got)
	}

	// kill 终结：c3 收到退出码，列表清空
	k := dialMirrorSock(t)
	defer k.c.Close()
	k.send(mirrorSockMsg{Op: "kill", Name: "work"})
	if m := k.recv(); !m.OK {
		t.Fatalf("kill 失败: %s", m.Err)
	}
	c3.waitExit(t)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if names := mirrorList(t); len(names) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("kill 后列表应为空，实际 %v", mirrorList(t))
}

// TestMirrorSockExitPropagates 镜像里的进程退出时，接入方拿到真实退出码，
// 登记处把它摘掉；之后同名接入是全新创建。
func TestMirrorSockExitPropagates(t *testing.T) {
	startMirrorEnv(t)

	c := dialMirrorSock(t)
	defer c.c.Close()
	c.attach(t, "bye", "sleep 0.2; exit 9")
	if code := c.waitExit(t); code != 9 {
		t.Fatalf("退出码应为 9，实际 %d", code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if names := mirrorList(t); len(names) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("退出后列表应为空，实际 %v", mirrorList(t))
}
