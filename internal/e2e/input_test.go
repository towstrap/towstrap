package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestStdinOverloadExec(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	_, sess1 := execDial(t, sshPort, gossh.Password("alicepw123"))
	in1, err := sess1.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var se1 bytes.Buffer
	sess1.Stderr = &se1
	if err := sess1.Start("sleep 60"); err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := bytes.Repeat([]byte("x"), 64*1024)
		for i := 0; i < 256; i++ {
			if _, err := in1.Write(buf); err != nil {
				return
			}
		}
	}()

	_, sess2 := execDial(t, sshPort, gossh.Password("alicepw123"))
	done := make(chan error, 1)
	go func() {
		out, err := sess2.Output("echo hello-unblocked")
		if err == nil && !strings.Contains(string(out), "hello-unblocked") {
			err = fmt.Errorf("输出不对: %q", out)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("第二个会话应正常完成: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("不读 stdin 的会话把整个 agent 拖死了")
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- sess1.Wait() }()
	select {
	case err := <-waitErr:
		if err == nil {
			t.Fatal("超载会话应被终止而不是正常退出")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("超载会话没被终止")
	}
}

func TestStdinOverloadPty(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	cfg := &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{gossh.Password("alicepw123")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	c, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess1, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess1.Close()
	if err := sess1.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	in1, err := sess1.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess1.Start("sleep 60"); err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := bytes.Repeat([]byte("y"), 64*1024)
		for i := 0; i < 256; i++ {
			if _, err := in1.Write(buf); err != nil {
				return
			}
		}
	}()

	_, sess2 := execDial(t, sshPort, gossh.Password("alicepw123"))
	done := make(chan error, 1)
	go func() {
		out, err := sess2.Output("echo hello-pty-unblocked")
		if err == nil && !strings.Contains(string(out), "hello-pty-unblocked") {
			err = fmt.Errorf("输出不对: %q", out)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("PTY 会话堵塞时第二个会话应正常完成: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("PTY 会话堵塞把整个 agent 拖死了")
	}
}

func TestExecStdinOrderAndEOF(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	_, sess := execDial(t, sshPort, gossh.Password("alicepw123"))
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sess.Stdout = &out
	if err := sess.Start("cat"); err != nil {
		t.Fatal(err)
	}
	parts := []string{"part1-", "part2-", "part3"}
	for _, p := range parts {
		if _, err := stdin.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- sess.Wait() }()
	select {
	case err := <-waitErr:
		if err != nil {
			t.Fatalf("cat 应正常退出: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cat 没在 stdin EOF 后退出")
	}
	if out.String() != "part1-part2-part3" {
		t.Fatalf("数据应按序原样到达: %q", out.String())
	}
}

func TestExecLargeStdin(t *testing.T) {
	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	big := bytes.Repeat([]byte("abcdefgh"), 64*1024)
	_, sess := execDial(t, sshPort, gossh.Password("alicepw123"))
	sess.Stdin = bytes.NewReader(big)
	out, err := sess.Output("cat")
	if err != nil {
		t.Fatalf("cat 大输入失败: %v", err)
	}
	if !bytes.Equal(out, big) {
		t.Fatalf("大输入应完整传递: got %d bytes, want %d", len(out), len(big))
	}
}

func TestMCPCwdViaSSHEnv(t *testing.T) {
	home := t.TempDir()
	sub := filepath.Join(home, "mcwsub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	srv, httpPort, sshPort, users := startServer(t)
	acct, err := users.Add("alice", "alicepw123", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	startAgent(t, httpPort, acct.Machines[0].Token, "h1")
	waitAgent(t, srv.Hub, "alice+default")

	dir := t.TempDir()
	_, sess := execDial(t, sshPort, gossh.Password("alicepw123"))
	if err := sess.Setenv("TOWSTRAP_MCP_CWD", dir); err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("pwd")
	if err != nil {
		t.Fatal(err)
	}
	got, err := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("cwd 应传到 agent cmd.Dir: got %q want %q", got, want)
	}

	_, sess2 := execDial(t, sshPort, gossh.Password("alicepw123"))
	if err := sess2.Setenv("TOWSTRAP_MCP_CWD", "~/mcwsub"); err != nil {
		t.Fatal(err)
	}
	out, err = sess2.Output("pwd")
	if err != nil {
		t.Fatal(err)
	}
	got, err = filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	want, err = filepath.EvalSymlinks(sub)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("~/ cwd 应在 agent 端展开: got %q want %q", got, want)
	}
}
