package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	glssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// envServer 起一台最小 gliderlabs server：密码恒真、session 通道走
// boundedSessionHandler——和 startSSH 里同一套挂接。
func envServer(t *testing.T) string {
	t.Helper()
	srv := &glssh.Server{
		PasswordHandler: func(glssh.Context, string) bool { return true },
		Handler:         func(glssh.Session) {},
		ChannelHandlers: map[string]glssh.ChannelHandler{
			"session": boundedSessionHandler,
		},
	}
	srv.AddHostKey(testSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func envClient(t *testing.T, addr string) *gossh.Client {
	t.Helper()
	cli, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{gossh.Password("pw")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

// 只发 env、不发会话请求的通道：env 攒到上限后通道必须被关掉，
// 不能继续无上限吃内存。
func TestEnvOnlyChannelCapped(t *testing.T) {
	cli := envClient(t, envServer(t))
	ch, reqs, err := cli.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go gossh.DiscardRequests(reqs)

	marshalEnv := func(i int) []byte {
		kv := struct{ Key, Value string }{
			Key:   fmt.Sprintf("K%d", i),
			Value: string(make([]byte, 4096)),
		}
		return gossh.Marshal(&kv)
	}
	rejected := false
	// maxEnvBytes=64KB，每条约 4KB+：17 条就该撞线。多打几条留余量。
	for i := 0; i < maxEnvCount+40; i++ {
		ok, err := ch.SendRequest("env", true, marshalEnv(i))
		if err != nil || !ok {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Fatal("env 超限的通道应被拒/被关，全程放行意味着内存无上限")
	}
}

// 正常量的 env + shell 请求不受闸口影响。
func TestEnvBelowCapStillWorks(t *testing.T) {
	cli := envClient(t, envServer(t))
	sess, err := cli.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	for i := 0; i < 4; i++ {
		if err := sess.Setenv(fmt.Sprintf("K%d", i), "v"); err != nil {
			t.Fatalf("正常 env 请求被拒: %v", err)
		}
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("正常量 env 后 shell 应照常开: %v", err)
	}
}
