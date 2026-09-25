package mcpsrv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Result 是一条命令在被控机上的执行结果。
type Result struct {
	Stdout          string
	Stderr          string
	ExitCode        int
	TimedOut        bool
	StdoutTruncated bool
	StderrTruncated bool
	Duration        time.Duration
}

// Pool 按机器懒建立并复用 SSH 连接（机器名 = towstrap 账号名 = SSH 用户名）。
type Pool struct {
	cfg       *Config
	signer    gossh.Signer
	hostKeyCb gossh.HostKeyCallback

	mu    sync.Mutex
	conns map[string]*gossh.Client
}

// NewPool 解析私钥、准备主机密钥校验。只做准备，不拨号——连接在第一次
// 用到某台机器时才建。
func NewPool(cfg *Config) (*Pool, error) {
	keyBytes, err := os.ReadFile(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("读私钥 %s: %w", cfg.Key, err)
	}
	signer, err := gossh.ParsePrivateKey(keyBytes)
	if err != nil {
		var passErr *gossh.PassphraseMissingError
		if errors.As(err, &passErr) {
			return nil, fmt.Errorf("私钥 %s 带口令，MCP 不支持，请用无口令的专用密钥（ssh-keygen 时不设口令，或 ssh-keygen -p 去掉）", cfg.Key)
		}
		return nil, fmt.Errorf("解析私钥 %s: %w", cfg.Key, err)
	}

	var cb gossh.HostKeyCallback
	if cfg.HostKey != "" {
		want := strings.TrimSpace(cfg.HostKey)
		cb = func(host string, _ net.Addr, key gossh.PublicKey) error {
			got := gossh.FingerprintSHA256(key)
			if got != want {
				return fmt.Errorf("服务器 %s 的主机密钥指纹是 %s，和 mcp.yaml 里钉死的 %s 不一致——可能被顶替，已拒绝连接", host, got, want)
			}
			return nil
		}
	} else {
		if cfg.KnownHosts == "" {
			return nil, fmt.Errorf("known_hosts 和 host_key 至少要配一个")
		}
		kh, err := knownhosts.New(cfg.KnownHosts)
		if err != nil {
			return nil, fmt.Errorf("读 known_hosts %s: %w", cfg.KnownHosts, err)
		}
		cb = func(host string, addr net.Addr, key gossh.PublicKey) error {
			err := kh(host, addr, key)
			if err == nil {
				return nil
			}
			var keyErr *knownhosts.KeyError
			if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
				h, port, _ := net.SplitHostPort(cfg.Server)
				fp := gossh.FingerprintSHA256(key)
				return fmt.Errorf("known_hosts 里没有 %s 的记录（服务器指纹 %s）。两种修法：ssh-keyscan -p %s %s >> %s，或在 mcp.yaml 里写 host_key: %s",
					host, fp, port, h, cfg.KnownHosts, fp)
			}
			return err
		}
	}
	return &Pool{cfg: cfg, signer: signer, hostKeyCb: cb, conns: make(map[string]*gossh.Client)}, nil
}

// conn 取某台机器的可用连接，没有就拨一条。
func (p *Pool) conn(machine string) (*gossh.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.conns[machine]; c != nil {
		return c, nil
	}
	return p.dialLocked(machine)
}

func (p *Pool) dialLocked(machine string) (*gossh.Client, error) {
	cc := &gossh.ClientConfig{
		User:            machine,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(p.signer)},
		HostKeyCallback: p.hostKeyCb,
		Timeout:         10 * time.Second,
	}
	c, err := gossh.Dial("tcp", p.cfg.Server, cc)
	if err != nil {
		return nil, fmt.Errorf("连 %s（账号 %s）: %w", p.cfg.Server, machine, err)
	}
	p.conns[machine] = c
	return c, nil
}

// drop 关掉并忘掉一条连接（下次用时重拨）。
func (p *Pool) drop(machine string, c *gossh.Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns[machine] == c {
		delete(p.conns, machine)
	}
	_ = c.Close()
}

// Connected 报告这台机器当前有没有已建立的连接（不会为它去拨号）。
func (p *Pool) Connected(machine string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns[machine] != nil
}

// isConnError 判断是不是连接层的错（值得重拨重试），区别于命令本身的错。
func isConnError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var exitErr *gossh.ExitError
	return !errors.As(err, &exitErr)
}

// Run 在 machine 上执行 cmd（经被控机的 shell -c），stdin 原样喂给进程。
// 超时先发 SIGKILL 再关会话。连接层的错误自动重拨重试一次。
func (p *Pool) Run(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int) (Result, error) {
	return p.RunAt(ctx, machine, cmd, stdin, timeout, maxOut, "")
}

func (p *Pool) RunAt(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int, cwd string) (Result, error) {
	res, err := p.runOnce(ctx, machine, cmd, stdin, timeout, maxOut, cwd)
	if err == nil || !isConnError(err) {
		return res, err
	}
	// 可能是旧连接断了：换掉重拨一次再试。
	if c := func() *gossh.Client {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.conns[machine]
	}(); c != nil {
		p.drop(machine, c)
	}
	return p.runOnce(ctx, machine, cmd, stdin, timeout, maxOut, cwd)
}

func (p *Pool) runOnce(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int, cwd string) (Result, error) {
	c, err := p.conn(machine)
	if err != nil {
		return Result{}, err
	}
	sess, err := c.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("开 SSH 会话: %w", err)
	}
	defer sess.Close()
	outW, errW := NewCapWriter(maxOut), NewCapWriter(maxOut)
	sess.Stdout = outW
	sess.Stderr = errW
	if len(stdin) > 0 {
		sess.Stdin = bytes.NewReader(stdin)
	}
	if cwd != "" {
		if err := sess.Setenv("TOWSTRAP_MCP_CWD", cwd); err != nil {
			return Result{}, fmt.Errorf("传工作目录: %w", err)
		}
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	res := Result{Duration: 0}
	timedOut := false
	t := time.NewTimer(timeout)
	defer t.Stop()
	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		_ = sess.Signal(gossh.SIGKILL)
		_ = sess.Close()
		<-done
		return Result{}, ctx.Err()
	case <-t.C:
		timedOut = true
		_ = sess.Signal(gossh.SIGKILL)
		_ = sess.Close()
		runErr = <-done // 会话已关，Run 马上回来
	}

	res.Duration = time.Since(start)
	res.Stdout = outW.String()
	res.Stderr = errW.String()
	res.StdoutTruncated = outW.Truncated()
	res.StderrTruncated = errW.Truncated()
	if timedOut {
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	}
	if runErr == nil {
		res.ExitCode = 0
		return res, nil
	}
	var exitErr *gossh.ExitError
	if errors.As(runErr, &exitErr) {
		res.ExitCode = exitErr.ExitStatus()
		return res, nil
	}
	var missErr *gossh.ExitMissingError
	if errors.As(runErr, &missErr) {
		res.ExitCode = -1
		return res, nil
	}
	return res, fmt.Errorf("执行出错: %w", runErr)
}

// OpenShell 在这台机器上开一个常驻 shell（SSH "shell" 通道，无 PTY）：
// 服务器侧落到 agent 的裸 shell exec 会话，stdin 由通道持续喂。供
// run_command 的 session 参数用。
func (p *Pool) OpenShell(ctx context.Context, machine string) (Shell, error) {
	c, err := p.conn(machine)
	if err != nil {
		return nil, err
	}
	sess, err := c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("开 SSH 会话: %w", err)
	}
	in, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	outR, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	errR, err := sess.StderrPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	// 先打个 env 标记让服务器认出这是 MCP 常驻 shell——agent 据此给
	// zsh 关掉 nomatch/banghist（普通 SSH 登录不受影响）。env 请求
	// 必须发在 Shell() 之前。
	if err := sess.Setenv("TOWSTRAP_MCP_SHELL", "1"); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("标记常驻 shell: %w", err)
	}
	// Shell() 发的是不带命令的 shell 请求：服务器落到 agent 的
	// 裸 shell exec 会话（Cmd 空 + Pty false）。
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("起常驻 shell: %w", err)
	}
	return &sshShell{sess: sess, in: in, out: outR, errR: errR}, nil
}

// sshShell 把一条 SSH shell 通道包成 Shell 接口。
type sshShell struct {
	sess *gossh.Session
	in   io.Writer
	out  io.Reader
	errR io.Reader
}

func (s *sshShell) Write(b []byte) (int, error) { return s.in.Write(b) }
func (s *sshShell) Stdout() io.Reader           { return s.out }
func (s *sshShell) Stderr() io.Reader           { return s.errR }
func (s *sshShell) Close() error                { return s.sess.Close() }

// OpenTerminal 在这台机器上开一条 PTY 会话：先 pty-req，再按 Command
// 起 shell 命令或交互 shell。输出是 PTY 的一条合并流，不能拆 stderr。
func (p *Pool) OpenTerminal(ctx context.Context, machine string, opts TerminalOptions) (Terminal, error) {
	t, err := p.openTerminalOnce(machine, opts)
	if err == nil || !isConnError(err) {
		return t, err
	}
	if c := func() *gossh.Client {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.conns[machine]
	}(); c != nil {
		p.drop(machine, c)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return p.openTerminalOnce(machine, opts)
}

func (p *Pool) openTerminalOnce(machine string, opts TerminalOptions) (Terminal, error) {
	c, err := p.conn(machine)
	if err != nil {
		return nil, err
	}
	sess, err := c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("开 SSH 会话: %w", err)
	}
	in, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	if opts.Cwd != "" {
		if err := sess.Setenv("TOWSTRAP_MCP_CWD", opts.Cwd); err != nil {
			_ = sess.Close()
			return nil, fmt.Errorf("传工作目录: %w", err)
		}
	}
	if err := sess.RequestPty("xterm-256color", opts.Rows, opts.Cols, gossh.TerminalModes{}); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("申请 PTY: %w", err)
	}
	if opts.Command != "" {
		err = sess.Start(opts.Command)
	} else {
		err = sess.Shell()
	}
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("起 PTY 命令: %w", err)
	}
	return newSSHTerminal(sess, in, out), nil
}

type sshTerminal struct {
	sess *gossh.Session
	in   io.Writer
	out  io.Reader
	done chan int
}

func newSSHTerminal(sess *gossh.Session, in io.Writer, out io.Reader) *sshTerminal {
	t := &sshTerminal{sess: sess, in: in, out: out, done: make(chan int, 1)}
	go func() {
		code := 0
		err := sess.Wait()
		var exitErr *gossh.ExitError
		switch {
		case err == nil:
		case errors.As(err, &exitErr):
			code = exitErr.ExitStatus()
		default:
			code = -1
		}
		t.done <- code
	}()
	return t
}

func (t *sshTerminal) Read(b []byte) (int, error)  { return t.out.Read(b) }
func (t *sshTerminal) Write(b []byte) (int, error) { return t.in.Write(b) }
func (t *sshTerminal) Resize(cols, rows int) error {
	return t.sess.WindowChange(rows, cols)
}
func (t *sshTerminal) Close() error { return t.sess.Close() }
func (t *sshTerminal) Wait() int    { return <-t.done }

// Close 关掉池里所有连接。
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for m, c := range p.conns {
		_ = c.Close()
		delete(p.conns, m)
	}
}
