package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	glssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"ws2ssh/internal/allow"
)

func (s *Server) startSSH() error {
	signer, err := loadOrCreateHostKey(s.cfg.HostKeyPath)
	if err != nil {
		return err
	}

	srv := &glssh.Server{
		Addr: s.cfg.SSHAddr,
		PasswordHandler: func(ctx glssh.Context, password string) bool {
			return s.sshAuthOK(ctx.User(), password, ctx.RemoteAddr())
		},
		KeyboardInteractiveHandler: s.handleKbdInteractive,
		Handler:                    s.handleSSH,
		// IdleTimeout 随读写活动刷新，能治未认证连接挂死（Slowloris），
		// 但也会杀掉长时间空闲的交互会话——默认关，需要的自己开。
		IdleTimeout: s.cfg.SSHIdleTimeout,
		MaxTimeout:  s.cfg.SSHMaxTimeout,
	}
	srv.AddHostKey(signer)

	ln, err := net.Listen("tcp", s.cfg.SSHAddr)
	if err != nil {
		return err
	}
	// 连接上限：全局 + 每来源 IP（SSH 面向人的登录，每 IP 限制是有效的，
	// 这里不会被 NAT 的机群误伤）。
	ln = newConnCap(ln, s.cfg.MaxConns, s.cfg.MaxConnsPerIP)
	slog.Info("ssh listen", "addr", s.cfg.SSHAddr)
	return srv.Serve(ln)
}

// sshAuthOK 是纯密码路径：全局白名单 → 限速器 → 账号密码 → 账号白名单。
// 绑了 TOTP 的账号在这里直接拒绝，而且**不碰限速器**：TOTP 账号的密码校验
// 和失败计数统一走 keyboard-interactive 通道。失败计数的清零只在整个登录
// 流程（含验证码）全部通过后做——如果密码一对就清零，攻击者拿泄露的密码
// 就能「每猜 4 次验证码重置一次」，把限速变成摆设。
func (s *Server) sshAuthOK(user, password string, remote net.Addr) bool {
	if acct, ok := s.cfg.Users.Get(user); ok && acct.TOTPEnabled {
		// 不看密码也要烧一次 bcrypt：直接拒比密码错快得多，快慢一比就能
		// 筛出「存在且绑了 TOTP」的账号。
		s.cfg.Users.BurnPassword(password)
		return false
	}
	if !s.verifyPassword(user, password, remote, "password") {
		return false
	}
	s.guard.pass(user, hostOnly(remote.String()))
	s.audit.Log("AUTH-OK", "user", user, "ip", hostOnly(remote.String()), "method", "password")
	return true
}

// verifyPassword 校验密码并联动限速器：全局白名单 → 锁定检查 → 密码 →
// 账号状态 → 账号自己的白名单。任何一步不过都计一次失败；这里**不**清零
// 计数——清零只在整个登录流程（含 TOTP）全部通过后由调用方做，否则
// 「密码对 + 验证码错」每轮都会把计数归零，限速形同虚设。结果写审计日志。
func (s *Server) verifyPassword(user, password string, remote net.Addr, method string) bool {
	ip := hostOnly(remote.String())
	if !s.cfg.AllowIPs.AllowsAddr(remote) {
		return false
	}
	if !s.guard.allowed(user, ip) {
		s.audit.Log("AUTH-FAIL", "user", user, "ip", ip, "method", method, "reason", "locked")
		return false
	}
	pwOK := s.cfg.Users.Verify(user, password)
	acct, ok := s.cfg.Users.Get(user)
	reason := ""
	switch {
	case !pwOK:
		reason = "password"
	case !ok || acct.Disabled:
		reason = "disabled"
	default:
		list, err := allow.Parse(acct.AllowIPs)
		if err != nil || !list.AllowsAddr(remote) {
			reason = "allow-ip"
		}
	}
	if reason != "" {
		s.guard.fail(user, ip)
		s.audit.Log("AUTH-FAIL", "user", user, "ip", ip, "method", method, "reason", reason)
		return false
	}
	return true
}

// handleKbdInteractive 键盘交互登录：先问密码，账号绑了 TOTP 再问验证码。
// 验证码错误也计入限速器——6 位码空间小，不能留不限速的爆破面。
func (s *Server) handleKbdInteractive(ctx glssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
	user := ctx.User()
	remote := ctx.RemoteAddr()
	ip := hostOnly(remote.String())

	answers, err := challenger("ws2ssh 登录", "", []string{"密码: "}, []bool{false})
	if err != nil || len(answers) == 0 {
		return false
	}
	if !s.verifyPassword(user, answers[0], remote, "kbd-interactive") {
		return false
	}
	acct, ok := s.cfg.Users.Get(user)
	if !ok || !acct.TOTPEnabled {
		s.guard.pass(user, ip)
		s.audit.Log("AUTH-OK", "user", user, "ip", ip, "method", "kbd-interactive")
		return true // 没绑 TOTP：密码对了就行
	}
	answers, err = challenger("ws2ssh 登录", "该账号绑定了 TOTP 验证器", []string{"TOTP 验证码: "}, []bool{false})
	if err != nil || len(answers) == 0 {
		return false
	}
	if !s.cfg.Users.VerifyTOTP(user, strings.TrimSpace(answers[0])) {
		s.guard.fail(user, ip)
		s.audit.Log("AUTH-FAIL", "user", user, "ip", ip, "method", "kbd-interactive", "reason", "totp")
		return false
	}
	s.guard.pass(user, ip)
	s.audit.Log("AUTH-OK", "user", user, "ip", ip, "method", "kbd-interactive", "totp", "true")
	return true
}

// agentCredentialValid 复核一个已连接 agent 的凭据：账号还在、没停用，
// 且它接入时用的 token 现在仍然映射到这个用户名（token 被 regen 换掉、
// 账号被删/停用都会让这里为 false）。
func (s *Server) agentCredentialValid(name string, a *agentConn) bool {
	u, ok := s.cfg.Users.UsernameByToken(a.token)
	return ok && u == name
}

// revokeStaleAgents 巡检一遍已连接的 agent，把凭据失效的当场断开。
func (s *Server) revokeStaleAgents() []string {
	revoked := s.Hub.PruneInvalid(func(name, token string) bool {
		u, ok := s.cfg.Users.UsernameByToken(token)
		return ok && u == name
	})
	for _, id := range revoked {
		s.audit.Log("AGENT-REVOKE", "id", id)
	}
	return revoked
}

// handleSSH：SSH 用户名就是账号用户名，落到那台账号 token 关联的机器上。
func (s *Server) handleSSH(sess glssh.Session) {
	username := sess.User()
	from := username + "@" + hostOnly(sess.RemoteAddr().String())

	agent, err := s.Hub.Agent(username)
	if err != nil {
		s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "offline")
		_, _ = sess.Write([]byte("这台机器没上线（agent 未连接）\n"))
		_ = sess.Exit(1)
		return
	}
	// 开会话前复核凭据：账号还在、没停用，且它接入时的 token 仍然有效。
	// 撤权（regen/remove/disable）对已经连上的 agent 立刻生效，而不是只挡新连接。
	if !s.agentCredentialValid(username, agent) {
		s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "credential")
		_, _ = sess.Write([]byte("这台机器的接入凭据已失效（token 已更换或账号已删/停用），等它重连\n"))
		_ = sess.Exit(1)
		return
	}

	cols, rows := 80, 24
	ptyReq, winCh, isPty := sess.Pty()
	if isPty {
		if ptyReq.Window.Width > 0 {
			cols = ptyReq.Window.Width
		}
		if ptyReq.Window.Height > 0 {
			rows = ptyReq.Window.Height
		}
	}

	sh, err := s.Hub.OpenShell(agent, cols, rows, from)
	if err != nil {
		s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "open")
		_, _ = sess.Write([]byte(err.Error() + "\n"))
		_ = sess.Exit(1)
		return
	}
	s.audit.Log("SESSION-START", "user", username, "from", from, "id", sh.id)
	defer s.audit.Log("SESSION-END", "user", username, "from", from, "id", sh.id)

	if isPty {
		go func() {
			for win := range winCh {
				s.Hub.Resize(agent, sh.id, win.Width, win.Height)
			}
		}()
	}

	in := io.Reader(sess)
	// 绑了 TOTP 的账号加空闲重验：挂机超过阈值后，下一次敲键先要一个新验证码
	// （挂着的输出不算使用；没绑 TOTP 的账号行为不变）。
	if s.cfg.IdleVerify > 0 {
		if acct, ok := s.cfg.Users.Get(username); ok && acct.TOTPEnabled {
			in = newIdleGate(sess, s.cfg.IdleVerify, func() error {
				return s.reverifyTOTP(sess, username, s.cfg.IdleVerify)
			})
		}
	}
	s.Hub.pipe(agent, sh, in, sess, sess.Context().Done())
	_ = sess.Exit(0)
}

// idleGate 包住 SSH 会话的输入流：距上次敲键超过 limit 后，新到的第一笔输入
// 先触发 challenge（弹 TOTP 重验），通过才放行；challenge 报错则终止会话。
type idleGate struct {
	r         io.Reader
	limit     time.Duration
	last      time.Time
	challenge func() error
}

func newIdleGate(r io.Reader, limit time.Duration, challenge func() error) *idleGate {
	return &idleGate{r: r, limit: limit, last: time.Now(), challenge: challenge}
}

func (g *idleGate) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	if n > 0 {
		if g.challenge != nil && time.Since(g.last) > g.limit {
			if cerr := g.challenge(); cerr != nil {
				return 0, cerr
			}
		}
		g.last = time.Now()
	}
	return n, err
}

// reverifyTOTP 在既有会话里要一个新的 6 位码：提示走 SSH 通道（shell 看不到），
// 用户的输入被这里直接消费。连错三次断开会话。
func (s *Server) reverifyTOTP(sess glssh.Session, username string, limit time.Duration) error {
	fmt.Fprintf(sess, "\r\n[ws2ssh] 空闲超过 %s，继续前请输入 TOTP 验证码（3 次机会，Ctrl-D 断开）\r\n", limit)
	for i := 0; i < 3; i++ {
		fmt.Fprint(sess, "验证码: ")
		line, err := readLine(sess)
		if err != nil {
			return err
		}
		if s.cfg.Users.VerifyTOTP(username, strings.TrimSpace(line)) {
			fmt.Fprint(sess, "\r\n[ws2ssh] 验证通过，继续。\r\n")
			return nil
		}
		fmt.Fprint(sess, "\r\n验证码不对。")
	}
	return errors.New("TOTP 重验失败，断开会话")
}

// readLine 从会话逐字节读一行（密码/验证码不要 bufio 缓冲，避免吞掉后续输入）。
func readLine(r io.Reader) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return string(b), nil
			}
			if one[0] != '\r' {
				b = append(b, one[0])
			}
		}
		if err != nil {
			return string(b), err
		}
	}
}

// hostOnly 去掉地址里的端口；去掉失败就原样返回。
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// loadOrCreateHostKey 读 SSH 主机密钥，只有文件不存在才生成新的；读不了
// 或解析不了就报错退出——静默换主机密钥等于让用户习惯性接受 host key
// 变更警告。
func loadOrCreateHostKey(path string) (gossh.Signer, error) {
	if path == "" {
		path = "ssh_host_key"
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		signer, perr := gossh.ParsePrivateKey(raw)
		if perr != nil {
			return nil, fmt.Errorf("SSH 主机密钥 %s 解析失败（不会自动覆盖，请检查或删掉它再启动）: %w", path, perr)
		}
		return signer, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("读 SSH 主机密钥 %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(block)
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return gossh.ParsePrivateKey(pemBytes)
}
