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

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/allow"
	"github.com/towstrap/towstrap/internal/proto"
)

func (s *Server) startSSH() error {
	signer, err := loadOrCreateHostKey(s.cfg.HostKeyPath)
	if err != nil {
		return err
	}

	srv := &glssh.Server{
		Addr: s.cfg.SSHAddr,
		PasswordHandler: func(ctx glssh.Context, password string) bool {
			return s.sshAuthOK(s.canonicalLogin(ctx.User()), password, ctx.RemoteAddr())
		},
		PublicKeyHandler:           s.handlePublicKey,
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

// splitUser 把登录名拆成「账号」和「机器名」：alice+office →
// ("alice","office")；没带 + 就是整个账号（机器为空）。
func splitUser(u string) (account, machine string) {
	return accounts.SplitMachineID(u)
}

// canonicalLogin 把登录名规范成 账号+机器 的规范形式：
//   - alice/office 当 alice+office 用（/ 是输入别名，内部统一 +）；
//   - 没带分隔符又不是账号名时，当裸机器名在全部账号里找唯一同名的
//     （ssh local@host 等价于 ssh demo+local@host）；是账号名、或机器名
//     跨账号重名/不存在时原样返回，走后面的正常失败路径。
//
// 所有认证回调和会话入口先用它归一，下游（审计、from、Hub 查找）
// 见到的就都是规范格式。
func (s *Server) canonicalLogin(user string) string {
	user = accounts.NormalizeMachineID(user)
	account, machine := splitUser(user)
	if machine != "" {
		return user
	}
	if _, ok := s.cfg.Users.Get(account); ok {
		return user // 是账号名：保留「整账号登录」的原有语义
	}
	if m, ok := s.cfg.Users.MachineByName(account); ok {
		return m.ID()
	}
	return user
}

// sshAuthOK 是纯密码路径：全局白名单 → 限速器 → 账号密码 → 账号白名单。
// 绑了 TOTP 的账号在这里直接拒绝，而且**不碰限速器**：TOTP 账号的密码校验
// 和失败计数统一走 keyboard-interactive 通道。失败计数的清零只在整个登录
// 流程（含验证码）全部通过后做——如果密码一对就清零，攻击者拿泄露的密码
// 就能「每猜 4 次验证码重置一次」，把限速变成摆设。
//
// user 是完整登录名（可能带 +机器名）；认证和限速都按账号部分走，
// 审计记完整登录名。
func (s *Server) sshAuthOK(user, password string, remote net.Addr) bool {
	account, _ := splitUser(user)
	if acct, ok := s.cfg.Users.Get(account); ok && acct.TOTPEnabled {
		// TOTP 账号的账号密码只走 kbd-interactive；但 OAuth 换来的
		// 一次性凭据本身已是外部强认证，这里直接放行。
		if strings.HasPrefix(password, "tso-") {
			ok, viaGrant := s.verifyPassword(user, password, remote, "password")
			if ok && viaGrant {
				ip := hostOnly(remote.String())
				s.guard.pass(account, ip)
				s.audit.Log("AUTH-OK", "user", user, "ip", ip, "method", "password", "via", "oauth")
				return true
			}
		}
		// 不看密码也要烧一次 bcrypt：直接拒比密码错快得多，快慢一比就能
		// 筛出「存在且绑了 TOTP」的账号。
		s.cfg.Users.BurnPassword(password)
		return false
	}
	ok, viaGrant := s.verifyPassword(user, password, remote, "password")
	if !ok {
		return false
	}
	ip := hostOnly(remote.String())
	s.guard.pass(account, ip)
	if viaGrant {
		s.audit.Log("AUTH-OK", "user", user, "ip", ip, "method", "password", "via", "oauth")
	} else {
		s.audit.Log("AUTH-OK", "user", user, "ip", ip, "method", "password")
	}
	return true
}

// verifyPassword 校验密码并联动限速器：全局白名单 → 锁定检查 → OAuth 凭据
// （tso- 前缀的一次性密码）→ oauth_only 拦截 → 账号密码 → 账号状态 →
// 账号白名单。第二个返回值表示「这次是靠 OAuth 凭据过的」——调用方用它
// 跳过 TOTP（OAuth 授权本身就是强认证）。任何一步不过都计一次失败；这里
// **不**清零计数——清零只在整个登录流程（含 TOTP）全部通过后由调用方做。
func (s *Server) verifyPassword(user, password string, remote net.Addr, method string) (bool, bool) {
	account, machineName := splitUser(user)
	ip := hostOnly(remote.String())
	if !s.cfg.AllowIPs.AllowsAddr(remote) {
		return false, false
	}
	if !s.guard.allowed(account, ip) {
		s.audit.Log("AUTH-FAIL", "user", user, "ip", ip, "method", method, "reason", "locked")
		return false, false
	}
	// OAuth 凭据是按完整机器名发的；登录名没带 +机器名 且账号只有一台
	// 机器时按那台解析（和 handleSSH 的路由一致）。
	if strings.HasPrefix(password, "tso-") {
		if machineName == "" {
			if ms := s.cfg.Users.Machines(account); len(ms) == 1 {
				machineName = ms[0].Name
			}
		}
		if machineName != "" && s.cfg.Users.UseSSHGrant(account+"+"+machineName, password) {
			s.audit.Log("OAUTH-GRANT-USE", "user", user, "ip", ip, "method", method)
			return true, true
		}
	}
	if s.sshOAuthOnly(account, machineName) {
		s.guard.fail(account, ip)
		s.audit.Log("AUTH-FAIL", "user", user, "ip", ip, "method", method, "reason", "oauth-required")
		return false, false
	}
	pwOK := s.cfg.Users.Verify(account, password)
	acct, ok := s.cfg.Users.Get(account)
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
		s.guard.fail(account, ip)
		s.audit.Log("AUTH-FAIL", "user", user, "ip", ip, "method", method, "reason", reason)
		return false, false
	}
	return true, false
}

// sshOAuthOnly 判断这次登录名指向的目标是否被标「只收 OAuth 凭据」：
// 账号级标记罩住名下所有机器；机器级只管那一台。登录名没带 +机器名 时
// 按「账号唯一机器」解析；多台机器时裸账号反正过不了路由，这里不拦。
func (s *Server) sshOAuthOnly(account, machineName string) bool {
	if acct, ok := s.cfg.Users.Get(account); ok && acct.OAuthOnly {
		return true
	}
	if machineName == "" {
		ms := s.cfg.Users.Machines(account)
		if len(ms) != 1 {
			return false
		}
		machineName = ms[0].Name
	}
	m, ok := s.cfg.Users.GetMachine(account, machineName)
	return ok && m.OAuthOnly
}

// handleKbdInteractive 键盘交互登录：先问密码，账号绑了 TOTP 再问验证码。
// 验证码错误也计入限速器——6 位码空间小，不能留不限速的爆破面。
func (s *Server) handleKbdInteractive(ctx glssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
	user := s.canonicalLogin(ctx.User())
	account, _ := splitUser(user)
	remote := ctx.RemoteAddr()
	ip := hostOnly(remote.String())

	// 提示符用英文：SSH 软件的密码自动填靠匹配 /password/i 这类模式，
	// 中文提示符匹配不上自动填就失灵（Tabby/Termius 等同理）。
	answers, err := challenger("towstrap login", "", []string{"Password: "}, []bool{false})
	if err != nil || len(answers) == 0 {
		return false
	}
	ok, viaGrant := s.verifyPassword(user, answers[0], remote, "kbd-interactive")
	if !ok {
		return false
	}
	acct, exists := s.cfg.Users.Get(account)
	if !exists || !acct.TOTPEnabled || viaGrant {
		s.guard.pass(account, ip)
		if viaGrant {
			s.audit.Log("AUTH-OK", "user", user, "ip", ip, "method", "kbd-interactive", "via", "oauth")
		} else {
			s.audit.Log("AUTH-OK", "user", user, "ip", ip, "method", "kbd-interactive")
		}
		return true // 没绑 TOTP、或 OAuth 凭据本身已是强认证：密码对了就行
	}
	answers, err = challenger("towstrap login", "This account has TOTP enabled", []string{"TOTP code: "}, []bool{false})
	if err != nil || len(answers) == 0 {
		return false
	}
	if !s.cfg.Users.VerifyTOTP(account, strings.TrimSpace(answers[0])) {
		s.guard.fail(account, ip)
		s.audit.Log("AUTH-FAIL", "user", user, "ip", ip, "method", "kbd-interactive", "reason", "totp")
		return false
	}
	s.guard.pass(account, ip)
	s.audit.Log("AUTH-OK", "user", user, "ip", ip, "method", "kbd-interactive", "totp", "true")
	return true
}

// authMethodKey 是 gliderlabs Context 里记「这次登录用了哪种认证」的键：
// 公钥登录（给自动化用的）和密码类登录待遇不同——空闲重验只罩后者。
type authMethodKey struct{}

// handlePublicKey 公钥登录：全局白名单 → 账号白名单/停用 → 公钥匹配。
// 不进限速器（客户端会依次试好几把钥匙，计失败会误锁；钥匙也猜不出来），
// 也不写每次拒绝的审计（同样原因），只记成功。公钥登录不要求 TOTP——
// 它就是给自动化用的第二种凭据，和 OpenSSH 的默认行为一致。
func (s *Server) handlePublicKey(ctx glssh.Context, key glssh.PublicKey) bool {
	user := s.canonicalLogin(ctx.User())
	remote := ctx.RemoteAddr()
	if !s.cfg.AllowIPs.AllowsAddr(remote) {
		return false
	}
	if !s.sshPubKeyOK(user, key, remote) {
		return false
	}
	ctx.SetValue(authMethodKey{}, "publickey")
	s.audit.Log("AUTH-OK", "user", user, "ip", hostOnly(remote.String()),
		"method", "publickey", "fp", gossh.FingerprintSHA256(key))
	return true
}

// sshPubKeyOK 是 handlePublicKey 去掉 gliderlabs Context 的核心，方便单测：
// 账号存在未停用、这把钥匙登记过、账号自己的白名单放行。
func (s *Server) sshPubKeyOK(user string, key gossh.PublicKey, remote net.Addr) bool {
	account, machineName := splitUser(user)
	// oauth_only 的账号/机器不认公钥——只收 OAuth 换来的凭据。
	if s.sshOAuthOnly(account, machineName) {
		return false
	}
	if !s.cfg.Users.VerifySSHKey(account, key) {
		return false
	}
	acct, ok := s.cfg.Users.Get(account)
	if !ok {
		return false
	}
	list, err := allow.Parse(acct.AllowIPs)
	if err != nil || !list.AllowsAddr(remote) {
		return false
	}
	return true
}

// auditCmd 把会话命令压成审计字段：空命令记 "-"，超过 512 字节截断标记——
// 每条命令都要进审计，但一行不能无限长。
func auditCmd(cmd string) string {
	if cmd == "" {
		return "-"
	}
	if len(cmd) > 512 {
		return cmd[:512] + "…(truncated)"
	}
	return cmd
}

// agentCredentialValid 复核一个已连接 agent 的凭据：它接入时用的 token
// 现在仍然映射到这台机器（token 被 regen 换掉、机器被删、账号被删/停用
// 都会让这里为 false）。
func (s *Server) agentCredentialValid(name string, a *agentConn) bool {
	m, ok := s.cfg.Users.MachineByToken(a.getToken())
	return ok && m.ID() == name
}

// revokeStaleAgents 巡检一遍已连接的 agent，把凭据失效的当场断开。
func (s *Server) revokeStaleAgents() []string {
	revoked := s.Hub.PruneInvalid(func(name, token string) bool {
		m, ok := s.cfg.Users.MachineByToken(token)
		return ok && m.ID() == name
	})
	for _, id := range revoked {
		s.audit.Log("AGENT-REVOKE", "id", id)
	}
	return revoked
}

// handleSSH：SSH 登录名是「账号+机器名」（alice+office）；不带 + 时账号
// 恰有一台机器就落到它，多台机器报错并列出候选。之后落到 Hub 里对应
// 的 agent 上。支持两种用法：申请 PTY 的交互终端，和无 PTY 的命令执行
// （ssh host '命令'、ssh -T）——后者 stdout/stderr 分开、退出码原样带回。
func (s *Server) handleSSH(sess glssh.Session) {
	username := s.canonicalLogin(sess.User())
	from := username + "@" + hostOnly(sess.RemoteAddr().String())
	ptyReq, winCh, isPty := sess.Pty()
	cmd := sess.RawCommand()
	mode := "exec"
	if isPty {
		mode = "pty"
	}

	// 命令混在 WebSocket 消息里发给 agent，超长会把 agent 那条连接打断——
	// 服务器先挡住。
	if len(cmd) > proto.MaxCommandBytes {
		s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "cmd-too-long")
		_, _ = fmt.Fprintf(sess.Stderr(), "命令太长（上限 %d 字节）\n", proto.MaxCommandBytes)
		_ = sess.Exit(1)
		return
	}

	// @ 开头的命令是服务器自己的管理命令（@machine 等），不发给 agent；
	// 登录名带 +机器名 时忽略后缀，管的是账号下的机器。
	account, machineName := splitUser(username)
	if strings.HasPrefix(strings.TrimSpace(cmd), "@") {
		s.handleMgmt(sess, account, cmd)
		return
	}

	// 选机器：登录名带 +机器名 就指名；不带时按账号名下机器数决定。
	machineID := username
	if machineName == "" {
		machines := s.cfg.Users.Machines(account)
		switch len(machines) {
		case 0:
			s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "no-machine")
			_, _ = sess.Write([]byte("这个账号还没有机器，先在服务器上跑 towstrap-server machine add\n"))
			_ = sess.Exit(1)
			return
		case 1:
			machineID = machines[0].ID()
		default:
			s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "ambiguous")
			var b strings.Builder
			fmt.Fprintf(&b, "这个账号有多台机器，请用 账号+机器名（或 账号/机器名）登录：\n")
			for _, m := range machines {
				state := "离线"
				if s.Hub.Has(m.ID()) {
					state = "在线"
				}
				fmt.Fprintf(&b, "  %s（%s）\n", m.ID(), state)
			}
			_, _ = sess.Write([]byte(b.String()))
			_ = sess.Exit(1)
			return
		}
	} else {
		// 指名机器不存在时也先给个明白话，不用等 Hub.Agent 的通用错误。
		if _, ok := s.cfg.Users.GetMachine(account, machineName); !ok {
			s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "no-machine")
			_, _ = fmt.Fprintf(sess.Stderr(), "机器 %s 不存在（账号 %s 下的机器可以用 towstrap-server machine list %s 查看）\n", machineID, account, account)
			_ = sess.Exit(1)
			return
		}
	}

	agent, err := s.Hub.Agent(machineID)
	if err != nil {
		s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "offline")
		_, _ = sess.Write([]byte("这台机器没上线（agent 未连接）\n"))
		_ = sess.Exit(1)
		return
	}
	// 开会话前复核凭据：账号还在、没停用，且它接入时的 token 仍然有效。
	// 撤权（regen/remove/disable）对已经连上的 agent 立刻生效，而不是只挡新连接。
	if !s.agentCredentialValid(machineID, agent) {
		s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "credential")
		_, _ = sess.Write([]byte("这台机器的接入凭据已失效（token 已更换或机器/账号已删/停用），等它重连\n"))
		_ = sess.Exit(1)
		return
	}

	cols, rows := 80, 24
	if isPty {
		if ptyReq.Window.Width > 0 {
			cols = ptyReq.Window.Width
		}
		if ptyReq.Window.Height > 0 {
			rows = ptyReq.Window.Height
		}
	}

	// towstrap-mcp 开常驻 shell 前会发 env 标记 TOWSTRAP_MCP_SHELL=1：
	// agent 据此给 zsh 启动加 +o nomatch +o banghist（普通 SSH 会话
	// 不带这个标记，行为不变；标记只让 shell 更「字面量」，没有放权）。
	noExpand := false
	mcpCwd := ""
	for _, e := range sess.Environ() {
		if e == "TOWSTRAP_MCP_SHELL=1" {
			noExpand = true
		}
		if v, ok := strings.CutPrefix(e, "TOWSTRAP_MCP_CWD="); ok {
			mcpCwd = v
		}
	}

	sh, err := s.Hub.OpenShell(agent, OpenReq{Cols: cols, Rows: rows, Pty: isPty, Cmd: cmd, NoExpand: noExpand, Cwd: mcpCwd, From: from})
	if err != nil {
		s.audit.Log("SESSION-DENY", "user", username, "from", from, "reason", "open")
		_, _ = sess.Write([]byte(err.Error() + "\n"))
		_ = sess.Exit(1)
		return
	}
	s.audit.Log("SESSION-START", "user", username, "from", from, "id", sh.id, "mode", mode,
		"machine", machineID, "cmd", auditCmd(cmd))
	defer func() {
		s.audit.Log("SESSION-END", "user", username, "from", from, "id", sh.id, "code", fmt.Sprintf("%d", sh.exitCode()))
	}()

	// 交互终端登记进广播表：之后 MCP 有待批请求时往这里写提示行——
	// 人正登在服务器上时立刻看得见（exec 会话不登记，不污染脚本输出）。
	if isPty {
		s.registerSSH(sess, account)
		defer s.unregisterSSH(sess)
	}

	if isPty {
		go func() {
			for win := range winCh {
				s.Hub.Resize(agent, sh.id, win.Width, win.Height)
			}
		}()
	}

	in := io.Reader(sess)
	// 绑了 TOTP 的账号加空闲重验：挂机超过阈值后，下一次敲键先要一个新验证码
	// （挂着的输出不算使用；没绑 TOTP 的账号行为不变）。只罩交互 PTY +
	// 密码类登录——公钥是给自动化用的，exec 会话挂久了往 stdin 塞 TOTP
	// 提示会毁掉脚本。
	if s.cfg.IdleVerify > 0 && isPty && sess.Context().Value(authMethodKey{}) != "publickey" {
		if acct, ok := s.cfg.Users.Get(account); ok && acct.TOTPEnabled {
			in = newIdleGate(sess, s.cfg.IdleVerify, func() error {
				return s.reverifyTOTP(sess, account, s.cfg.IdleVerify)
			})
		}
	}
	s.Hub.pipe(agent, sh, in, sess, sess.Stderr(), isPty, sess.Context().Done())
	// agent 那边命令没起得来的原因（比如 shell 不存在）带给客户端
	if m := sh.errText(); m != "" {
		_, _ = fmt.Fprintln(sess.Stderr(), "agent: "+m)
	}
	_ = sess.Exit(sh.exitCode())
}

// registerSSH/unregisterSSH 维护活跃交互 SSH 会话表；broadcastSSH 把
// 「有 MCP 请求在等人批准」写进同账号的每个终端——人正登在服务器上时
// 立刻看得见，不用猜调用为什么挂着。按账号过滤：命令内容不跨账号泄；
// machine 解析不出账号（不该有）时发给所有会话兜底。
func (s *Server) registerSSH(sess glssh.Session, account string) {
	s.sshMu.Lock()
	defer s.sshMu.Unlock()
	if s.sshSess == nil {
		s.sshSess = map[glssh.Session]string{}
	}
	s.sshSess[sess] = account
}

func (s *Server) unregisterSSH(sess glssh.Session) {
	s.sshMu.Lock()
	defer s.sshMu.Unlock()
	delete(s.sshSess, sess)
}

func (s *Server) broadcastSSH(machine, text string) {
	account, _ := accounts.SplitMachineID(machine)
	line := fmt.Sprintf("\r\n\x1b[1;33m[towstrap] %s\x1b[0m\r\n", text)
	s.sshMu.Lock()
	defer s.sshMu.Unlock()
	for sess, acct := range s.sshSess {
		if account == "" || acct == account {
			_, _ = io.WriteString(sess, line)
		}
	}
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
	fmt.Fprintf(sess, "\r\n[towstrap] 空闲超过 %s，继续前请输入 TOTP 验证码（3 次机会，Ctrl-D 断开）\r\n", limit)
	for i := 0; i < 3; i++ {
		fmt.Fprint(sess, "验证码: ")
		line, err := readLine(sess)
		if err != nil {
			return err
		}
		if s.cfg.Users.VerifyTOTP(username, strings.TrimSpace(line)) {
			fmt.Fprint(sess, "\r\n[towstrap] 验证通过，继续。\r\n")
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
