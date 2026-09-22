package server

// @ 开头的命令是服务器自己的管理命令，不转发给 agent：账号本人用密码
// 登录（公钥不行）后，可以自助管理自己账号下的机器。目前只有 @machine。

import (
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	glssh "github.com/gliderlabs/ssh"

	"towstrap/internal/config"
)

const mgmtUsage = `服务器管理命令（@ 开头的命令只由服务器执行，不发给 agent）：
  @machine list                                     列出账号下的机器（不含 token）
  @machine add <名字> [--agent-allow-ip 地址]...    加一台机器并打印 agent token
  @machine remove <名字>                            删一台机器，在线 agent 立刻断开
  @machine token <名字>                             看这台机器的 token
                                                    （换 token 在 agent 机器上跑 towstrap-agent token refresh）
  @machine help                                     本说明
`

// stringFlags 是可重复的字符串旗标（--agent-allow-ip 可以写多次）。
type stringFlags []string

func (f *stringFlags) String() string { return strings.Join(*f, ",") }
func (f *stringFlags) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// handleMgmt 是 @ 命令的入口：先做安全校验（认证方式、TOTP 重验），再分发。
// 任何拒绝都会写 MGMT-DENY 审计。
func (s *Server) handleMgmt(sess glssh.Session, account, rawCmd string) {
	from := sess.User() + "@" + hostOnly(sess.RemoteAddr().String())
	deny := func(reason, msg string) {
		s.audit.Log("MGMT-DENY", "user", sess.User(), "from", from, "reason", reason)
		_, _ = fmt.Fprintln(sess.Stderr(), msg)
		_ = sess.Exit(1)
	}

	// 管理操作必须是「人」在操作：公钥登录是给自动化的，不能管理机器。
	if sess.Context().Value(authMethodKey{}) == "publickey" {
		deny("pubkey", "管理命令只能用密码登录执行（公钥登录是给自动化用的）")
		return
	}
	// 绑了 TOTP 的账号，管理命令要再要一个新验证码——登录时用过的那个不行。
	if acct, ok := s.cfg.Users.Get(account); ok && acct.TOTPEnabled {
		if !s.mgmtReverifyTOTP(sess, account, from) {
			return
		}
	}

	fields := strings.Fields(rawCmd)
	if len(fields) == 0 || fields[0] != "@machine" {
		_, _ = fmt.Fprintln(sess.Stderr(), "未知管理命令，可用：@machine help")
		_ = sess.Exit(2)
		return
	}
	s.mgmtMachine(sess, account, fields[1:], from)
}

// mgmtReverifyTOTP 向会话要一个新的 TOTP 验证码：最多 3 次，每次错记一次
// 失败（走登录同一个限速器）并写一条 MGMT-DENY reason=totp。锁着的不给试。
func (s *Server) mgmtReverifyTOTP(sess glssh.Session, account, from string) bool {
	ip := hostOnly(sess.RemoteAddr().String())
	if !s.guard.allowed(account, ip) {
		s.audit.Log("MGMT-DENY", "user", sess.User(), "from", from, "reason", "locked")
		_, _ = fmt.Fprintln(sess.Stderr(), "失败次数过多，暂时锁定，稍后再试")
		_ = sess.Exit(1)
		return false
	}
	_, _ = fmt.Fprint(sess, "请输入一个新的 TOTP 验证码（登录时用过的那个不能再用）: ")
	for i := 0; i < 3; i++ {
		line, err := readLine(sess)
		if err != nil {
			_ = sess.Exit(1)
			return false
		}
		if s.cfg.Users.VerifyTOTP(account, strings.TrimSpace(line)) {
			s.guard.pass(account, ip)
			_, _ = fmt.Fprint(sess, "\n")
			return true
		}
		s.guard.fail(account, ip)
		s.audit.Log("MGMT-DENY", "user", sess.User(), "from", from, "reason", "totp")
		if i < 2 {
			_, _ = fmt.Fprint(sess, "\n验证码不对，再试: ")
		} else {
			_, _ = fmt.Fprint(sess, "\n")
		}
	}
	_, _ = fmt.Fprintln(sess.Stderr(), "验证码错误次数过多")
	_ = sess.Exit(1)
	return false
}

// mgmtArgs 解析「位置参数和旗标可交错」的命令行（标准库 flag 遇到第一个
// 位置参数就停，所以分段喂），返回位置参数。
func mgmtArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	return pos, nil
}

func (s *Server) mgmtMachine(sess glssh.Session, account string, args []string, from string) {
	usage := func(code int) {
		_, _ = fmt.Fprint(sess, mgmtUsage)
		_ = sess.Exit(code)
	}
	fail := func(err error) {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
	}
	if len(args) == 0 {
		usage(2)
		return
	}
	switch args[0] {
	case "help":
		usage(0)
	case "list":
		tw := tabwriter.NewWriter(sess, 0, 2, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ID\t状态\tagent白名单")
		for _, m := range s.cfg.Users.Machines(account) {
			state := "离线"
			if s.Hub.Has(m.ID()) {
				state = "在线"
			}
			ips := strings.Join(m.AgentAllowIPs, ",")
			if ips == "" {
				ips = "-"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", m.ID(), state, ips)
		}
		_ = tw.Flush()
		_ = sess.Exit(0)
	case "add":
		fs := flag.NewFlagSet("@machine add", flag.ContinueOnError)
		fs.SetOutput(sess.Stderr())
		var allowIPs stringFlags
		fs.Var(&allowIPs, "agent-allow-ip", "这台机器的 agent 只允许这些来源 IP 接入（可重复）")
		pos, err := mgmtArgs(fs, args[1:])
		if err != nil {
			_ = sess.Exit(2)
			return
		}
		if len(pos) != 1 {
			usage(2)
			return
		}
		m, err := s.cfg.Users.AddMachine(account, pos[0], allowIPs)
		if err != nil {
			fail(err)
			return
		}
		s.audit.Log("MACHINE-ADD", "user", sess.User(), "machine", m.ID(), "from", from)
		_, _ = fmt.Fprintf(sess, "机器 %s 已创建\nagent token: %s\n%s\n", m.ID(), m.Token, config.AgentInstallHint(s.cfg.PublicURL, m.Token))
		_ = sess.Exit(0)
	case "remove":
		if len(args) != 2 {
			usage(2)
			return
		}
		id := account + "+" + args[1]
		if err := s.cfg.Users.RemoveMachine(account, args[1]); err != nil {
			fail(err)
			return
		}
		s.audit.Log("MACHINE-REMOVE", "user", sess.User(), "machine", id, "from", from)
		s.revokeStaleAgents() // 在线的那台马上断开，不等 30 秒巡检
		_, _ = fmt.Fprintf(sess, "机器 %s 已删除\n", id)
		_ = sess.Exit(0)
	case "token":
		fs := flag.NewFlagSet("@machine token", flag.ContinueOnError)
		fs.SetOutput(sess.Stderr())
		regen := fs.Bool("regen", false, "（已停用）换 token 请在那台机器上执行 towstrap-agent token refresh")
		pos, err := mgmtArgs(fs, args[1:])
		if err != nil {
			_ = sess.Exit(2)
			return
		}
		if *regen {
			_, _ = fmt.Fprintln(sess.Stderr(), "换 token 请在那台机器上执行 towstrap-agent token refresh（新 token 会直接写进它的 token 文件，不换断连接）")
			_ = sess.Exit(2)
			return
		}
		if len(pos) != 1 {
			usage(2)
			return
		}
		id := account + "+" + pos[0]
		m, ok := s.cfg.Users.GetMachine(account, pos[0])
		if !ok {
			fail(fmt.Errorf("机器 %s 不存在（@machine list 看现有的）", id))
			return
		}
		s.audit.Log("MACHINE-TOKEN", "user", sess.User(), "machine", id, "from", from)
		_, _ = fmt.Fprintf(sess, "agent token: %s\n", m.Token)
		_ = sess.Exit(0)
	default:
		usage(2)
	}
}
