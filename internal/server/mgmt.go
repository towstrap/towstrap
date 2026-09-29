package server

// @ 开头的命令是服务器自己的管理命令，不转发给 agent：账号本人用密码
// 登录（公钥不行）后，可以自助管理自己账号下的机器、MCP 凭据、二因素、
// 登录公钥和密码。目前有 @machine / @mcp / @totp / @sshkey / @passwd。

import (
	"flag"
	"fmt"
	"log/slog"
	"strings"
	"text/tabwriter"
	"time"

	glssh "github.com/gliderlabs/ssh"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/mcpsrv"
	"github.com/towstrap/towstrap/internal/qrcode"
	"github.com/towstrap/towstrap/internal/totp"
)

const mgmtUsage = `服务器管理命令（@ 开头的命令只由服务器执行，不发给 agent）：
  @machine list                                     列出账号下的机器（不含 token）
  @machine add <名字> [--agent-allow-ip 地址]...    加一台机器并打印 agent token
  @machine set <名字> [--agent-allow-ip 地址]...    改这台机器的 agent 来源白名单
                 [--clear-agent-allow]                （不清 token，机器不用重装）
  @machine remove <名字>                            删一台机器，在线 agent 立刻断开
  @machine token <名字>                             看这台机器的 token
                                                    （换 token 在 agent 机器上跑 towstrap token refresh）
  @machine help                                     本说明
  @mcp add <名字> [--machine 机器名]...               签一个 MCP token，默认授权本账号全部机器
  @mcp list                                         列本账号自签的 MCP 客户端
  @mcp set <名字> [--machine 机器名]... [--allow-ip 地址]...
           [--clear-allow] [--disable|--enable]       改自签客户端的授权/白名单/停启用
  @mcp token <名字> [--regen]                        看 / 换发这个客户端的 token
  @mcp remove <名字>                                 删客户端（token 作废）
  @mcp pending                                      列本账号机器上等批准的 MCP 请求
  @mcp approve <编号>|--all [--remember]              批准（--remember 发起会话内不再问）
  @mcp deny <编号>|--all                             拒绝
  @totp                                             绑定/换绑 TOTP 二因素（出二维码，输码确认）
  @totp remove                                      解绑 TOTP
  @sshkey list                                      列已登记的登录公钥（SHA256 指纹 + 注释）
  @sshkey add [公钥行]                               登记一把登录公钥；不带参数则提示粘贴一行
  @sshkey remove <指纹|公钥行>                       删一把登录公钥
  @passwd                                           改自己的 SSH 登录密码
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
	// OAuth 一次性授权换的登录只够「用机器」，够不着管理面：grant
	// 有效期就十几分钟，拿它跑 @machine token/add、@totp 等于把
	// 临时票换成长期钥匙串（甚至给账号绑上攻击者的验证器）。要管理
	// 请用密码（+TOTP）完整登录。
	if sess.Context().Value(authMethodKey{}) == "grant" {
		deny("grant", "这是 OAuth 授权换来的临时登录，管理命令需要密码完整登录")
		return
	}
	// 绑了 TOTP 的账号，管理命令要再要一个新验证码——登录时用过的那个不行。
	if acct, ok := s.cfg.Users.Get(account); ok && acct.TOTPEnabled {
		if !s.mgmtReverifyTOTP(sess, account, from) {
			return
		}
	}

	fields := strings.Fields(rawCmd)
	if len(fields) == 0 || (fields[0] != "@machine" && fields[0] != "@mcp" && fields[0] != "@totp" && fields[0] != "@sshkey" && fields[0] != "@passwd") {
		_, _ = fmt.Fprintln(sess.Stderr(), "未知管理命令，可用：@machine help")
		_ = sess.Exit(2)
		return
	}
	switch fields[0] {
	case "@totp":
		s.mgmtTOTP(sess, account, fields[1:], from)
	case "@mcp":
		s.mgmtMCP(sess, account, fields[1:], from)
	case "@sshkey":
		s.mgmtSSHKey(sess, account, fields[1:], from)
	case "@passwd":
		s.mgmtPasswd(sess, account, from)
	default:
		s.mgmtMachine(sess, account, fields[1:], from)
	}
}

// mgmtTOTP 是 SSH 里的 TOTP 自助：enroll 出二维码+输码确认（已绑过的走
// 上面那道 TOTP 重验，等于换绑）；remove 解绑。失败都记 MGMT-DENY。
func (s *Server) mgmtTOTP(sess glssh.Session, account string, args []string, from string) {
	if len(args) > 0 && args[0] == "remove" {
		if err := s.cfg.Users.RemoveTOTP(account); err != nil {
			_, _ = fmt.Fprintln(sess.Stderr(), err)
			_ = sess.Exit(1)
			return
		}
		s.audit.Log("TOTP-REMOVE", "user", sess.User(), "from", from)
		_, _ = fmt.Fprintln(sess, "TOTP 已解绑——之后登录只要密码。SSH 面薄了，建议尽快绑回来")
		_ = sess.Exit(0)
		return
	}
	secret, uri := totp.Generate("towstrap", account)
	_, _ = fmt.Fprintln(sess, "在验证器（Google Authenticator / 1Password / Aegis 等）里添加：")
	if qr, err := qrcode.Terminal(uri); err == nil {
		_, _ = fmt.Fprint(sess, qr)
	}
	_, _ = fmt.Fprintf(sess, "  %s\n手动录入秘钥: %s\n", uri, totp.SecretString(secret))
	_, _ = fmt.Fprint(sess, "输入验证器上现在的 6 位码确认绑定: ")
	line, err := readLine(sess)
	if err != nil {
		_ = sess.Exit(1)
		return
	}
	step, ok := totp.Verify(secret, strings.TrimSpace(line), 0, time.Now())
	if !ok {
		s.audit.Log("MGMT-DENY", "user", sess.User(), "from", from, "reason", "totp-enroll")
		_, _ = fmt.Fprintln(sess.Stderr(), "验证码不对，未绑定")
		_ = sess.Exit(1)
		return
	}
	if err := s.cfg.Users.EnrollTOTP(account, secret, step); err != nil {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
		return
	}
	s.audit.Log("TOTP-ENROLL", "user", sess.User(), "from", from)
	_, _ = fmt.Fprintln(sess, "TOTP 已绑定——之后登录是 密码 + 6 位动态码 两道")
	_ = sess.Exit(0)
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

// mgmtSSHKey 是 SSH 里的公钥自助：list 列已登记的、add 挂一把（不带
// 参数就提示粘贴一行）、remove 按指纹或公钥行删。能走到这的会话本身
// 已经过了完整登录 + TOTP 重验（公钥/一次性授权登录在上面就被拦了），
// 所以这里直接对账号操作。
func (s *Server) mgmtSSHKey(sess glssh.Session, account string, args []string, from string) {
	fail := func(err error) {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(sess, mgmtUsage)
		_ = sess.Exit(2)
		return
	}
	switch args[0] {
	case "list":
		acct, ok := s.cfg.Users.Get(account)
		if !ok || len(acct.SSHKeys) == 0 {
			_, _ = fmt.Fprintln(sess, "这个账号还没登记公钥——@sshkey add 挂一把")
			_ = sess.Exit(0)
			return
		}
		for _, line := range acct.SSHKeys {
			k := sshKeyInfo(line)
			fp := k.Fingerprint
			if fp == "" {
				fp = "（解析不了）"
			}
			_, _ = fmt.Fprintf(sess, "%s  %s\n    %s\n", fp, k.Comment, k.Line)
		}
		_ = sess.Exit(0)
	case "add":
		line := strings.TrimSpace(strings.Join(args[1:], " "))
		if line == "" {
			_, _ = fmt.Fprint(sess, "粘贴要登记的公钥行（authorized_keys 格式，回车结束）: ")
			l, err := readLine(sess)
			if err != nil {
				_ = sess.Exit(1)
				return
			}
			line = strings.TrimSpace(l)
		}
		if line == "" {
			fail(fmt.Errorf("没收到公钥行"))
			return
		}
		if err := s.cfg.Users.AddSSHKey(account, line); err != nil {
			fail(err)
			return
		}
		fp := sshKeyInfo(line).Fingerprint
		s.audit.Log("SSHKEY-ADD", "user", sess.User(), "from", from, "fp", fp)
		_, _ = fmt.Fprintf(sess, "公钥已登记 %s——之后拿对应私钥 ssh -i 登录，不用密码\n", fp)
		_ = sess.Exit(0)
	case "remove":
		if len(args) < 2 {
			_, _ = fmt.Fprintln(sess.Stderr(), "用法：@sshkey remove <SHA256 指纹|公钥行>")
			_ = sess.Exit(2)
			return
		}
		keyID := strings.TrimSpace(strings.Join(args[1:], " "))
		if err := s.cfg.Users.RemoveSSHKey(account, keyID); err != nil {
			fail(err)
			return
		}
		s.audit.Log("SSHKEY-REMOVE", "user", sess.User(), "from", from, "key", auditCmd(keyID))
		_, _ = fmt.Fprintln(sess, "公钥已删除")
		_ = sess.Exit(0)
	default:
		_, _ = fmt.Fprintln(sess.Stderr(), "用法：@sshkey list | add [公钥行] | remove <指纹|公钥行>")
		_ = sess.Exit(2)
	}
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
	case "set":
		fs := flag.NewFlagSet("@machine set", flag.ContinueOnError)
		fs.SetOutput(sess.Stderr())
		var allowIPs stringFlags
		fs.Var(&allowIPs, "agent-allow-ip", "这台机器的 agent 只允许这些来源 IP 接入（可重复）")
		clearAgentAllow := fs.Bool("clear-agent-allow", false, "清空 agent 来源白名单（回到不限来源）")
		pos, err := mgmtArgs(fs, args[1:])
		if err != nil {
			_ = sess.Exit(2)
			return
		}
		if len(pos) != 1 {
			usage(2)
			return
		}
		if *clearAgentAllow && len(allowIPs) > 0 {
			fail(fmt.Errorf("--agent-allow-ip 和 --clear-agent-allow 二选一"))
			return
		}
		if !*clearAgentAllow && len(allowIPs) == 0 {
			fail(fmt.Errorf("没给要改的内容（--agent-allow-ip / --clear-agent-allow）"))
			return
		}
		id := account + "+" + pos[0]
		if _, ok := s.cfg.Users.GetMachine(account, pos[0]); !ok {
			fail(fmt.Errorf("机器 %s 不存在（@machine list 看现有的）", id))
			return
		}
		if err := s.cfg.Users.SetMachineAgentAllow(account, pos[0], allowIPs); err != nil {
			fail(err)
			return
		}
		s.audit.Log("MACHINE-SET", "user", sess.User(), "machine", id, "agent-allow-ip", strings.Join(allowIPs, ","), "from", from)
		if *clearAgentAllow {
			_, _ = fmt.Fprintf(sess, "机器 %s 的 agent 来源白名单已清空（不限来源）\n", id)
		} else {
			_, _ = fmt.Fprintf(sess, "机器 %s 的 agent 来源白名单已更新：%s\n", id, strings.Join(allowIPs, ", "))
		}
		_ = sess.Exit(0)
	case "token":
		fs := flag.NewFlagSet("@machine token", flag.ContinueOnError)
		fs.SetOutput(sess.Stderr())
		regen := fs.Bool("regen", false, "（已停用）换 token 请在那台机器上执行 towstrap token refresh")
		pos, err := mgmtArgs(fs, args[1:])
		if err != nil {
			_ = sess.Exit(2)
			return
		}
		if *regen {
			_, _ = fmt.Fprintln(sess.Stderr(), "换 token 请在那台机器上执行 towstrap token refresh（新 token 会直接写进它的 token 文件，不换断连接）")
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

// mcpSelfName 是账号自签 MCP 客户端在库里的全名：「账号.名字」。它只负责
// 起名字——**归属判定不靠这个名字**（账号名允许点号，前缀不是无歧义的
// 名字空间），而是靠库里的 owner 列（见 MCPOwnedGet/OwnedList）。管理员
// 代签的客户端 owner 留空，@mcp 任何子命令都碰不到。
func mcpSelfName(account, name string) string {
	return account + "." + strings.TrimPrefix(name, account+".")
}

// mcpSelfGet 是 @mcp 子命令取「本账号自签客户端」的唯一入口：库里按 owner
// 列圈定归属，名字只是用户敲的短名。@mcp 的 token/set/remove 都先过它，
// 拿不到就是不属于本账号——归属判错的后果是明文 token 外送或凭据被改废。
func (s *Server) mcpSelfGet(account, name string) (accounts.MCPClient, bool) {
	return s.cfg.Users.MCPOwnedGet(account, mcpSelfName(account, name))
}

// validMCPClientShort 校验自签客户端的短名。**短名里不许有点**：全名是
// 「账号.短名」且拼在同一个全局唯一列里，账号名本身可带点，短名再带点
// 就不是单射——账号 alice 的 "bob.laptop" 会拼出账号 alice.bob 的
// "alice.bob.laptop"，抢注先把名字占死，对方就再也建不出自己的客户端。
// 禁掉短名里的点之后，按最后一个点拆分是唯一的。
func validMCPClientShort(name string) error {
	if name == "" {
		return fmt.Errorf("名字不能为空")
	}
	if strings.Contains(name, ".") {
		return fmt.Errorf("名字 %q 里不能带点——名字是「账号.名字」拼出来的，带点会和别的账号撞名", name)
	}
	return nil
}

// mcpSelfMachines 把 --machine 参数收敛成「只能指向本账号」的授权列表：
// 允许 机器名（补成 账号+机器名）、账号、账号+*、账号+机器名；裸 "*"
// 和别人账号一律拒。空列表默认授权整个账号。
func (s *Server) mcpSelfMachines(account string, specs []string) ([]string, error) {
	if len(specs) == 0 {
		return []string{account}, nil
	}
	out := make([]string, 0, len(specs))
	for _, spec := range specs {
		u, mn := accounts.SplitMachineID(spec)
		if mn == "" && u != account {
			mn, u = u, account // 裸机器名写法：--machine office = 本账号+office
		}
		switch {
		case spec == "*" || u != account:
			return nil, fmt.Errorf("--machine %q 越界：自签 token 只能授权本账号（%s）下的机器", spec, account)
		case mn == "" || mn == "*":
			out = append(out, account)
		default:
			if _, ok := s.cfg.Users.GetMachine(account, mn); !ok {
				return nil, fmt.Errorf("机器 %s+%s 不存在（@machine list 看现有的，或先 @machine add）", account, mn)
			}
			out = append(out, account+"+"+mn)
		}
	}
	return out, nil
}

// mgmtMCP 是 SSH 里的 MCP token 自助签发：账号本人给自己的机器签 MCP
// 凭据，不需要管理员跑 towstrap-server mcp add。安全性来自两点：一是
// 走到这已经过了密码登录 + TOTP 重验（公钥/一次性授权在上面被拦）；二是
// 授权范围被锁死在本账号——这人本来就能 SSH 上这些机器拿完整 shell，
// MCP token 只过策略引擎，是比 shell 更弱的凭据，不算放权。
func (s *Server) mgmtMCP(sess glssh.Session, account string, args []string, from string) {
	usage := func(code int) {
		_, _ = fmt.Fprint(sess, mgmtUsage)
		_ = sess.Exit(code)
	}
	fail := func(err error) {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
	}
	// 本账号自签的客户端在库里挂在 owner 列上（本账号），操作前按 owner
	// 取，不按名字前缀——账号名允许点号，前缀匹配会撞到别人账号名里带点
	// 的客户端（账号 alice 能拼出 alice.bob.laptop 这种名字）。取不到就是
	// 不属于本账号，管理员签的别的名字的客户端也一并挡在外面。
	get := func(name string) (accounts.MCPClient, bool) {
		return s.mcpSelfGet(account, name)
	}
	if len(args) == 0 {
		usage(2)
		return
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("@mcp add", flag.ContinueOnError)
		fs.SetOutput(sess.Stderr())
		var machines stringFlags
		fs.Var(&machines, "machine", "授权哪台机器（可重复）；写机器名或 账号+机器名，只能是本账号的；不带 = 整个账号")
		pos, err := mgmtArgs(fs, args[1:])
		if err != nil {
			_ = sess.Exit(2)
			return
		}
		if len(pos) != 1 {
			usage(2)
			return
		}
		if err := validMCPClientShort(pos[0]); err != nil {
			fail(err)
			return
		}
		grants, err := s.mcpSelfMachines(account, machines)
		if err != nil {
			fail(err)
			return
		}
		c, token, err := s.cfg.Users.MCPAdd(mcpSelfName(account, pos[0]), account, grants, nil)
		if err != nil {
			fail(err)
			return
		}
		s.audit.Log("MCP-ADD", "user", sess.User(), "client", c.Name, "machines", strings.Join(grants, ","), "from", from)
		_, _ = fmt.Fprintf(sess, "MCP 客户端 %s 已创建（授权：%s）\ntoken: %s\n", c.Name, strings.Join(grants, " "), token)
		if s.cfg.PublicURL != "" {
			_, _ = fmt.Fprintf(sess, "\n跑 AI 客户端的机器上一条命令接入：\n  curl -fsSL %s/install-mcp.sh | sh -s -- --token %s\n", s.cfg.PublicURL, token)
		}
		_, _ = fmt.Fprintln(sess, "token 只在这里显示这一次——丢了用 @mcp token "+pos[0]+" --regen 换新的")
		_ = sess.Exit(0)
	case "list":
		tw := tabwriter.NewWriter(sess, 0, 2, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "名字\t授权\t状态\t创建时间")
		n := 0
		prefix := account + "."
		for _, c := range s.cfg.Users.MCPOwnedList(account) {
			state := "启用"
			if c.Disabled {
				state = "停用"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strings.TrimPrefix(c.Name, prefix),
				strings.Join(c.Machines, ","), state, c.CreatedAt.Local().Format("2006-01-02 15:04"))
			n++
		}
		_ = tw.Flush()
		if n == 0 {
			_, _ = fmt.Fprintln(sess, "还没有自签的 MCP 客户端——@mcp add <名字> 签一个")
		}
		_ = sess.Exit(0)
	case "token":
		fs := flag.NewFlagSet("@mcp token", flag.ContinueOnError)
		fs.SetOutput(sess.Stderr())
		regen := fs.Bool("regen", false, "换发新 token（旧的立刻作废）")
		pos, err := mgmtArgs(fs, args[1:])
		if err != nil {
			_ = sess.Exit(2)
			return
		}
		if len(pos) != 1 {
			usage(2)
			return
		}
		full := mcpSelfName(account, pos[0])
		if _, ok := get(pos[0]); !ok {
			fail(fmt.Errorf("MCP 客户端 %s 不存在（@mcp list 看现有的）", full))
			return
		}
		if *regen {
			token, err := s.cfg.Users.MCPOwnedRegenToken(account, full)
			if err != nil {
				fail(err)
				return
			}
			s.audit.Log("MCP-TOKEN", "user", sess.User(), "client", full, "op", "regen", "from", from)
			_, _ = fmt.Fprintf(sess, "新 token: %s\n旧的已作废——各 AI 客户端配置里的 token 要更新\n", token)
		} else {
			c, _ := get(pos[0])
			s.audit.Log("MCP-TOKEN", "user", sess.User(), "client", full, "op", "show", "from", from)
			_, _ = fmt.Fprintf(sess, "token: %s\n", c.Token)
		}
		_ = sess.Exit(0)
	case "remove":
		if len(args) != 2 {
			usage(2)
			return
		}
		full := mcpSelfName(account, args[1])
		if _, ok := get(args[1]); !ok {
			fail(fmt.Errorf("MCP 客户端 %s 不存在（@mcp list 看现有的）", full))
			return
		}
		if err := s.cfg.Users.MCPOwnedRemove(account, full); err != nil {
			fail(err)
			return
		}
		s.audit.Log("MCP-REMOVE", "user", sess.User(), "client", full, "from", from)
		_, _ = fmt.Fprintf(sess, "MCP 客户端 %s 已删除，token 作废\n", full)
		_ = sess.Exit(0)
	case "set":
		fs := flag.NewFlagSet("@mcp set", flag.ContinueOnError)
		fs.SetOutput(sess.Stderr())
		var machines, allowIPs stringFlags
		fs.Var(&machines, "machine", "授权哪台机器（可重复）；给了就是整体替换授权列表")
		fs.Var(&allowIPs, "allow-ip", "这个 token 只允许这些来源 IP 使用（可重复）")
		clearAllow := fs.Bool("clear-allow", false, "清空来源白名单（回到不限来源）")
		disable := fs.Bool("disable", false, "停用（token 立刻不能用，配置保留）")
		enable := fs.Bool("enable", false, "重新启用")
		pos, err := mgmtArgs(fs, args[1:])
		if err != nil {
			_ = sess.Exit(2)
			return
		}
		if len(pos) != 1 {
			usage(2)
			return
		}
		if *clearAllow && len(allowIPs) > 0 {
			fail(fmt.Errorf("--allow-ip 和 --clear-allow 二选一"))
			return
		}
		if *disable && *enable {
			fail(fmt.Errorf("--disable 和 --enable 二选一"))
			return
		}
		full := mcpSelfName(account, pos[0])
		if _, ok := get(pos[0]); !ok {
			fail(fmt.Errorf("MCP 客户端 %s 不存在（@mcp list 看现有的）", full))
			return
		}
		var machinesP *[]string
		if len(machines) > 0 {
			grants, err := s.mcpSelfMachines(account, machines)
			if err != nil {
				fail(err)
				return
			}
			machinesP = &grants
		}
		var allowP *[]string
		switch {
		case *clearAllow:
			empty := []string{}
			allowP = &empty
		case len(allowIPs) > 0:
			ips := []string(allowIPs)
			allowP = &ips
		}
		var disP *bool
		if *disable || *enable {
			v := *disable
			disP = &v
		}
		if machinesP == nil && allowP == nil && disP == nil {
			fail(fmt.Errorf("没给要改的内容（--machine / --allow-ip / --clear-allow / --disable / --enable）"))
			return
		}
		if err := s.cfg.Users.MCPOwnedSet(account, full, machinesP, allowP, disP); err != nil {
			fail(err)
			return
		}
		s.audit.Log("MCP-SET", "user", sess.User(), "client", full, "from", from)
		_, _ = fmt.Fprintf(sess, "MCP 客户端 %s 已更新\n", full)
		_ = sess.Exit(0)
	case "pending", "approve", "deny":
		s.mgmtMCPApprove(sess, account, args[0], args[1:], from)
	default:
		usage(2)
	}
}

// mcpApprovalsDir 是服务器端 MCP 批准目录；MCP 没开或目录没配好返回空串。
func (s *Server) mcpApprovalsDir() string {
	if s.cfg.MCP == nil {
		return ""
	}
	return s.cfg.MCP.ApprovalsDir
}

// ownPending 列出批准目录里属于本账号机器的请求（pf.Machine 的账号部分
// 和登录账号相等才算——别人的待批连看都看不见，也就批不着）。
func (s *Server) ownPending(account, dir string) ([]mcpsrv.PendingFile, error) {
	list, err := mcpsrv.Pending(dir)
	if err != nil {
		return nil, err
	}
	var out []mcpsrv.PendingFile
	for _, p := range list {
		if u, _ := accounts.SplitMachineID(p.Machine); u == account {
			out = append(out, p)
		}
	}
	return out, nil
}

// mgmtMCPApprove 是 SSH 里的 MCP 待批自助：批准本该由这台机器的主人做，
// 不该事事找管理员。范围锁死在本账号待批项上——approve --all 也只批
// 自己机器的，不会顺手批了别人的请求。
func (s *Server) mgmtMCPApprove(sess glssh.Session, account, verb string, args []string, from string) {
	fail := func(err error) {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
	}
	dir := s.mcpApprovalsDir()
	if dir == "" {
		fail(fmt.Errorf("服务器没开 MCP（server.yaml 的 mcp.enabled），没有批准目录"))
		return
	}
	if verb == "pending" {
		list, err := s.ownPending(account, dir)
		if err != nil {
			fail(fmt.Errorf("读批准目录失败: %w", err))
			return
		}
		if len(list) == 0 {
			_, _ = fmt.Fprintln(sess, "本账号没有等待批准的 MCP 请求")
			_ = sess.Exit(0)
			return
		}
		for _, p := range list {
			// Machine/Kind/Detail/Preview 是 LLM 给的原文——打进终端前
			// 过一遍清洗，不然一条带转义序列的「命令」能画假提示清屏。
			_, _ = fmt.Fprintf(sess, "%s  %s  %-8s  %s  （等了 %s）\n",
				p.ID, auditlog.Clean(p.Machine), auditlog.Clean(p.Kind), auditlog.Clean(p.Detail),
				time.Since(p.Created).Round(time.Second))
			if p.Preview != "" {
				_, _ = fmt.Fprintf(sess, "    ↳ %s\n", auditlog.Clean(p.Preview))
			}
		}
		_, _ = fmt.Fprintln(sess, "\n批准：@mcp approve [--remember] <编号>|--all；拒绝：@mcp deny <编号>|--all")
		_ = sess.Exit(0)
		return
	}
	fs := flag.NewFlagSet("@mcp "+verb, flag.ContinueOnError)
	fs.SetOutput(sess.Stderr())
	all := fs.Bool("all", false, "处理本账号的全部待批请求")
	rem := fs.Bool("remember", false, "批准后让发起会话记住这条命令（本会话内不再问）")
	pos, err := mgmtArgs(fs, args)
	if err != nil {
		_ = sess.Exit(2)
		return
	}
	if *all && len(pos) > 0 || !*all && len(pos) != 1 {
		_, _ = fmt.Fprintf(sess.Stderr(), "用法：@mcp %s <编号>|--all\n", verb)
		_ = sess.Exit(2)
		return
	}
	list, err := s.ownPending(account, dir)
	if err != nil {
		fail(fmt.Errorf("读批准目录失败: %w", err))
		return
	}
	ownIDs := map[string]bool{}
	for _, p := range list {
		ownIDs[p.ID] = true
	}
	var ids []string
	if *all {
		for _, p := range list {
			ids = append(ids, p.ID)
		}
		if len(ids) == 0 {
			_, _ = fmt.Fprintln(sess, "本账号没有等待批准的 MCP 请求")
			_ = sess.Exit(0)
			return
		}
	} else {
		if !ownIDs[pos[0]] {
			fail(fmt.Errorf("待批请求 %s 不存在或不属于本账号（@mcp pending 看现有的）", pos[0]))
			return
		}
		ids = []string{pos[0]}
	}
	// 逐 id 落批准文件——不用 settle 的 all=true：那会把目录里别人账号
	// 的待批也一起批了，越界。
	for _, id := range ids {
		var err error
		if verb == "approve" {
			_, err = mcpsrv.ApprovePending(dir, id, false, *rem)
		} else {
			_, err = mcpsrv.DenyPending(dir, id, false)
		}
		if err != nil {
			fail(fmt.Errorf("处理 %s 失败: %w", id, err))
			return
		}
	}
	ev := "MCP-DENY"
	if verb == "approve" {
		ev = "MCP-APPROVE"
	}
	s.audit.Log(ev, "user", sess.User(), "ids", strings.Join(ids, ","), "from", from)
	verbCN := "已拒绝"
	if verb == "approve" {
		verbCN = "已批准"
	}
	_, _ = fmt.Fprintf(sess, "%s %d 条\n", verbCN, len(ids))
	_ = sess.Exit(0)
}

// mgmtPasswd 是 SSH 里的自助改密码：手里没在线 agent 机器（比如只有
// 手机登着）也能改。会话本身是密码+TOTP 登进来的，但密码再验一遍旧值
// ——防止别人趁你不在摸进开着的终端改密。验证走登录同一个限速器。
func (s *Server) mgmtPasswd(sess glssh.Session, account, from string) {
	fail := func(err error) {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
	}
	ip := hostOnly(sess.RemoteAddr().String())
	if !s.guard.allowed(account, ip) {
		s.audit.Log("MGMT-DENY", "user", sess.User(), "from", from, "reason", "locked")
		_, _ = fmt.Fprintln(sess.Stderr(), "失败次数过多，暂时锁定，稍后再试")
		_ = sess.Exit(1)
		return
	}
	_, _ = fmt.Fprint(sess, "当前密码: ")
	oldOK := false
	for i := 0; i < 3; i++ {
		line, err := readLine(sess)
		if err != nil {
			_ = sess.Exit(1)
			return
		}
		if s.cfg.Users.Verify(account, strings.TrimSpace(line)) {
			s.guard.pass(account, ip)
			oldOK = true
			break
		}
		s.guard.fail(account, ip)
		s.audit.Log("MGMT-DENY", "user", sess.User(), "from", from, "reason", "passwd-oldpw")
		if i < 2 {
			_, _ = fmt.Fprint(sess, "\n密码不对，再试: ")
		} else {
			_, _ = fmt.Fprint(sess, "\n")
		}
	}
	if !oldOK {
		_, _ = fmt.Fprintln(sess.Stderr(), "密码错误次数过多")
		_ = sess.Exit(1)
		return
	}
	_, _ = fmt.Fprint(sess, "新密码: ")
	p1, err := readLine(sess)
	if err != nil {
		_ = sess.Exit(1)
		return
	}
	_, _ = fmt.Fprint(sess, "再输一次新密码: ")
	p2, err := readLine(sess)
	if err != nil {
		_ = sess.Exit(1)
		return
	}
	p1, p2 = strings.TrimSpace(p1), strings.TrimSpace(p2)
	if p1 != p2 {
		fail(fmt.Errorf("两次输入不一致"))
		return
	}
	if err := s.cfg.Users.SetPassword(account, p1); err != nil {
		fail(err)
		return
	}
	// 和 /passwd 一样的收尾：旧密码可能已经被拿去换过 OAuth grant，
	// 改密码顺手把没过期的一次性凭据全吊销。
	if err := s.cfg.Users.RevokeSSHGrants(account); err != nil {
		slog.Warn("吊销 SSH 凭据失败", "account", account, "err", err)
	}
	s.audit.Log("PASSWD", "account", account, "via", "ssh", "from", from)
	_, _ = fmt.Fprintln(sess, "密码已更新——没过期的一次性登录凭据也已吊销")
	_ = sess.Exit(0)
}
