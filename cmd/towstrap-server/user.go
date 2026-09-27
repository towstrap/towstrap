package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/qrcode"
	"github.com/towstrap/towstrap/internal/totp"
)

// ---- 账号管理 ----

func usageUser() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap-server user add  用户名 [--password 密码] [--contact 联系方式] [--allow-ip 地址]...
                           [--ssh-key 公钥]... [--ssh-key-file 文件] [通用选项]
  towstrap-server user list [通用选项]
  towstrap-server user set   用户名 [--password 密码] [--name 新名] [--contact 联系方式]
                           [--clear-contact] [--allow-ip 地址]... [--clear-allow]
                           [--agent-allow-ip 地址]... [--clear-agent-allow]
                           [--ssh-key 公钥]... [--ssh-key-file 文件]
                           [--remove-ssh-key 公钥或SHA256指纹]... [--clear-ssh-keys]
                           [--disable] [--enable]
                           [--oauth-only | --no-oauth-only]       账号级：名下所有
                               机器 SSH 只收 OAuth 换来的短时效凭据
                           [--oidc-bind IdP的sub [--oidc-email 邮箱] [--oidc-issuer 来源]]
                           [--oidc-unbind IdP的sub [--oidc-issuer 来源]]
                               预先绑定/解绑外部身份；issuer 默认取 server.yaml
                               的 oauth.issuer
                           [通用选项]
  towstrap-server user remove 用户名 [通用选项]
  towstrap-server user token  用户名 [--regen] [--admin] [通用选项]
                           看 token（仅当账号只有一台机器；多台用 machine
                           token 指定）。要账号本人确认：密码 + TOTP；--admin
                           跳过（打警告并写审计 MACHINE-TOKEN-ADMIN）。
                           --regen 是应急换法，必须 --admin
  towstrap-server user totp   用户名 [--remove] [通用选项]    绑定/解绑 TOTP 二因素验证器

通用选项: --config server.yaml（读里面的 users_db/users_key/public_url/audit_log）、
          --users-db 路径、--users-key 路径、--server-url 地址、--audit-log 路径
`)
}

func runUser(args []string) int {
	if len(args) == 0 {
		usageUser()
		return 2
	}
	verb := args[0]
	args = args[1:]
	var code int
	switch verb {
	case "add":
		code = userAdd(args)
	case "list":
		code = userList(args)
	case "set":
		code = userSet(args)
	case "remove":
		code = userRemove(args)
	case "token":
		code = userToken(args)
	case "totp":
		code = userTOTP(args)
	default:
		usageUser()
		return 2
	}
	return code
}

// userEnv 是账号命令的公共环境：账号文件 + 生成安装命令用的服务器地址。
// auditPath 只在需要写管理员审计的命令里填（machine add/token、user token）。
type userEnv struct {
	store     *accounts.Store
	serverURL string
	auditPath string
}

func loadUserEnv(configPath, usersDB, usersKey, serverURL string) (userEnv, bool) {
	db, key, url := usersDB, usersKey, serverURL
	if db == "" || url == "" {
		if configPath != "" {
			s, err := config.LoadServer(configPath)
			if err != nil {
				slog.Error(err.Error())
				return userEnv{}, false
			}
			if db == "" && s.UsersDB != "" {
				db = s.UsersDB
			}
			if key == "" && s.UsersKey != "" {
				key = s.UsersKey
			}
			if url == "" && s.PublicURL != "" {
				url = s.PublicURL
			}
		}
	}
	if db == "" {
		db = "/etc/towstrap/users.db"
	}
	store, err := accounts.Open(db, key)
	if err != nil {
		slog.Error(err.Error())
		return userEnv{}, false
	}
	return userEnv{store: store, serverURL: url}, true
}

func printInstallHint(url, token string) {
	fmt.Println(config.AgentInstallHint(url, token))
	if url == "" {
		fmt.Println("（提示：加 --server-url wss://域名:443 或在 server.yaml 写 public_url 可生成完整命令）")
	}
}

// parseMix 解析「位置参数和 --flag 可交错」的命令行（标准库 flag 遇到第一个
// 非 flag 参数就停），返回位置参数。
func parseMix(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			return positional
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// readKeyFile 读 authorized_keys 格式的公钥文件：逐行返回，跳过空行和
// # 注释行。
func readKeyFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// 公钥行一般几百字节，给注释长的行留足余量
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var lines []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

// keyFingerprint 从一行公钥算出 SHA256 指纹用于展示。
func keyFingerprint(line string) string {
	pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return gossh.FingerprintSHA256(pk)
}

func userAdd(args []string) int {
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	usersDB := fs.String("users-db", "", "")
	usersKey := fs.String("users-key", "", "")
	serverURL := fs.String("server-url", "", "")
	password := fs.String("password", "", "")
	contact := fs.String("contact", "", "负责人/联系方式备注，只做追溯")
	var allowIPs config.StringList
	fs.Var(&allowIPs, "allow-ip", "")
	var agentAllowIPs config.StringList
	fs.Var(&agentAllowIPs, "agent-allow-ip", "")
	var sshKeys config.StringList
	fs.Var(&sshKeys, "ssh-key", "")
	sshKeyFile := fs.String("ssh-key-file", "", "")
	rest := parseMix(fs, args)
	name := firstArg(rest)
	if name == "" {
		usageUser()
		return 2
	}
	// 公钥先读进来再建号：文件读不了就别留个半成品账号
	keyLines := []string(sshKeys)
	if *sshKeyFile != "" {
		lines, err := readKeyFile(*sshKeyFile)
		if err != nil {
			slog.Error(fmt.Sprintf("读公钥文件 %s: %s", *sshKeyFile, err))
			return 2
		}
		keyLines = append(keyLines, lines...)
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}

	pw := *password
	generated := false
	if pw == "" {
		// 不给密码就生成强随机密码，只在这里显示一次（库里只有 bcrypt 哈希）
		pw = accounts.RandomPassword()
		generated = true
	}

	acct, err := env.store.Add(name, pw, allowIPs, *contact, agentAllowIPs)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}
	for _, line := range keyLines {
		if err := env.store.AddSSHKey(name, line); err != nil {
			slog.Error(err.Error())
			return 2
		}
	}
	fmt.Printf("已建号 %s（SSH 用户名 %s）\n", acct.Username, acct.Username)
	if generated {
		fmt.Printf("SSH 密码（只显示这一次，请立即保存）: %s\n", pw)
	}
	if len(keyLines) > 0 {
		fmt.Println("SSH 公钥已登记：")
		for _, line := range keyLines {
			fmt.Printf("  %s\n", keyFingerprint(line))
		}
	}
	if len(acct.AllowIPs) > 0 {
		fmt.Printf("白名单: %s\n", strings.Join(acct.AllowIPs, ", "))
	}
	token := acct.Machines[0].Token
	fmt.Printf("默认机器: %s\n", acct.Machines[0].ID())
	fmt.Printf("agent token: %s\n", token)
	printInstallHint(env.serverURL, token)
	return 0
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func userList(args []string) int {
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	usersDB := fs.String("users-db", "", "")
	usersKey := fs.String("users-key", "", "")
	serverURL := fs.String("server-url", "", "")
	parseMix(fs, args)
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	list := env.store.List()
	if len(list) == 0 {
		fmt.Println("还没有账号。用 towstrap user add 用户名 开一个。")
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "用户名\t状态\tTOTP\t公钥\tOAuth\t联系方式\tSSH白名单\t机器")
	for _, a := range list {
		state := "启用"
		if a.Disabled {
			state = "停用"
		}
		totpState := "-"
		if a.TOTPEnabled {
			totpState = "已绑定"
		}
		keys := "-"
		if len(a.SSHKeys) > 0 {
			keys = fmt.Sprintf("%d", len(a.SSHKeys))
		}
		ips := strings.Join(a.AllowIPs, ",")
		if ips == "" {
			ips = "-"
		}
		var names []string
		for _, m := range a.Machines {
			names = append(names, m.Name)
		}
		machines := strings.Join(names, ",")
		if machines == "" {
			machines = "-"
		}
		contact := a.Contact
		if contact == "" {
			contact = "-"
		}
		oauthState := "-"
		if a.OAuthOnly {
			oauthState = "仅OAuth"
		} else if n := len(env.store.OAuthIdentities(a.Username)); n > 0 {
			oauthState = fmt.Sprintf("%d个绑定", n)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.Username, state, totpState, keys, oauthState, contact, ips, machines)
	}
	tw.Flush()
	return 0
}

func userSet(args []string) int {
	fs := flag.NewFlagSet("user set", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	usersDB := fs.String("users-db", "", "")
	usersKey := fs.String("users-key", "", "")
	serverURL := fs.String("server-url", "", "")
	password := fs.String("password", "", "")
	newName := fs.String("name", "", "")
	contact := fs.String("contact", "", "")
	clearContact := fs.Bool("clear-contact", false, "")
	var allowIPs config.StringList
	fs.Var(&allowIPs, "allow-ip", "")
	clearAllow := fs.Bool("clear-allow", false, "")
	var agentAllowIPs config.StringList
	fs.Var(&agentAllowIPs, "agent-allow-ip", "")
	clearAgentAllow := fs.Bool("clear-agent-allow", false, "")
	var sshKeys, removeKeys config.StringList
	fs.Var(&sshKeys, "ssh-key", "")
	sshKeyFile := fs.String("ssh-key-file", "", "")
	fs.Var(&removeKeys, "remove-ssh-key", "")
	clearSSHKeys := fs.Bool("clear-ssh-keys", false, "")
	disable := fs.Bool("disable", false, "")
	enable := fs.Bool("enable", false, "")
	oauthOnly := fs.Bool("oauth-only", false, "")
	noOAuthOnly := fs.Bool("no-oauth-only", false, "")
	oidcBind := fs.String("oidc-bind", "", "")
	oidcUnbind := fs.String("oidc-unbind", "", "")
	oidcEmail := fs.String("oidc-email", "", "")
	oidcIssuer := fs.String("oidc-issuer", "", "")
	rest := parseMix(fs, args)
	name := firstArg(rest)
	if name == "" {
		usageUser()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}

	if *newName != "" {
		if err := env.store.Rename(name, *newName); err != nil {
			slog.Error(err.Error())
			return 2
		}
		fmt.Printf("已改名 %s -> %s（agent 不用动，token 不变）\n", name, *newName)
		name = *newName
	}
	if *password != "" {
		if err := env.store.SetPassword(name, *password); err != nil {
			slog.Error(err.Error())
			return 2
		}
		fmt.Println("密码已更新")
	}
	if *contact != "" || *clearContact {
		val := *contact
		if *clearContact {
			val = ""
		}
		if err := env.store.SetContact(name, val); err != nil {
			slog.Error(err.Error())
			return 2
		}
		if val == "" {
			fmt.Println("联系方式已清空")
		} else {
			fmt.Printf("联系方式已更新: %s\n", val)
		}
	}
	if len(allowIPs) > 0 || *clearAllow {
		ips := []string(allowIPs)
		if *clearAllow {
			ips = nil
		}
		if err := env.store.SetAllow(name, ips); err != nil {
			slog.Error(err.Error())
			return 2
		}
		if len(ips) == 0 {
			fmt.Println("白名单已清空（不限来源）")
		} else {
			fmt.Printf("白名单已更新: %s\n", strings.Join(ips, ", "))
		}
	}
	if len(agentAllowIPs) > 0 || *clearAgentAllow {
		ips := []string(agentAllowIPs)
		if *clearAgentAllow {
			ips = nil
		}
		if err := env.store.SetAgentAllow(name, ips); err != nil {
			slog.Error(err.Error())
			return 2
		}
		if len(ips) == 0 {
			fmt.Println("agent 来源白名单已清空（不限来源，仅记录变更）")
		} else {
			fmt.Printf("agent 来源白名单已更新: %s\n", strings.Join(ips, ", "))
		}
	}
	if *clearSSHKeys {
		if err := env.store.ClearSSHKeys(name); err != nil {
			slog.Error(err.Error())
			return 2
		}
		fmt.Println("SSH 公钥已清空")
	}
	keyLines := []string(sshKeys)
	if *sshKeyFile != "" {
		lines, err := readKeyFile(*sshKeyFile)
		if err != nil {
			slog.Error(fmt.Sprintf("读公钥文件 %s: %s", *sshKeyFile, err))
			return 2
		}
		keyLines = append(keyLines, lines...)
	}
	for _, line := range keyLines {
		if err := env.store.AddSSHKey(name, line); err != nil {
			slog.Error(err.Error())
			return 2
		}
		fmt.Printf("SSH 公钥已登记: %s\n", keyFingerprint(line))
	}
	for _, k := range removeKeys {
		if err := env.store.RemoveSSHKey(name, k); err != nil {
			slog.Error(err.Error())
			return 2
		}
		fmt.Println("SSH 公钥已移除")
	}
	if *disable {
		if err := env.store.SetDisabled(name, true); err != nil {
			slog.Error(err.Error())
			return 2
		}
		fmt.Println("已停用（SSH 和 agent 都进不来）")
	}
	if *enable {
		if err := env.store.SetDisabled(name, false); err != nil {
			slog.Error(err.Error())
			return 2
		}
		fmt.Println("已启用")
	}
	if *oauthOnly || *noOAuthOnly {
		if err := env.store.SetOAuthOnly(name, *oauthOnly && !*noOAuthOnly); err != nil {
			slog.Error(err.Error())
			return 2
		}
		if *oauthOnly && !*noOAuthOnly {
			fmt.Println("已开启仅 OAuth 登录：SSH 密码/公钥都不再能建隧道，只收 OAuth 换来的短时效凭据")
		} else {
			fmt.Println("已关闭仅 OAuth 登录：恢复普通密码/公钥")
		}
	}
	if *oidcBind != "" || *oidcUnbind != "" {
		issuer := *oidcIssuer
		if issuer == "" && *configPath != "" {
			if sc, err := config.LoadServer(*configPath); err == nil && sc.OAuth != nil {
				issuer = sc.OAuth.Issuer
			}
		}
		if issuer == "" {
			slog.Error("--oidc-bind/--oidc-unbind 需要身份来源：在 server.yaml 的 oauth.issuer 里配，或用 --oidc-issuer 指定")
			return 2
		}
		if *oidcBind != "" {
			if err := env.store.BindOAuthIdentity(name, issuer, *oidcBind, *oidcEmail); err != nil {
				slog.Error(err.Error())
				return 2
			}
			fmt.Printf("已绑定外部身份 sub=%s @ %s（OAuth 校验通过即可给名下机器发 SSH 凭据）\n",
				*oidcBind, strings.TrimSuffix(issuer, "/"))
		}
		if *oidcUnbind != "" {
			if err := env.store.UnbindOAuthIdentity(issuer, *oidcUnbind); err != nil {
				slog.Error(err.Error())
				return 2
			}
			fmt.Println("已解绑外部身份")
		}
	}
	return 0
}

func userRemove(args []string) int {
	fs := flag.NewFlagSet("user remove", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	usersDB := fs.String("users-db", "", "")
	usersKey := fs.String("users-key", "", "")
	serverURL := fs.String("server-url", "", "")
	rest := parseMix(fs, args)
	name := firstArg(rest)
	if name == "" {
		usageUser()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	if err := env.store.Remove(name); err != nil {
		slog.Error(err.Error())
		return 2
	}
	fmt.Printf("已删除 %s（它的 token 立刻作废）\n", name)
	return 0
}

func userToken(args []string) int {
	fs := flag.NewFlagSet("user token", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	usersDB := fs.String("users-db", "", "")
	usersKey := fs.String("users-key", "", "")
	serverURL := fs.String("server-url", "", "")
	auditLog := fs.String("audit-log", "", "")
	admin := fs.Bool("admin", false, "")
	regen := fs.Bool("regen", false, "")
	rest := parseMix(fs, args)
	name := firstArg(rest)
	if name == "" {
		usageUser()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	env.auditPath = cliAuditPath(*auditLog, *configPath)
	machine := "-"
	if machines := env.store.Machines(name); len(machines) == 1 {
		machine = machines[0].Name
	}
	// 换 token 只允许在 agent 机器上发起（token refresh）；--admin 是应急通道。
	if *regen && !*admin {
		slog.Error("换 token 请在 agent 机器上执行 towstrap token refresh；机器离线/丢失的应急换法：加 --admin（记审计）")
		return 2
	}
	event := "MACHINE-TOKEN-ADMIN"
	if *regen {
		event = "MACHINE-TOKEN-REGEN-ADMIN"
	}
	if !ownerOrAdmin(env, name, machine, event, *admin) {
		return 2
	}
	token := ""
	if *regen {
		t, err := env.store.RegenToken(name)
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
		token = t
		fmt.Println("已换新 token，旧 token 立刻作废")
	} else {
		machines := env.store.Machines(name)
		if len(machines) == 0 {
			slog.Error("这个账号还没有机器，先用 machine add 加一台", "账号", name)
			return 2
		}
		if len(machines) != 1 {
			slog.Error("该账号有多台机器，请用 machine token 指定一台", "账号", name)
			return 2
		}
		token = machines[0].Token
	}
	fmt.Printf("agent token: %s\n", token)
	printInstallHint(env.serverURL, token)
	return 0
}

// userTOTP 绑定/解绑 TOTP 验证器（SSH 登录第二因素）。
func userTOTP(args []string) int {
	fs := flag.NewFlagSet("user totp", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	usersDB := fs.String("users-db", "", "")
	usersKey := fs.String("users-key", "", "")
	serverURL := fs.String("server-url", "", "")
	remove := fs.Bool("remove", false, "")
	rest := parseMix(fs, args)
	name := firstArg(rest)
	if name == "" {
		usageUser()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}

	if *remove {
		if err := env.store.RemoveTOTP(name); err != nil {
			slog.Error(err.Error())
			return 2
		}
		fmt.Printf("已解绑 %s 的 TOTP（退回纯密码登录）\n", name)
		return 0
	}
	if _, exists := env.store.Get(name); !exists {
		slog.Error(accounts.ErrNotFound.Error() + ": " + name)
		return 2
	}

	secret, uri := totp.Generate("towstrap", name)
	fmt.Println("在验证器（Google Authenticator / 1Password / Aegis 等）里添加：")
	// 终端里直接给二维码扫；输出被管道/重定向时不画（免得脚本里混进画板）
	if term.IsTerminal(int(os.Stdout.Fd())) {
		if qr, err := qrcode.Terminal(uri); err == nil {
			fmt.Print(qr)
		}
	}
	fmt.Printf("  %s\n", uri)
	fmt.Printf("手动录入用秘钥: %s\n", totp.SecretString(secret))
	fmt.Print("输入验证器上现在的 6 位码确认绑定: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	step, ok := totp.Verify(secret, strings.TrimSpace(line), 0, time.Now())
	if !ok {
		slog.Error("验证码不对，未绑定")
		return 2
	}
	if err := env.store.EnrollTOTP(name, secret, step); err != nil {
		slog.Error(err.Error())
		return 2
	}
	fmt.Printf("已绑定。之后 ssh %s 在密码之后还要输一个 6 位码\n", name)
	return 0
}
