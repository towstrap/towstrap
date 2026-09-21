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

	"ws2ssh/internal/accounts"
	"ws2ssh/internal/allow"
	"ws2ssh/internal/config"
	"ws2ssh/internal/server"
	"ws2ssh/internal/totp"
	"ws2ssh/internal/version"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "server": // 容忍旧的子命令写法（ws2ssh-server server --config ...）
		os.Exit(runServer(os.Args[2:]))
	case "user":
		os.Exit(runUser(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println(version.String())
	default:
		// 不带子命令直接跑服务器：ws2ssh-server --config server.yaml
		os.Exit(runServer(os.Args[1:]))
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ws2ssh-server — 服务器端 + 账号管理（被控机上装的是另一个二进制 ws2ssh-agent）

用法:
  ws2ssh-server [--config 文件.yaml] [选项]        跑服务器
  ws2ssh-server user  add|list|set|remove|token|totp [选项] 用户名
  ws2ssh-server version

开通一台机器（都在服务器上操作，不用网页）:
  ws2ssh-server user add alice --password 密码 --allow-ip 1.2.3.4   # 自定义用户名密码和白名单
  # 输出唯一的 agent token 和安装命令，把安装命令放到那台机器上执行
  ws2ssh-agent --server wss://服务器:443 --agent-token w2s-...

之后外人: ssh alice@服务器 -p 2222 （密码就是上面设置的）

服务端:
  --config 文件.yaml
  --http :8080                 网页口（/health、/agent、/status）
  --ssh :2222                  SSH 入口
  --host-key ssh_host_key      SSH 主机密钥，没有会自动生成
  --users-db users.db           账号 SQLite 库（user 子命令改的就是它）
  --users-key users.key         token 加密密钥；不写用 users.db 同名的 .key
  --admin-token TOKEN          查 /status 用的管理口令（可选）
  --public-url wss://域名:443  写进 user add 生成的安装命令
  --tls                        网页口走 HTTPS/WSS；配合 --cert/--key 用正式证书，
                               不给证书时自动生成自签（浏览器会告警）
  --cert cert.pem              TLS 证书文件
  --key key.pem                TLS 私钥文件
  --allow-ip 地址              可重复。全局：谁能连 SSH；账号还可以再设自己的白名单
  --idle-verify 30m            绑了 TOTP 的账号 SSH 挂机超过这个时长后，
                               下次敲键要先输一个新验证码；0 关闭
  --min-agent-version 0.2.0    agent 上报版本低于此值就拒绝接入（版本淘汰用；
                               版本是自报的，不是安全控制）
  --audit-log 路径             服务器审计日志：认证成败、agent 上下线、会话开关；
                               默认 root: /var/lib/ws2ssh/server-audit.log，
                               普通用户 ~/.ws2ssh/server-audit.log；写 /dev/null 关
  --max-sessions 16            每台机器（每账号）并发 SSH 会话上限；0 不限
  --max-conns 4096             SSH/HTTP 各自并发连接总上限；0 不限
  --max-conns-per-ip 64        SSH 每来源 IP 并发连接上限（只对 SSH；0 不限）
  --ssh-idle-timeout 0         SSH 空闲超时：治未认证连接挂死，但也会断开
                               空闲的交互会话，想留住挂机会话就别开
  --ssh-max-timeout 24h        SSH 连接绝对寿命；0 不限

账号管理（--config/--users-db 指定账号库，默认 /etc/ws2ssh/users.db；改完即时生效）:
  user add   用户名 [--password 密码] [--contact 联系方式] [--allow-ip 地址]...
                               [--agent-allow-ip 地址]...
                               （不给 --password 会生成强随机密码，只显示一次）
  user list                                                       列出账号
  user set   用户名 [--password 密码] [--name 新名]
                              [--contact 联系方式] [--clear-contact]
                              [--allow-ip 地址]... [--clear-allow]
                              [--agent-allow-ip 地址]... [--clear-agent-allow]
                              [--disable|--enable]
  user remove 用户名                                               删号（token 作废）
  user token 用户名 [--regen]                                      看/换 token
  user totp  用户名 [--remove]                                     绑定/解绑 TOTP 二因素

白名单写法：IP、网段、IP:端口、主机名、*.domain、*。不写就全放行。
--allow-ip 管的是「谁能 SSH 登录」；--agent-allow-ip 管的是「被控机器从哪连出」——
不设不限，设了就硬校验。没设时 agent 换了来源 IP 只记审计（AGENT-IPCHANGE）不拦。
`)
}

func visited(fs *flag.FlagSet) map[string]string {
	out := map[string]string{}
	fs.Visit(func(f *flag.Flag) {
		out[f.Name] = f.Value.String()
	})
	return out
}

func runServer(args []string) int {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	fs.String("http", "", "")
	fs.String("ssh", "", "")
	fs.String("host-key", "", "")
	fs.String("users-db", "", "")
	fs.String("users-key", "", "")
	fs.String("admin-token", "", "")
	fs.String("public-url", "", "")
	fs.Bool("tls", false, "")
	fs.String("cert", "", "")
	fs.String("key", "", "")
	minAgentVer := fs.String("min-agent-version", "", "")
	idleVerify := fs.Duration("idle-verify", 30*time.Minute, "")
	fs.Int("max-sessions", 16, "")
	fs.Int("max-conns", 4096, "")
	fs.Int("max-conns-per-ip", 64, "")
	auditLog := fs.String("audit-log", server.DefaultAuditPath(), "")
	sshIdleTimeout := fs.String("ssh-idle-timeout", "", "")
	sshMaxTimeout := fs.String("ssh-max-timeout", "", "")
	var allowIPs stringList
	fs.Var(&allowIPs, "allow-ip", "")
	_ = fs.Parse(args)

	var file config.Server
	if *configPath != "" {
		var err error
		file, err = config.LoadServer(*configPath)
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
	}
	cfg := config.MergeServer(file, visited(fs))
	cfg.AllowIPs = append(cfg.AllowIPs, allowIPs...)

	users, err := accounts.Open(cfg.UsersDB, cfg.UsersKey)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}
	ips, err := allow.Parse(cfg.AllowIPs)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}
	// 旗标显式给了就听旗标的；否则用 yaml 值（MergeServer 默认 30m）。
	idle := *idleVerify
	if _, set := visited(fs)["idle-verify"]; !set && cfg.IdleVerify != "" {
		d, err := time.ParseDuration(cfg.IdleVerify)
		if err != nil {
			slog.Error("idle_verify 格式不对（如 30m、1h、0 关闭）: " + cfg.IdleVerify)
			return 2
		}
		idle = d
	}
	sshIdle := time.Duration(0)
	if *sshIdleTimeout != "" {
		sshIdle, err = time.ParseDuration(*sshIdleTimeout)
	} else if cfg.SSHIdleTimeout != "" {
		sshIdle, err = time.ParseDuration(cfg.SSHIdleTimeout)
	}
	if err != nil {
		slog.Error("ssh_idle_timeout/--ssh-idle-timeout 格式不对（如 30m；0 关闭）")
		return 2
	}
	sshMax := 24 * time.Hour
	// 审计路径：显式旗标 > yaml > 默认位置
	auditPath := *auditLog
	if _, set := visited(fs)["audit-log"]; !set && cfg.AuditLog != "" {
		auditPath = cfg.AuditLog
	}
	if *sshMaxTimeout != "" {
		sshMax, err = time.ParseDuration(*sshMaxTimeout)
	} else if cfg.SSHMaxTimeout != "" {
		sshMax, err = time.ParseDuration(cfg.SSHMaxTimeout)
	}
	if err != nil {
		slog.Error("ssh_max_timeout/--ssh-max-timeout 格式不对（如 24h；0 不限）")
		return 2
	}
	// agent 版本门槛：旗标 > yaml；值形如 0.2.0
	minAgent := *minAgentVer
	if _, set := visited(fs)["min-agent-version"]; !set && cfg.MinAgentVersion != "" {
		minAgent = cfg.MinAgentVersion
	}
	// 启动回显生效配置（秘密只显示设没设）：排查「yaml 到底生效没」靠这行。
	adminTokenState := "未设置"
	if cfg.AdminToken != "" {
		adminTokenState = "已设置"
	}
	slog.Info("生效配置（旗标显式给过的项覆盖 yaml）",
		"http", cfg.HTTP, "ssh", cfg.SSH, "tls", cfg.TLS,
		"users_db", cfg.UsersDB, "admin_token", adminTokenState,
		"allow_ips", strings.Join(cfg.AllowIPs, ","),
		"idle_verify", idle.String(),
		"min_agent_version", minAgent,
		"max_sessions", cfg.MaxSessions,
		"max_conns", cfg.MaxConns, "max_conns_per_ip", cfg.MaxConnsPerIP,
		"ssh_idle_timeout", sshIdle.String(), "ssh_max_timeout", sshMax.String(),
		"audit_log", auditPath)
	s := server.New(server.Config{
		HTTPAddr:        cfg.HTTP,
		SSHAddr:         cfg.SSH,
		HostKeyPath:     cfg.HostKey,
		TLS:             cfg.TLS,
		CertPath:        cfg.Cert,
		KeyPath:         cfg.Key,
		Users:           users,
		AdminToken:      cfg.AdminToken,
		AllowIPs:        ips,
		IdleVerify:      idle,
		AuditLog:        auditPath,
		MinAgentVersion: minAgent,
		MaxSessions:     cfg.MaxSessions,
		MaxConns:        cfg.MaxConns,
		MaxConnsPerIP:   cfg.MaxConnsPerIP,
		SSHIdleTimeout:  sshIdle,
		SSHMaxTimeout:   sshMax,
	})
	if err := s.Run(); err != nil {
		slog.Error("server", "err", err)
		return 1
	}
	return 0
}

// ---- 账号管理 ----

func usageUser() {
	fmt.Fprintf(os.Stderr, `用法:
  ws2ssh-server user add  用户名 [--password 密码] [--contact 联系方式] [--allow-ip 地址]... [通用选项]
  ws2ssh-server user list [通用选项]
  ws2ssh-server user set   用户名 [--password 密码] [--name 新名] [--contact 联系方式]
                           [--clear-contact] [--allow-ip 地址]... [--clear-allow]
                           [--agent-allow-ip 地址]... [--clear-agent-allow]
                           [--disable] [--enable] [通用选项]
  ws2ssh-server user remove 用户名 [通用选项]
  ws2ssh-server user token  用户名 [--regen] [通用选项]
  ws2ssh-server user totp   用户名 [--remove] [通用选项]    绑定/解绑 TOTP 二因素验证器

通用选项: --config server.yaml（读里面的 users_db/users_key/public_url）、--users-db 路径、--users-key 路径、--server-url 地址
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
type userEnv struct {
	store     *accounts.Store
	serverURL string
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
		db = "/etc/ws2ssh/users.db"
	}
	store, err := accounts.Open(db, key)
	if err != nil {
		slog.Error(err.Error())
		return userEnv{}, false
	}
	return userEnv{store: store, serverURL: url}, true
}

func agentCmd(url, token string) string {
	if url == "" {
		url = "wss://<服务器地址>"
	}
	return fmt.Sprintf("ws2ssh-agent --server %s --agent-token %s", url, token)
}

func printInstallHint(url, token string) {
	fmt.Println("在那台机器上执行 agent 安装命令：")
	fmt.Println("  " + agentCmd(url, token))
	if url == "" {
		fmt.Println("（服务器地址没配：加 --server-url wss://域名:443 或在 server.yaml 写 public_url 可生成完整命令）")
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

func userAdd(args []string) int {
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	usersDB := fs.String("users-db", "", "")
	usersKey := fs.String("users-key", "", "")
	serverURL := fs.String("server-url", "", "")
	password := fs.String("password", "", "")
	contact := fs.String("contact", "", "负责人/联系方式备注，只做追溯")
	var allowIPs stringList
	fs.Var(&allowIPs, "allow-ip", "")
	var agentAllowIPs stringList
	fs.Var(&agentAllowIPs, "agent-allow-ip", "")
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
	fmt.Printf("已建号 %s（SSH 用户名 %s）\n", acct.Username, acct.Username)
	if generated {
		fmt.Printf("SSH 密码（只显示这一次，请立即保存）: %s\n", pw)
	}
	if len(acct.AllowIPs) > 0 {
		fmt.Printf("白名单: %s\n", strings.Join(acct.AllowIPs, ", "))
	}
	fmt.Printf("agent token: %s\n", acct.Token)
	printInstallHint(env.serverURL, acct.Token)
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
		fmt.Println("还没有账号。用 ws2ssh user add 用户名 开一个。")
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "用户名\t状态\tTOTP\t联系方式\tSSH白名单\tagent来源\ttoken")
	for _, a := range list {
		state := "启用"
		if a.Disabled {
			state = "停用"
		}
		totpState := "-"
		if a.TOTPEnabled {
			totpState = "已绑定"
		}
		ips := strings.Join(a.AllowIPs, ",")
		if ips == "" {
			ips = "-"
		}
		agentIPs := strings.Join(a.AgentAllowIPs, ",")
		if agentIPs == "" {
			agentIPs = "-"
		}
		contact := a.Contact
		if contact == "" {
			contact = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.Username, state, totpState, contact, ips, agentIPs, a.Token)
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
	var allowIPs stringList
	fs.Var(&allowIPs, "allow-ip", "")
	clearAllow := fs.Bool("clear-allow", false, "")
	var agentAllowIPs stringList
	fs.Var(&agentAllowIPs, "agent-allow-ip", "")
	clearAgentAllow := fs.Bool("clear-agent-allow", false, "")
	disable := fs.Bool("disable", false, "")
	enable := fs.Bool("enable", false, "")
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
		acct, exists := env.store.Get(name)
		if !exists {
			slog.Error(accounts.ErrNotFound.Error() + ": " + name)
			return 2
		}
		token = acct.Token
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

	secret, uri := totp.Generate("ws2ssh", name)
	fmt.Println("在验证器（Google Authenticator / 1Password / Aegis 等）里添加：")
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

type stringList []string

func (s *stringList) String() string { return "" }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
