package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/allow"
	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/mcpsrv"
	"github.com/towstrap/towstrap/internal/monitor"
	"github.com/towstrap/towstrap/internal/qrcode"
	"github.com/towstrap/towstrap/internal/selfupdate"
	"github.com/towstrap/towstrap/internal/server"
	"github.com/towstrap/towstrap/internal/totp"
	"github.com/towstrap/towstrap/internal/version"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "server": // 容忍旧的子命令写法（towstrap-server server --config ...）
		os.Exit(runServer(os.Args[2:]))
	case "init": // 装完后的交互式初始化向导（改配置也能反复跑）
		os.Exit(runInit(os.Args[2:]))
	case "user":
		os.Exit(runUser(os.Args[2:]))
	case "machine":
		os.Exit(runMachine(os.Args[2:]))
	case "mcp":
		os.Exit(runMCP(os.Args[2:]))
	case "update":
		os.Exit(runUpdate(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println(version.String())
	default:
		// 不带子命令直接跑服务器：towstrap-server --config server.yaml
		os.Exit(runServer(os.Args[1:]))
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `towstrap-server — 服务器端 + 账号管理（被控机上装的是另一个二进制 towstrap）

用法:
  towstrap-server [--config 文件.yaml] [选项]        跑服务器
  towstrap-server init [选项]                        装完后的初始化向导（对外地址/自助注册/建号）
  towstrap-server user    add|list|set|remove|token|totp [选项] 用户名
  towstrap-server machine add|list|set|remove|token [选项] 账号 机器名
  towstrap-server mcp     add|list|set|remove|token|pending|approve|deny [选项]
  towstrap-server update [--version vX.Y.Z] [--check]     自升级：拉新版替换自身，服务在跑则重启生效
  towstrap-server version

开通一台机器（都在服务器上操作，不用网页）:
  towstrap-server user add alice --password 密码 --allow-ip 1.2.3.4   # 自定义用户名密码和白名单
  # 输出这台默认机器（alice+default）的 agent token 和安装命令：
  towstrap --server wss://服务器:443 --agent-token tsa-...

之后外人: ssh alice@服务器 -p 7822 （密码就是上面设置的）

同一账号再加一台机器:
  towstrap-server machine add alice build          # 拿到 build 的独立 token
  # 多台机器后外人要指名登录：
  ssh alice+build@服务器 -p 7822                  # 或 ssh alice+default@...

服务端:
  --config 文件.yaml
  --http :7880                 网页口（/health、/agent、/status）
  --ssh :7822                  SSH 入口
  --host-key 路径              SSH 主机密钥；默认和 users.db 同目录下的 ssh_host_key，不存在会自动生成
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
                               默认 root: /var/lib/towstrap/server-audit.log，
                               普通用户 ~/.towstrap/server-audit.log；写 /dev/null 关
  --max-sessions 16            每台机器（每账号）并发 SSH 会话上限；0 不限
  --max-conns 4096             SSH/HTTP 各自并发连接总上限；0 不限
  --max-conns-per-ip 64        SSH 每来源 IP 并发连接上限（只对 SSH；0 不限）
  --ssh-idle-timeout 0         SSH 空闲超时：治未认证连接挂死，但也会断开
                               空闲的交互会话，想留住挂机会话就别开
  --ssh-max-timeout 24h        SSH 连接绝对寿命；0 不限

账号管理（--config/--users-db 指定账号库，默认 /etc/towstrap/users.db；改完即时生效）:
  user add   用户名 [--password 密码] [--contact 联系方式] [--allow-ip 地址]...
                               [--agent-allow-ip 地址]...
                               [--ssh-key 公钥]... [--ssh-key-file 文件]
                               （不给 --password 会生成强随机密码，只显示一次；
                               自动建一台 default 机器并打印它的 token）
  user list                                                       列出账号和名下机器
  user set   用户名 [--password 密码] [--name 新名]
                              [--contact 联系方式] [--clear-contact]
                              [--allow-ip 地址]... [--clear-allow]
                              [--agent-allow-ip 地址]... [--clear-agent-allow]
                              [--ssh-key 公钥]... [--ssh-key-file 文件]
                              [--remove-ssh-key 公钥或SHA256指纹]... [--clear-ssh-keys]
                              [--disable|--enable]
  user remove 用户名                                               删号（名下机器 token 全作废）
  user token 用户名 [--regen] [--admin]                            看 token（仅当账号只有一台机器；
                                                                  多台用 machine token 指定；要本人确认；
                                                                  --regen 是应急换法，必须 --admin）
  user totp  用户名 [--remove]                                     绑定/解绑 TOTP 二因素

机器管理（一个账号可挂多台，每台独立 token；SSH 登录名 = 账号+机器名）:
  machine add    账号 机器名 [--agent-allow-ip 地址]...            加机器并打印 token
                                                                 （要账号本人确认：密码+TOTP）
  machine list   [账号]                                            列机器（不给账号列全部）
  machine set    账号 机器名 [--agent-allow-ip 地址]... [--clear-agent-allow]
  machine remove 账号 机器名                                       删机器（token 作废）
  machine token  账号 机器名 [--regen]                             看这台机器的 token（要本人确认；
                                                                  --regen 是应急换法，必须 --admin）
账号本人确认：add 和 token 会先问账号密码（绑了 TOTP 再问验证码）；
--admin 跳过确认（打警告并写审计 MACHINE-*-ADMIN）；--audit-log 指定审计文件。
换 token 的正常通道是在 agent 机器上跑 towstrap token refresh（新 token
直接写进那台机器的 token 文件，不断连接），--regen --admin 只用于机器丢了

白名单写法：IP、网段、IP:端口、主机名、*.domain、*。不写就全放行。
--allow-ip 管的是「谁能 SSH 登录」；--agent-allow-ip 管的是「被控机器从哪连出」——
不设不限，设了就硬校验。没设时 agent 换了来源 IP 只记审计（AGENT-IPCHANGE）不拦。

内嵌 MCP（server.yaml 里 mcp.enabled: true 时，/mcp 路径挂在网页口上，
和 /agent 同一端口同一套 TLS；LLM 客户端用 Bearer token 直连）:
  mcp add    名字 --machine 授权... [--allow-ip 地址]...    签发客户端 token（只显示一次）
             --machine 写法：'*' 全部机器；'alice' 或 'alice+*' alice 名下全部；
             'alice+office' 指定一台
  mcp list                                                  列出 MCP 客户端
  mcp set    名字 [--machine 授权]... [--allow-ip 地址]... [--clear-allow]
                              [--disable|--enable]
  mcp remove 名字                                           删客户端（token 作废）
  mcp token  名字 [--regen]                                 看/换 token
  mcp pending|approve <id>|deny <id> [--all] [--approvals-dir 目录]
             处理等待人工批准的命令（LLM 客户端不支持弹窗时的兜底通道）

安全提示：mcp 开在明文 HTTP 且监听非回环地址时会拒绝启动（Bearer token
不能明文传输）；确认只在内网/隧道里用才设 mcp.allow_plain_http: true。
token 是凭据：别贴进 shell 历史（命令行里用文件/环境变量传），别进日志。
`)
}

// runUpdate：手工自升级（towstrap-server update）。实现在 internal/selfupdate。
func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	tag := fs.String("version", "", "指定版本（默认 latest）")
	check := fs.Bool("check", false, "只查最新版本，不下载")
	_ = fs.Parse(args)
	if err := selfupdate.Run(selfupdate.Opts{Product: "towstrap-server", Tag: *tag, Check: *check}); err != nil {
		fmt.Fprintln(os.Stderr, "update:", err)
		return 1
	}
	return 0
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
	// 位置参数没有意义——拼错的子命令（如 updte）会落到这里，
	// 不拦就悄悄把服务器跑起来了，报错比误解安全。
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "未知参数 %q——是不是想打某个子命令？（init/user/machine/mcp/update/version）\n", fs.Args())
		return 2
	}

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

	// 内嵌 MCP：yaml 的 mcp.enabled 才开。这里组装的 machines 只是元数据
	//（说明、write_file 放行目录）；客户端能看哪些机器由它 token 对应的
	// mcp_clients.machines 决定，在 server 包里按请求解析。
	var mcpCfg *mcpsrv.Config
	mcpPath, mcpState := "", "关闭"
	if cfg.MCP != nil && cfg.MCP.Enabled {
		// local_notify 默认开（审批就该让人看见）：yaml 显式 false 才关。
		localNotify := true
		if cfg.MCP.LocalNotify != nil {
			localNotify = *cfg.MCP.LocalNotify
		}
		mc := &mcpsrv.Config{
			Machines:     cfg.MCP.Machines,
			Policy:       cfg.MCP.Policy,
			Limits:       cfg.MCP.Limits,
			ApprovalsDir: cfg.MCP.ApprovalsDir,
			LocalNotify:  localNotify,
		}
		if mc.Machines == nil {
			mc.Machines = map[string]*mcpsrv.Machine{}
		}
		if mc.ApprovalsDir == "" {
			// 待批目录默认跟着实际审计路径走（auditPath 已解好旗标/yaml/默认），
			// 不能拿 DefaultAuditPath——自定义 audit_log 时会放错地方。
			mc.ApprovalsDir = filepath.Join(filepath.Dir(expandHome(auditPath)), "approvals")
		}
		mc.ApprovalsDir = expandHome(mc.ApprovalsDir)
		mc.ApplyDefaults()
		if err := mc.Validate(); err != nil {
			slog.Error("mcp 配置不合法: " + err.Error())
			return 2
		}
		mcpCfg = mc
		mcpPath = cfg.MCP.Path
		if mcpPath == "" {
			mcpPath = "/mcp"
		}
		mcpState = mcpPath
	}

	// 旁路监控：yaml 的 monitor.url 才开。interval/buffer 留空走默认。
	monState := "关闭"
	monCfg := monitor.Config{
		URL:    cfg.Monitor.URL,
		Token:  cfg.Monitor.Token,
		Buffer: cfg.Monitor.Buffer,
	}
	if cfg.Monitor.URL != "" {
		monCfg.Interval = 5 * time.Second
		if cfg.Monitor.Interval != "" {
			monCfg.Interval, err = time.ParseDuration(cfg.Monitor.Interval)
			if err != nil {
				slog.Error("monitor.interval 格式不对（如 5s、30s）: " + cfg.Monitor.Interval)
				return 2
			}
		}
		monState = cfg.Monitor.URL
	}
	// OIDC 外部身份接入：yaml 的 oauth: 小节。issuer+client_id 必填；
	// 不配则不挂 /oauth/* 端点。
	var oauthCfg *server.OAuthConfig
	oauthState := "关闭"
	if cfg.OAuth != nil {
		if cfg.OAuth.Issuer == "" || cfg.OAuth.ClientID == "" {
			slog.Error("oauth: 需要 issuer 和 client_id")
			return 2
		}
		if cfg.OAuth.RedirectURL == "" && cfg.PublicURL == "" && !cfg.TLS {
			slog.Warn("oauth 没配 redirect_url/public_url 且未开 TLS：回调地址按请求 Host 推导，" +
				"浏览器访问的地址变了授权就失败——建议显式配置")
		}
		oauthCfg = &server.OAuthConfig{
			Issuer:       cfg.OAuth.Issuer,
			ClientID:     cfg.OAuth.ClientID,
			ClientSecret: cfg.OAuth.ClientSecret,
			RedirectURL:  cfg.OAuth.RedirectURL,
			Scopes:       cfg.OAuth.Scopes,
		}
		oauthState = cfg.OAuth.Issuer
	}
	// 启动回显生效配置（秘密只显示设没设）：排查「yaml 到底生效没」靠这行。
	adminTokenState := "未设置"
	if cfg.AdminToken != "" {
		adminTokenState = "已设置"
	}
	// agent_defaults 渲染成写进 agent.yaml 的片段：server/agent_token*
	// 身份字段进不了预设（地址由脚本生成、token 一机一份），写了就提醒。
	agentDefaults, ignored := cfg.AgentDefaults.InstallDefaults()
	if len(ignored) > 0 {
		slog.Warn("agent_defaults 忽略身份字段（地址/token 由安装脚本按机器生成）",
			"keys", strings.Join(ignored, ","))
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
		"audit_log", auditPath, "mcp", mcpState, "monitor", monState,
		"oauth", oauthState, "agent_defaults", len(agentDefaults) > 0,
		"register", cfg.Register, "register_invite", cfg.RegisterInvite != "")
	s := server.New(server.Config{
		HTTPAddr:          cfg.HTTP,
		SSHAddr:           cfg.SSH,
		HostKeyPath:       cfg.HostKey,
		TLS:               cfg.TLS,
		CertPath:          cfg.Cert,
		KeyPath:           cfg.Key,
		Users:             users,
		AdminToken:        cfg.AdminToken,
		AllowIPs:          ips,
		IdleVerify:        idle,
		AuditLog:          auditPath,
		MinAgentVersion:   minAgent,
		PublicURL:         cfg.PublicURL,
		AgentDefaults:     string(agentDefaults),
		Register:          cfg.Register,
		RegisterInvite:    cfg.RegisterInvite,
		AllowPlainHTTP:    cfg.AllowPlainHTTP,
		MaxSessions:       cfg.MaxSessions,
		MaxConns:          cfg.MaxConns,
		MaxConnsPerIP:     cfg.MaxConnsPerIP,
		SSHIdleTimeout:    sshIdle,
		SSHMaxTimeout:     sshMax,
		MCP:               mcpCfg,
		MCPPath:           mcpPath,
		MCPAllowPlainHTTP: cfg.MCP != nil && cfg.MCP.AllowPlainHTTP,
		Monitor:           monCfg,
		MonitorAllowPlain: cfg.Monitor.AllowPlain,
		OAuth:             oauthCfg,
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
	var allowIPs stringList
	fs.Var(&allowIPs, "allow-ip", "")
	var agentAllowIPs stringList
	fs.Var(&agentAllowIPs, "agent-allow-ip", "")
	var sshKeys stringList
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
	var allowIPs stringList
	fs.Var(&allowIPs, "allow-ip", "")
	clearAllow := fs.Bool("clear-allow", false, "")
	var agentAllowIPs stringList
	fs.Var(&agentAllowIPs, "agent-allow-ip", "")
	clearAgentAllow := fs.Bool("clear-agent-allow", false, "")
	var sshKeys, removeKeys stringList
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

type stringList []string

func (s *stringList) String() string { return "" }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// ---- 机器管理：一个账号下挂多台 agent ----

func usageMachine() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap-server machine add    账号 机器名 [--agent-allow-ip 地址]... [--admin] [通用选项]
                               加一台机器并打印它的 agent token（只显示一次）。
                               SSH 登录名随之变成 账号+机器名（如 alice+build）。
  towstrap-server machine list   [账号] [--show-tokens] [--admin] [通用选项]
                               列机器（不给账号列全部）。token 默认只显首尾；
                               --show-tokens 看明文：单账号要账号本人密码确认，
                               跨账号整列必须 --admin，两种情况都记审计
  towstrap-server machine set    账号 机器名 [--agent-allow-ip 地址]...
                               [--clear-agent-allow]
                               [--oauth-only | --no-oauth-only]   只收 OAuth 凭据
                               [通用选项]
  towstrap-server machine remove 账号 机器名 [通用选项]           删机器（token 作废，
                               连着的 agent 会被巡检断开）
  towstrap-server machine token  账号 机器名 [--regen] [--admin] [通用选项]
                               看这台机器的 token；--regen 是应急换法（机器
                               离线/丢失时用），必须加 --admin，记
                               MACHINE-TOKEN-REGEN-ADMIN。正常换法是在 agent
                               机器上跑 towstrap token refresh

账号本人确认：add 和 token 会先问这个账号的 SSH 密码（绑了 TOTP 再问验证码），
防「能碰服务器 DB 就能给任何账号发 token」。--admin 跳过确认：打一条警告，
并往服务器审计日志写 MACHINE-ADD-ADMIN / MACHINE-TOKEN-ADMIN。

通用选项: --config server.yaml（读 users_db/users_key/public_url）、--users-db 路径、
          --users-key 路径、--server-url 地址、--audit-log 路径（admin 审计写哪）
`)
}

func runMachine(args []string) int {
	if len(args) == 0 {
		usageMachine()
		return 2
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "add":
		return machineAdd(rest)
	case "list":
		return machineList(rest)
	case "set":
		return machineSet(rest)
	case "remove":
		return machineRemove(rest)
	case "token":
		return machineToken(rest)
	default:
		usageMachine()
		return 2
	}
}

// machineArgs 解析「账号 机器名」两个位置参数。
func machineArgs(rest []string) (user, name string, ok bool) {
	if len(rest) != 2 {
		return "", "", false
	}
	return rest[0], rest[1], true
}

func machineAdd(args []string) int {
	fs := flag.NewFlagSet("machine add", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	auditLog := fs.String("audit-log", "", "")
	admin := fs.Bool("admin", false, "")
	var agentAllowIPs stringList
	fs.Var(&agentAllowIPs, "agent-allow-ip", "")
	rest := parseMix(fs, args)
	user, name, ok := machineArgs(rest)
	if !ok {
		usageMachine()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	env.auditPath = cliAuditPath(*auditLog, *configPath)
	if !ownerOrAdmin(env, user, name, "MACHINE-ADD-ADMIN", *admin) {
		return 2
	}
	m, err := env.store.AddMachine(user, name, agentAllowIPs)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}
	fmt.Printf("已在 %s 下建好机器 %s（SSH 登录名 %s）\n", m.Username, m.Name, m.ID())
	fmt.Printf("agent token: %s\n", m.Token)
	printInstallHint(env.serverURL, m.Token)
	return 0
}

func machineList(args []string) int {
	fs := flag.NewFlagSet("machine list", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	auditLog := fs.String("audit-log", "", "")
	admin := fs.Bool("admin", false, "")
	showTokens := fs.Bool("show-tokens", false, "")
	rest := parseMix(fs, args)
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	env.auditPath = cliAuditPath(*auditLog, *configPath)
	var machines []accounts.Machine
	user := firstArg(rest)
	if user != "" {
		if _, exists := env.store.Get(user); !exists {
			slog.Error(accounts.ErrNotFound.Error() + ": " + user)
			return 2
		}
		machines = env.store.Machines(user)
	} else {
		for _, a := range env.store.List() {
			machines = append(machines, a.Machines...)
		}
	}
	if len(machines) == 0 {
		fmt.Println("没有机器；用 towstrap-server machine add 账号 机器名 加一台")
		return 0
	}
	if *showTokens {
		// 批量看明文 token 是敏感操作：单账号列 = 账号本人确认（或 --admin
		// 跳过）；跨账号整列只许 --admin（没法逐个验主人），两种都记审计。
		if user != "" {
			if !ownerOrAdmin(env, user, "*", "MACHINE-LIST-TOKENS-ADMIN", *admin) {
				return 2
			}
		} else if !*admin {
			fmt.Fprintln(os.Stderr, "跨账号列 token 只能管理员操作：加 --admin（会写一条审计）")
			return 2
		} else {
			slog.Warn("以管理员身份导出全部机器 token，已记审计")
			auditAdminAction(env.auditPath, "MACHINE-LIST-TOKENS-ADMIN", "scope", "all")
		}
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "账号\t机器\t登录名\tagent来源\tOAuth\ttoken\t创建于")
	for _, m := range machines {
		ips := strings.Join(m.AgentAllowIPs, ",")
		if ips == "" {
			ips = "-"
		}
		oauthState := "-"
		if m.OAuthOnly {
			oauthState = "仅OAuth"
		}
		tok := maskToken(m.Token)
		if *showTokens {
			tok = m.Token
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			m.Username, m.Name, m.ID(), ips, oauthState, tok, m.CreatedAt.Format("2006-01-02 15:04"))
	}
	tw.Flush()
	if !*showTokens {
		fmt.Println("（token 只显示首尾几位：单台明文用 machine token 账号 机器名；整列加 --show-tokens，单账号要本人密码、跨账号要 --admin）")
	}
	return 0
}

// maskToken 把 agent token 脱敏成「头4位…尾4位」：够认得出是哪台机器，
// 又不能让拿到清单的人冒充 agent。
func maskToken(t string) string {
	if len(t) <= 10 {
		return "***"
	}
	return t[:4] + "…" + t[len(t)-4:]
}

func machineSet(args []string) int {
	fs := flag.NewFlagSet("machine set", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	var agentAllowIPs stringList
	fs.Var(&agentAllowIPs, "agent-allow-ip", "")
	clearAgentAllow := fs.Bool("clear-agent-allow", false, "")
	oauthOnly := fs.Bool("oauth-only", false, "")
	noOAuthOnly := fs.Bool("no-oauth-only", false, "")
	rest := parseMix(fs, args)
	user, name, ok := machineArgs(rest)
	if !ok {
		usageMachine()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	if len(agentAllowIPs) == 0 && !*clearAgentAllow && !*oauthOnly && !*noOAuthOnly {
		slog.Error("没给要改的内容（--agent-allow-ip / --clear-agent-allow / --oauth-only / --no-oauth-only）")
		return 2
	}
	if len(agentAllowIPs) > 0 || *clearAgentAllow {
		ips := []string(agentAllowIPs)
		if *clearAgentAllow {
			ips = nil
		}
		if err := env.store.SetMachineAgentAllow(user, name, ips); err != nil {
			slog.Error(err.Error())
			return 2
		}
		if len(ips) == 0 {
			fmt.Println("agent 来源白名单已清空（不限来源，仅记录变更）")
		} else {
			fmt.Printf("agent 来源白名单已更新: %s\n", strings.Join(ips, ", "))
		}
	}
	if *oauthOnly || *noOAuthOnly {
		if err := env.store.SetMachineOAuthOnly(user, name, *oauthOnly && !*noOAuthOnly); err != nil {
			slog.Error(err.Error())
			return 2
		}
		if *oauthOnly && !*noOAuthOnly {
			fmt.Printf("机器 %s+%s 已开启仅 OAuth 登录：SSH 密码/公钥都不再能建隧道\n", user, name)
		} else {
			fmt.Printf("机器 %s+%s 已关闭仅 OAuth 登录\n", user, name)
		}
	}
	return 0
}

func machineRemove(args []string) int {
	fs := flag.NewFlagSet("machine remove", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	rest := parseMix(fs, args)
	user, name, ok := machineArgs(rest)
	if !ok {
		usageMachine()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	if err := env.store.RemoveMachine(user, name); err != nil {
		slog.Error(err.Error())
		return 2
	}
	fmt.Printf("已删除机器 %s+%s（它的 token 立刻作废）\n", user, name)
	return 0
}

func machineToken(args []string) int {
	fs := flag.NewFlagSet("machine token", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	auditLog := fs.String("audit-log", "", "")
	admin := fs.Bool("admin", false, "")
	regen := fs.Bool("regen", false, "")
	rest := parseMix(fs, args)
	user, name, ok := machineArgs(rest)
	if !ok {
		usageMachine()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	env.auditPath = cliAuditPath(*auditLog, *configPath)
	// 换 token 只允许在 agent 机器上发起（token refresh）；--admin 是应急通道。
	if *regen && !*admin {
		slog.Error("换 token 请在 agent 机器上执行 towstrap token refresh；机器离线/丢失的应急换法：加 --admin（记审计）")
		return 2
	}
	event := "MACHINE-TOKEN-ADMIN"
	if *regen {
		event = "MACHINE-TOKEN-REGEN-ADMIN"
	}
	if !ownerOrAdmin(env, user, name, event, *admin) {
		return 2
	}
	token := ""
	if *regen {
		t, err := env.store.RegenMachineToken(user, name)
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
		token = t
		fmt.Println("已换新 token，旧 token 立刻作废")
	} else {
		m, exists := env.store.GetMachine(user, name)
		if !exists {
			slog.Error(fmt.Sprintf("机器不存在: %s+%s", user, name))
			return 2
		}
		token = m.Token
	}
	fmt.Printf("agent token: %s\n", token)
	printInstallHint(env.serverURL, token)
	return 0
}

// ---- 内嵌 MCP 的客户端管理 + 批准兜底 ----

func usageMCP() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap-server mcp add    名字 --machine 授权... [--allow-ip 地址]... [通用选项]
                           签发一个 MCP 客户端 token（tsm-...，只显示一次）。
                           --machine 写法：'*' 全部机器；'alice' 或 'alice+*'
                           alice 名下全部；'alice+office' 指定一台。
  towstrap-server mcp list   [通用选项]                          列出客户端
  towstrap-server mcp set    名字 [--machine 授权]... [--allow-ip 地址]...
                           [--clear-allow] [--disable|--enable] [通用选项]
  towstrap-server mcp remove 名字 [通用选项]                     删除（token 作废）
  towstrap-server mcp token  名字 [--regen] [通用选项]           看/换 token
  towstrap-server mcp pending  [--approvals-dir 目录] [--config server.yaml]
  towstrap-server mcp approve <id>|--all  [--approvals-dir 目录] [--config server.yaml]
  towstrap-server mcp deny    <id>|--all  [--approvals-dir 目录] [--config server.yaml]

通用选项: --config server.yaml（读 users_db/users_key/public_url/mcp 小节）、
          --users-db 路径、--users-key 路径、--server-url 地址

批准目录的查找顺序：--approvals-dir > server.yaml 的 mcp.approvals_dir >
审计日志目录下的 approvals/。token 是凭据，别写进脚本和日志。
`)
}

func runMCP(args []string) int {
	if len(args) == 0 {
		usageMCP()
		return 2
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "add":
		return mcpAdd(rest)
	case "list":
		return mcpList(rest)
	case "set":
		return mcpSet(rest)
	case "remove":
		return mcpRemove(rest)
	case "token":
		return mcpToken(rest)
	case "pending":
		return mcpPending(rest)
	case "approve", "deny":
		return mcpSettle(verb, rest)
	default:
		usageMCP()
		return 2
	}
}

// expandHome 把开头的 ~ 换成家目录（和 mcpsrv 里的 expandTilde 同一约定）。
func expandHome(p string) string {
	if p == "~" {
		if h, err := os.UserHomeDir(); err == nil {
			return h
		}
	}
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

// mcpApprovalsDir 决定 pending/approve/deny 操作哪个目录：
// --approvals-dir > server.yaml 的 mcp.approvals_dir > 审计日志目录下的 approvals/。
func mcpApprovalsDir(flagDir, configPath string) string {
	if flagDir != "" {
		return expandHome(flagDir)
	}
	if configPath != "" {
		if s, err := config.LoadServer(configPath); err == nil {
			if s.MCP != nil && s.MCP.ApprovalsDir != "" {
				return expandHome(s.MCP.ApprovalsDir)
			}
			// 和服务端运行时同一个兜底：实际 audit_log 旁边的 approvals/
			if s.AuditLog != "" {
				return filepath.Join(filepath.Dir(expandHome(s.AuditLog)), "approvals")
			}
		}
	}
	return filepath.Join(filepath.Dir(server.DefaultAuditPath()), "approvals")
}

// mcpEndpointURL 给客户端配置示例用：public-url 优先，没配就留个占位。
func mcpEndpointURL(serverURL, configPath string) string {
	path := "/mcp"
	if configPath != "" {
		if s, err := config.LoadServer(configPath); err == nil &&
			s.MCP != nil && s.MCP.Path != "" {
			path = s.MCP.Path
		}
	}
	return mcpBaseURL(serverURL) + path
}

// mcpBaseURL 推导对外的 HTTP 基址：public_url 是 ws/wss scheme，
// 给 MCP 客户端的得是 http/https；没配就留占位。
func mcpBaseURL(serverURL string) string {
	base := serverURL
	if base == "" {
		base = "https://<服务器>:<HTTP端口>"
	}
	switch {
	case strings.HasPrefix(base, "wss://"):
		base = "https://" + base[len("wss://"):]
	case strings.HasPrefix(base, "ws://"):
		base = "http://" + base[len("ws://"):]
	}
	return strings.TrimSuffix(base, "/")
}

// skillInstallHint 给 mcp add 输出末尾用：不装 towstrap-mcp 的用户
// 也能直接从服务器的 /skill 路径把 skill 拉下来。
func skillInstallHint(base string) string {
	return fmt.Sprintf(`给编码助手装 towstrap skill（任选其一）：
  Claude Code:  mkdir -p ~/.claude/skills/towstrap && curl -fsSL %s/skill -o ~/.claude/skills/towstrap/SKILL.md
  Cursor:       mkdir -p ~/.cursor/skills/towstrap && curl -fsSL %s/skill -o ~/.cursor/skills/towstrap/SKILL.md
  Codex/Grok:   mkdir -p ~/.agents/skills/towstrap && curl -fsSL %s/skill -o ~/.agents/skills/towstrap/SKILL.md
  或下载 towstrap-mcp 后执行 towstrap-mcp connect（一次装全部）
  （服务器是自签证书的话 curl 要加 -k）`, base, base, base)
}

func mcpCommonFlags(fs *flag.FlagSet) (configPath, usersDB, usersKey, serverURL *string) {
	return fs.String("config", "", ""), fs.String("users-db", "", ""),
		fs.String("users-key", "", ""), fs.String("server-url", "", "")
}

func mcpAdd(args []string) int {
	fs := flag.NewFlagSet("mcp add", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	var machines, allowIPs stringList
	fs.Var(&machines, "machine", "")
	fs.Var(&allowIPs, "allow-ip", "")
	rest := parseMix(fs, args)
	name := firstArg(rest)
	if name == "" {
		usageMCP()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	// 机器现在不存在不挡（可以先建凭据后建账号/机器），但提醒一声。
	for _, m := range machines {
		if m == "*" {
			continue
		}
		u, mn := accounts.SplitMachineID(m)
		switch {
		case mn == "" || mn == "*":
			if _, ok := env.store.Get(u); !ok {
				slog.Warn("账号还不存在，之后建了才生效", "machine", m)
			}
		default:
			if _, ok := env.store.GetMachine(u, mn); !ok {
				slog.Warn("机器还不存在，之后建了才生效", "machine", m)
			}
		}
	}
	c, token, err := env.store.MCPAdd(name, machines, allowIPs)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}
	fmt.Printf("MCP 客户端 %q 已创建\n", c.Name)
	fmt.Printf("token: %s\n（只显示这一次；忘了就 mcp token %s --regen 换一个，旧的立刻作废）\n\n", token, c.Name)
	fmt.Printf("支持 MCP 的客户端（如 Claude Code）这样配：\n")
	fmt.Printf("  \"mcpServers\": {\"towstrap\": {\"type\": \"http\", \"url\": %q,\n"+
		"      \"headers\": {\"Authorization\": \"Bearer %s\"}}}\n\n",
		mcpEndpointURL(env.serverURL, *configPath), token)
	fmt.Println(skillInstallHint(mcpBaseURL(env.serverURL)))
	return 0
}

func mcpList(args []string) int {
	fs := flag.NewFlagSet("mcp list", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	_ = parseMix(fs, args)
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	list := env.store.MCPList()
	if len(list) == 0 {
		fmt.Println("还没有 MCP 客户端；用 towstrap-server mcp add 签发")
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "名字\t机器\t来源白名单\t状态\t创建于")
	for _, c := range list {
		state := "启用"
		if c.Disabled {
			state = "停用"
		}
		mach := strings.Join(c.Machines, ",")
		ips := strings.Join(c.AllowIPs, ",")
		if ips == "" {
			ips = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			c.Name, mach, ips, state, c.CreatedAt.Format("2006-01-02 15:04"))
	}
	tw.Flush()
	return 0
}

func mcpSet(args []string) int {
	fs := flag.NewFlagSet("mcp set", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	var machines, allowIPs stringList
	fs.Var(&machines, "machine", "")
	fs.Var(&allowIPs, "allow-ip", "")
	clearAllow := fs.Bool("clear-allow", false, "")
	disable := fs.Bool("disable", false, "")
	enable := fs.Bool("enable", false, "")
	rest := parseMix(fs, args)
	name := firstArg(rest)
	if name == "" {
		usageMCP()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	var machinesP, allowIPsP *[]string
	var disabledP *bool
	if len(machines) > 0 {
		m := []string(machines)
		machinesP = &m
	}
	if len(allowIPs) > 0 || *clearAllow {
		ips := []string(allowIPs)
		allowIPsP = &ips
	}
	if *disable {
		b := true
		disabledP = &b
	} else if *enable {
		b := false
		disabledP = &b
	}
	if machinesP == nil && allowIPsP == nil && disabledP == nil {
		slog.Error("没给要改的内容（--machine / --allow-ip / --clear-allow / --disable / --enable）")
		return 2
	}
	if err := env.store.MCPSet(name, machinesP, allowIPsP, disabledP); err != nil {
		slog.Error(err.Error())
		return 2
	}
	fmt.Printf("MCP 客户端 %q 已更新\n", name)
	return 0
}

func mcpRemove(args []string) int {
	fs := flag.NewFlagSet("mcp remove", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	rest := parseMix(fs, args)
	name := firstArg(rest)
	if name == "" {
		usageMCP()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	if err := env.store.MCPRemove(name); err != nil {
		slog.Error(err.Error())
		return 2
	}
	fmt.Printf("MCP 客户端 %q 已删除，token 作废\n", name)
	return 0
}

func mcpToken(args []string) int {
	fs := flag.NewFlagSet("mcp token", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	regen := fs.Bool("regen", false, "")
	rest := parseMix(fs, args)
	name := firstArg(rest)
	if name == "" {
		usageMCP()
		return 2
	}
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	token := ""
	if *regen {
		t, err := env.store.MCPRegenToken(name)
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
		token = t
		fmt.Println("已换新 token，旧 token 立刻作废")
	} else {
		c, exists := env.store.MCPGet(name)
		if !exists {
			slog.Error(accounts.ErrNotFound.Error() + ": " + name)
			return 2
		}
		token = c.Token
	}
	fmt.Printf("mcp token: %s\n", token)
	return 0
}

func mcpPending(args []string) int {
	fs := flag.NewFlagSet("mcp pending", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	dir := fs.String("approvals-dir", "", "")
	_ = parseMix(fs, args)
	list, err := mcpsrv.Pending(mcpApprovalsDir(*dir, *configPath))
	if err != nil {
		slog.Error("读批准目录失败", "err", err)
		return 1
	}
	if len(list) == 0 {
		fmt.Println("没有等待批准的请求")
		return 0
	}
	for _, p := range list {
		// Machine/Kind/Detail/Preview 是 LLM 给的原文——打进管理终端
		// 前过一遍清洗，不然一条带转义序列的「命令」能画假提示清屏。
		fmt.Printf("%s  %s  %-8s  %s  （等了 %s）\n",
			p.ID, auditlog.Clean(p.Machine), auditlog.Clean(p.Kind), auditlog.Clean(p.Detail),
			time.Since(p.Created).Round(time.Second))
		if p.Preview != "" {
			fmt.Printf("    ↳ %s\n", auditlog.Clean(p.Preview))
		}
	}
	fmt.Println("\n批准：towstrap-server mcp approve [--remember] <id>|--all；拒绝：towstrap-server mcp deny <id>|--all")
	return 0
}

func mcpSettle(verb string, args []string) int {
	fs := flag.NewFlagSet("mcp "+verb, flag.ExitOnError)
	configPath := fs.String("config", "", "")
	dir := fs.String("approvals-dir", "", "")
	all := fs.Bool("all", false, "")
	rem := fs.Bool("remember", false, "")
	rest := parseMix(fs, args)
	id := firstArg(rest)
	if id == "" && !*all {
		usageMCP()
		return 2
	}
	approvalsDir := mcpApprovalsDir(*dir, *configPath)
	var n int
	var err error
	if verb == "approve" {
		n, err = mcpsrv.ApprovePending(approvalsDir, id, *all, *rem)
	} else {
		n, err = mcpsrv.DenyPending(approvalsDir, id, *all)
	}
	if err != nil {
		slog.Error(err.Error())
		return 1
	}
	fmt.Printf("已处理 %d 条\n", n)
	return 0
}
