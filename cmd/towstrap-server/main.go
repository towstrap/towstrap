package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/allow"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/mcpsrv"
	"github.com/towstrap/towstrap/internal/monitor"
	"github.com/towstrap/towstrap/internal/selfupdate"
	"github.com/towstrap/towstrap/internal/server"
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
	case "service":
		os.Exit(runServiceCmd(os.Args[2:]))
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
  towstrap-server service install|status|uninstall [--config server.yaml]  注册成常驻服务
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
  --update-check 6h            定时扫官方最新 release 推给落后 agent 自升级；
                               0/off 关闭
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
	fs.String("update-check", "", "")
	idleVerify := fs.Duration("idle-verify", 30*time.Minute, "")
	fs.Int("max-sessions", 16, "")
	fs.Int("max-conns", 4096, "")
	fs.Int("max-conns-per-ip", 64, "")
	auditLog := fs.String("audit-log", server.DefaultAuditPath(), "")
	sshIdleTimeout := fs.String("ssh-idle-timeout", "", "")
	sshMaxTimeout := fs.String("ssh-max-timeout", "", "")
	var allowIPs config.StringList
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
	cfg := config.MergeServer(file, config.VisitedFlags(fs))
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
	if _, set := config.VisitedFlags(fs)["idle-verify"]; !set && cfg.IdleVerify != "" {
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
	if _, set := config.VisitedFlags(fs)["audit-log"]; !set && cfg.AuditLog != "" {
		auditPath = cfg.AuditLog
	}
	if auditPath == "" {
		slog.Warn("审计日志路径推导不出（HOME 未设置）且未配置 audit_log——不写审计文件")
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
	if _, set := config.VisitedFlags(fs)["min-agent-version"]; !set && cfg.MinAgentVersion != "" {
		minAgent = cfg.MinAgentVersion
	}
	// update_check：定时扫官方最新 release 推给落后 agent。off/0 关，
	// 空 = MergeServer 给的默认 6h。
	updateCheck, err := parseUpdateCheck(cfg.UpdateCheck)
	if err != nil {
		slog.Error("update_check 时长不对", "value", cfg.UpdateCheck, "err", err)
		return 2
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
		"min_agent_version", minAgent, "update_check", updateCheck,
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
		UpdateCheck:       updateCheck,
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

// parseUpdateCheck：update_check 时长写法（如 6h；off/0/never 关闭）。
// 空串理论上来不到这里（MergeServer 默认 6h），兜底也按默认走。
func parseUpdateCheck(s string) (time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default":
		return 6 * time.Hour, nil
	case "0", "off", "false", "no", "never":
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q 不是时长（如 6h）也不是 0/off", s)
	}
	return d, nil
}
