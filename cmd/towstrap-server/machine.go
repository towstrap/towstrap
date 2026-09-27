package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/proto"
)

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
  towstrap-server machine fingerprint list|release [指纹] [--admin]
                               查/解「机器指纹→账号」绑定：自助注册占位或
                               重装换账号时用。list 要 --admin；release 不加
                               --admin 时会向绑定账号本人要密码确认。

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
	case "fingerprint":
		return machineFingerprint(rest)
	default:
		usageMachine()
		return 2
	}
}

// machineFingerprint 查/释放「机器指纹→账号」绑定：自助注册一台机器
// 只许绑一个账号，遇到占位（squat）或重装换账号时管理员用这个解。
//
//	machine fingerprint list                      列出全部绑定
//	machine fingerprint release <指纹> --admin    解绑（只删 register_fps 行，
//	                                              不动账号/机器本身）
func machineFingerprint(args []string) int {
	if len(args) == 0 {
		usageMachine()
		return 2
	}
	verb, rest := args[0], args[1:]
	fs := flag.NewFlagSet("machine fingerprint "+verb, flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	auditLog := fs.String("audit-log", "", "")
	admin := fs.Bool("admin", false, "")
	rest = parseMix(fs, rest)
	env, ok := loadUserEnv(*configPath, *usersDB, *usersKey, *serverURL)
	if !ok {
		return 2
	}
	env.auditPath = cliAuditPath(*auditLog, *configPath)
	switch verb {
	case "list":
		// 绑定表是跨账号的归属信息，只能管理员整列（不借「账号本人」口子）。
		if !*admin {
			fmt.Fprintln(os.Stderr, "列指纹绑定要加 --admin（确认你是服务器管理员，会记审计）")
			return 2
		}
		auditAdminAction(env.auditPath, "FP-LIST-ADMIN", "count", "all")
		rows, err := env.store.FingerprintBindings()
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
		for _, r := range rows {
			fmt.Printf("%s  %s\n", r.Fingerprint, r.Username)
		}
		if len(rows) == 0 {
			fmt.Println("（没有指纹绑定）")
		}
		return 0
	case "release":
		fp := firstArg(rest)
		if fp == "" {
			usageMachine()
			return 2
		}
		owner, _ := env.store.FingerprintAccount(fp)
		if owner == "" {
			fmt.Println("这个指纹没有绑定记录")
			return 1
		}
		// 绑定账号本人（密码确认）或管理员都能解——别人替它解不行。
		if !ownerOrAdmin(env, owner, "", "FP-RELEASE-ADMIN", *admin) {
			return 2
		}
		released, err := env.store.ForceReleaseFingerprint(fp)
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
		if !released {
			fmt.Println("这个指纹没有绑定记录")
			return 1
		}
		auditAdminAction(env.auditPath, "FP-RELEASE", "fingerprint", fp, "owner", owner)
		fmt.Printf("已解绑 %s（原账号 %s）——那台机器可以重新注册\n", fp, owner)
		return 0
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
	var agentAllowIPs config.StringList
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
		tok := proto.MaskToken(m.Token)
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

func machineSet(args []string) int {
	fs := flag.NewFlagSet("machine set", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	var agentAllowIPs config.StringList
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
