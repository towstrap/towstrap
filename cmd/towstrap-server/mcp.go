package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/mcpsrv"
	"github.com/towstrap/towstrap/internal/server"
)

// ---- 内嵌 MCP 的客户端管理 + 批准兜底 ----

func usageMCP() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap-server mcp add    名字 --machine 授权... [--allow-ip 地址]...
                           [--owner 账号] [通用选项]
                           签发一个 MCP 客户端 token（tsm-...，只显示一次）。
                           --machine 写法：'*' 全部机器；'alice' 或 'alice+*'
                           alice 名下全部；'alice+office' 指定一台。
                           --owner 账号 = 签给该账号自管（名字自动收敛成
                           「账号.名字」，本人 @mcp 能管）；不写 = 管理员名下。
  towstrap-server mcp list   [通用选项]                          列出客户端
  towstrap-server mcp set    名字 [--machine 授权]... [--allow-ip 地址]...
                           [--clear-allow] [--disable|--enable]
                           [--owner 账号|none] [通用选项]
                           --owner 账号 = 移交给该账号（名字自动改成
                           「账号.短名」，本人 @mcp 接手）；--owner none =
                           收回管理员名下
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
	if d := server.DefaultAuditPath(); d != "" {
		return filepath.Join(filepath.Dir(d), "approvals")
	}
	return ""
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
	var machines, allowIPs config.StringList
	fs.Var(&machines, "machine", "")
	fs.Var(&allowIPs, "allow-ip", "")
	owner := fs.String("owner", "", "")
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
	// --owner：签给该账号自管——名字收敛成「账号.名字」（自助面按全名
	// 寻址），账号必须真实存在。
	if *owner != "" {
		if _, ok := env.store.Get(*owner); !ok {
			slog.Error(fmt.Sprintf("账号 %q 不存在——归属必须指向真实账号", *owner))
			return 2
		}
		if !strings.HasPrefix(name, *owner+".") {
			name = *owner + "." + name
		}
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
	// 管理员签发：默认 owner 留空——这样的客户端 @mcp 自助面碰不到（自助
	// 面只管 owner = 当前账号的），只能由管理员 CLI 管理；--owner 给了
	// 账号就是直接签给本人（等价于对方跑了一遍 @mcp add）。
	c, token, err := env.store.MCPAdd(name, *owner, machines, allowIPs)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}
	fmt.Printf("MCP 客户端 %q 已创建\n", c.Name)
	if *owner != "" {
		fmt.Printf("归属 %s——本人 @mcp 可以直接管理\n", *owner)
	}
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
	fmt.Fprintln(tw, "名字\t归属\t机器\t来源白名单\t状态\t创建于")
	for _, c := range list {
		state := "启用"
		if c.Disabled {
			state = "停用"
		}
		ow := c.Owner
		if ow == "" {
			ow = "-"
		}
		mach := strings.Join(c.Machines, ",")
		ips := strings.Join(c.AllowIPs, ",")
		if ips == "" {
			ips = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name, ow, mach, ips, state, c.CreatedAt.Format("2006-01-02 15:04"))
	}
	tw.Flush()
	return 0
}

func mcpSet(args []string) int {
	fs := flag.NewFlagSet("mcp set", flag.ExitOnError)
	configPath, usersDB, usersKey, serverURL := mcpCommonFlags(fs)
	var machines, allowIPs config.StringList
	fs.Var(&machines, "machine", "")
	fs.Var(&allowIPs, "allow-ip", "")
	clearAllow := fs.Bool("clear-allow", false, "")
	disable := fs.Bool("disable", false, "")
	enable := fs.Bool("enable", false, "")
	owner := fs.String("owner", "", "")
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
	// 区分「没给 --owner」和「--owner none」——前者不动归属，后者收回
	// 管理员名下（owner 留空，@mcp 碰不到）。
	var ownerP *string
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "owner" {
			v := *owner
			if v == "none" || v == "-" {
				v = ""
			}
			ownerP = &v
		}
	})
	if ownerP != nil {
		newName, err := env.store.MCPSetOwner(name, *ownerP)
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
		if newName != name {
			fmt.Printf("已改名 %q → %q\n", name, newName)
			name = newName // 后续按新名继续改
		}
		if *ownerP == "" {
			fmt.Println("已收回管理员名下（@mcp 不再能看到）")
		} else {
			fmt.Printf("已移交给 %s——本人 @mcp 可以直接管理\n", *ownerP)
		}
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
	if machinesP == nil && allowIPsP == nil && disabledP == nil && ownerP == nil {
		slog.Error("没给要改的内容（--machine / --allow-ip / --clear-allow / --disable / --enable / --owner）")
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
	approvalsDir := mcpApprovalsDir(*dir, *configPath)
	if approvalsDir == "" {
		slog.Error("批准目录推导不出（HOME 未设置？）——用 --approvals-dir 指定")
		return 2
	}
	list, err := mcpsrv.Pending(approvalsDir)
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
	if approvalsDir == "" {
		slog.Error("批准目录推导不出（HOME 未设置？）——用 --approvals-dir 指定")
		return 2
	}
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
