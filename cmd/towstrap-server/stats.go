package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/server"
)

// stats 子命令的在线段：对应 /status 里管理口令路径给的字段。
type liveStatus struct {
	OK             bool  `json:"ok"`
	UptimeS        int64 `json:"uptime_s"`
	SessionsActive int64 `json:"sessions_active"`
	AuthOK         int64 `json:"auth_ok"`
	AuthFail       int64 `json:"auth_fail"`
	RelayToAgent   int64 `json:"relay_to_agent"`
	RelayFromAgent int64 `json:"relay_from_agent"`
	Users          []struct {
		Online bool `json:"online"`
	} `json:"users"`
}

type statsOut struct {
	Users                  int `json:"users"`
	UsersDisabled          int `json:"users_disabled"`
	Machines               int `json:"machines"`
	MachinesOfDisabledAcct int `json:"machines_of_disabled_acct"`
	MCPClients             int `json:"mcp_clients"`

	Live *liveStatus `json:"live,omitempty"`

	Since            string               `json:"since"`
	Sessions         int64                `json:"sessions"`
	SessionsDone     int64                `json:"sessions_done"`
	SessionsOpen     int64                `json:"sessions_open"`
	SessionDur       string               `json:"session_dur"`
	SessionDurMax    string               `json:"session_dur_max"`
	SessionDurAvg    string               `json:"session_dur_avg"`
	AgentConnects    int64                `json:"agent_connects"`
	AgentOnline      string               `json:"agent_online"`
	AgentsUnclosed   int64                `json:"agents_unclosed"`
	AuthOK           int64                `json:"auth_ok_events"`
	AuthFail         int64                `json:"auth_fail_events"`
	TopSessionUsers  []auditlog.NamedStat `json:"top_session_users,omitempty"`
	TopAgentMachines []auditlog.NamedStat `json:"top_agent_machines,omitempty"`
}

func runStats(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	usersDB := fs.String("users-db", "", "")
	usersKey := fs.String("users-key", "", "")
	auditLogPath := fs.String("audit-log", "", "")
	sinceFlag := fs.String("since", "all", "24h/7d/30d/all")
	asJSON := fs.Bool("json", false, "")
	_ = parseMix(fs, args)

	since, err := parseSince(*sinceFlag)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}

	var scfg config.Server
	if *configPath != "" {
		c, err := config.LoadServer(*configPath)
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
		scfg = c
	}
	db := *usersDB
	key := *usersKey
	if db == "" && scfg.UsersDB != "" {
		db = scfg.UsersDB
	}
	if key == "" && scfg.UsersKey != "" {
		key = scfg.UsersKey
	}
	if db == "" {
		db = "/etc/towstrap/users.db"
	}
	apath := *auditLogPath
	if apath == "" {
		apath = scfg.AuditLog
	}
	if apath == "" {
		apath = server.DefaultAuditPath()
	}

	out := statsOut{Since: *sinceFlag}

	store, err := accounts.Open(db, key)
	if err != nil {
		slog.Error("账号库打不开", "db", db, "err", err)
		return 1
	}
	for _, b := range store.ListBasic() {
		out.Users++
		if b.Disabled {
			out.UsersDisabled++
		}
	}
	for _, m := range store.ListMachinesBasic() {
		out.Machines++
		if m.Disabled {
			out.MachinesOfDisabledAcct++
		}
	}
	out.MCPClients = len(store.MCPList())

	st, err := auditlog.Scan(apath, since)
	if err != nil {
		slog.Error("审计日志读失败", "path", apath, "err", err)
		return 1
	}
	out.Sessions = st.Sessions
	out.SessionsDone = st.SessionsDone
	out.SessionsOpen = st.SessionsOpen()
	out.SessionDur = fmtDur(st.SessionDur)
	out.SessionDurMax = fmtDur(st.SessionDurMax)
	if st.SessionsDone > 0 {
		out.SessionDurAvg = fmtDur(st.SessionDur / time.Duration(st.SessionsDone))
	}
	out.AgentConnects = st.AgentConnects
	out.AgentOnline = fmtDur(st.AgentOnline)
	out.AgentsUnclosed = st.AgentsLive()
	out.AuthOK = st.AuthOK
	out.AuthFail = st.AuthFail
	out.TopSessionUsers = auditlog.TopN(st.SessionUsers, 5)
	out.TopAgentMachines = auditlog.TopN(st.AgentMachines, 5)

	out.Live = fetchLive(scfg)

	if *asJSON {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	printStats(&out)
	return 0
}

// parseSince：24h 这类时长直接 ParseDuration，7d/30d 这类天数按 24h 倍数，
// all 返回零值（不过滤）。
func parseSince(s string) (time.Time, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "all":
		return time.Time{}, nil
	}
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &days); err != nil || days <= 0 {
			return time.Time{}, fmt.Errorf("--since 看不懂 %q（写法：24h、7d、30d、all）", s)
		}
		return time.Now().Add(-time.Duration(days) * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf("--since 看不懂 %q（写法：24h、7d、30d、all）", s)
	}
	return time.Now().Add(-d), nil
}

// fetchLive 调本机 /status 拿实时量。配了 http+admin_token 才试；拿不到
// 就返回 nil，展示成「—」。TLS 自签是默认部署形态，本机回环查询用
// InsecureSkipVerify（数据不出本机，验签没意义反而添堵）。
func fetchLive(c config.Server) *liveStatus {
	if c.HTTP == "" || c.AdminToken == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(c.HTTP)
	if err != nil {
		return nil
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	scheme := "http"
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if c.TLS {
		scheme = "https"
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // 见上注释
	}
	cli := &http.Client{Timeout: 3 * time.Second, Transport: tr}
	req, err := http.NewRequest("GET", scheme+"://"+net.JoinHostPort(host, port)+"/status", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Admin-Token", c.AdminToken)
	resp, err := cli.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 503 {
		return nil
	}
	var ls liveStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ls); err != nil {
		return nil
	}
	return &ls
}

func printStats(o *statsOut) {
	fmt.Println("== 当前 ==")
	fmt.Printf("注册用户        %d（停用 %d）\n", o.Users, o.UsersDisabled)
	fmt.Printf("注册机器        %d（账号停用 %d）\n", o.Machines, o.MachinesOfDisabledAcct)
	fmt.Printf("MCP 客户端      %d\n", o.MCPClients)
	if o.Live != nil {
		online := 0
		for _, u := range o.Live.Users {
			if u.Online {
				online++
			}
		}
		fmt.Printf("在线机器        %d / %d\n", online, len(o.Live.Users))
		fmt.Printf("活跃会话        %d\n", o.Live.SessionsActive)
		fmt.Printf("已运行          %s\n", fmtDur(time.Duration(o.Live.UptimeS)*time.Second))
		fmt.Printf("认证成功/失败   %d / %d\n", o.Live.AuthOK, o.Live.AuthFail)
		fmt.Printf("转发流量        发 %s / 收 %s\n", fmtBytes(o.Live.RelayToAgent), fmtBytes(o.Live.RelayFromAgent))
	} else {
		fmt.Println("在线机器        —（server 没在跑，或 --config 里没配 http/admin_token）")
	}

	window := "全部"
	if o.Since != "" && o.Since != "all" {
		window = "近 " + o.Since
	}
	fmt.Printf("\n== 用量（%s，按审计日志）==\n", window)
	avg := ""
	if o.SessionDurAvg != "" {
		avg = "，平均 " + o.SessionDurAvg
	}
	open := ""
	if o.SessionsOpen > 0 {
		open = fmt.Sprintf("（%d 条未闭环）", o.SessionsOpen)
	}
	fmt.Printf("SSH+MCP 会话    %d 次，闭环总时长 %s%s，最长 %s%s\n",
		o.Sessions, o.SessionDur, avg, o.SessionDurMax, open)
	fmt.Printf("机器在线        %d 台次，闭环在线总时长 %s", o.AgentConnects, o.AgentOnline)
	if o.AgentsUnclosed > 0 {
		fmt.Printf("（%d 条未闭环）", o.AgentsUnclosed)
	}
	fmt.Println()
	fmt.Printf("认证事件        AUTH-OK %d / AUTH-FAIL %d\n", o.AuthOK, o.AuthFail)

	if len(o.TopSessionUsers) > 0 {
		fmt.Println("\n会话量 top:")
		for _, u := range o.TopSessionUsers {
			fmt.Printf("  %-20s %d 次 / %s\n", u.Name, u.Count, fmtDur(u.Dur))
		}
	}
	if len(o.TopAgentMachines) > 0 {
		fmt.Println("机器在线 top:")
		for _, m := range o.TopAgentMachines {
			fmt.Printf("  %-20s %d 台次 / %s\n", m.Name, m.Count, fmtDur(m.Dur))
		}
	}
}

// fmtDur 把时长写成人话（含天）。0 -> "0"。
func fmtDur(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	if d < time.Minute {
		return fmt.Sprintf("%d秒", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d分%d秒", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d小时%d分", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%d天%d小时", int(d.Hours())/24, int(d.Hours())%24)
}

func fmtBytes(n int64) string {
	const u = 1024
	switch {
	case n >= u*u*u:
		return fmt.Sprintf("%.1fG", float64(n)/(u*u*u))
	case n >= u*u:
		return fmt.Sprintf("%.1fM", float64(n)/(u*u))
	case n >= u:
		return fmt.Sprintf("%.1fK", float64(n)/u)
	default:
		return fmt.Sprintf("%dB", n)
	}
}
