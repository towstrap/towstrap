// 服务器内嵌 MCP（Streamable HTTP，/mcp）：给 LLM 客户端一个直接操纵
// 已上线 agent 的入口。和 SSH 会话一样走 Hub.pipe，不开第二条到 agent
// 的连接；认证用 ws2ssh-server mcp 子命令签发的 Bearer token。

package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ws2ssh/internal/accounts"
	"ws2ssh/internal/allow"
	"ws2ssh/internal/mcpsrv"
	"ws2ssh/internal/proto"
)

// mcpPlainHTTPAllowed 决定 /mcp 能不能挂在明文 HTTP 上：Bearer token
// 是凭据，走明文就等于把钥匙贴在网上。TLS 开着、显式
// allow_plain_http、或只监听回环地址时放行，其余拒绝启动。
func mcpPlainHTTPAllowed(listenAddr string, tls, allowPlain bool) error {
	if tls || allowPlain {
		return nil
	}
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr
	}
	if host != "" {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		if host == "localhost" {
			return nil
		}
	}
	return fmt.Errorf("mcp 开在明文 HTTP 上，Bearer token 会明文传输；" +
		"请开 tls，或确认只在内网/隧道里用并设置 mcp.allow_plain_http: true")
}

// mcpBearer 校验 /mcp 请求的 Bearer token：先过服务器全局白名单，再查
// mcp_clients 表，最后过客户端自己的 allow_ips。任何一步不过都记
// MCP-AUTH-FAIL 并回 401；日志里不写 token 本身。
func (s *Server) mcpBearer(ctx context.Context, token string, r *http.Request) (*auth.TokenInfo, error) {
	fail := func(reason string) (*auth.TokenInfo, error) {
		s.audit.Log("MCP-AUTH-FAIL", "ip", hostOnly(r.RemoteAddr), "reason", reason)
		return nil, fmt.Errorf("%w: %s", auth.ErrInvalidToken, reason)
	}
	if s.cfg.AllowIPs != nil && !s.cfg.AllowIPs.AllowsAddr(tcpAddr(r.RemoteAddr)) {
		return fail("allow-ip")
	}
	c, ok := s.cfg.Users.MCPClientByToken(token)
	if !ok {
		return fail("token")
	}
	if len(c.AllowIPs) > 0 {
		if l, err := allow.Parse(c.AllowIPs); err == nil && !l.AllowsAddr(tcpAddr(r.RemoteAddr)) {
			return fail("client-allow-ip")
		}
	}
	c.Token = "" // 明文 token 不进请求上下文，后面只需要名字和机器集合
	return &auth.TokenInfo{
		UserID: c.Name,
		Extra:  map[string]any{"client": c},
	}, nil
}

// mcpHandler 组装 /mcp 的 HTTP 入口。SDK 的 getServer 每请求都会被调
// 一次（查协议版本），真正决定生命周期的是建会话那一次；这里每请求
// 新建一份 mcpsrv.Server（机器清单跟着凭据和账号表走，永远新鲜），
// remembered 批准按会话 ID 分桶，互不串。
func (s *Server) mcpHandler() http.Handler {
	getServer := func(r *http.Request) *mcp.Server {
		ti := auth.TokenInfoFromContext(r.Context())
		if ti == nil {
			return nil
		}
		c, _ := ti.Extra["client"].(accounts.MCPClient)

		// 凭据能看的机器。machines 条目四种写法：
		//   "*"           全部账号的全部机器
		//   "alice"       alice 账号的全部机器
		//   "alice+*"     同上（显式通配）
		//   "alice+office" 指定一台
		// 账号不存在/停用、机器不存在的条目跳过。
		machines := map[string]*mcpsrv.Machine{}
		grantAll := func(username string) {
			if acc, ok := s.cfg.Users.Get(username); !ok || acc.Disabled {
				return
			}
			for _, m := range s.cfg.Users.Machines(username) {
				machines[m.ID()] = s.mcpMachineMeta(m.ID())
			}
		}
		for _, spec := range c.Machines {
			if spec == "*" {
				for _, b := range s.cfg.Users.ListMachinesBasic() {
					if !b.Disabled {
						machines[b.ID] = s.mcpMachineMeta(b.ID)
					}
				}
				break
			}
			u, mn := accounts.SplitMachineID(spec)
			if mn == "" || mn == "*" {
				grantAll(u)
				continue
			}
			if acc, ok := s.cfg.Users.Get(u); !ok || acc.Disabled {
				continue
			}
			if _, ok := s.cfg.Users.GetMachine(u, mn); ok {
				machines[spec] = s.mcpMachineMeta(spec)
			}
		}

		cfg := *s.cfg.MCP // 浅拷贝：Machines 整个换掉，Policy/Limits 照用
		cfg.Machines = machines
		cfg.ApproveCmd = "ws2ssh-server mcp approve（在服务器上执行）"
		cfg.LocalNotify = false // 服务器一般没桌面，不弹系统通知
		ip := hostOnly(r.RemoteAddr)
		cfg.Audit = func(ev string, kv ...string) {
			s.audit.Log(ev, append([]string{"client", c.Name, "ip", ip}, kv...)...)
		}

		runner := &mcpRunner{s: s, client: c.Name, ip: ip}
		srv, err := mcpsrv.New(&cfg, runner)
		if err != nil {
			slog.Error("mcp: 装配失败", "client", c.Name, "err", err)
			return nil
		}
		// 只在「没有会话 ID」的请求（即建新会话）记一行；SDK 建会话时
		// 会调两次 getServer（一次查版本、一次真建），短时间窗内去重。
		if r.Header.Get("Mcp-Session-Id") == "" {
			s.mcpSessionAudit(c.Name, ip)
		}
		return srv.MCP()
	}

	inner := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		SessionTimeout: 30 * time.Minute,
		Logger:         slog.Default(),
	})
	return auth.RequireBearerToken(s.mcpBearer, &auth.RequireBearerTokenOptions{
		AllowMissingExpiration: true, // w2m- token 本身没有过期字段
	})(inner)
}

// mcpMachineMeta 给 MCP 工具看的机器元数据：说明优先 mcp.machines 配置
// （键是完整机器 ID），退到所属账号的 contact，最后占位；roots 只来自
// mcp.machines 配置。
func (s *Server) mcpMachineMeta(id string) *mcpsrv.Machine {
	m := &mcpsrv.Machine{}
	if cm, ok := s.cfg.MCP.Machines[id]; ok && cm != nil {
		*m = *cm
	}
	if m.Description == "" {
		account, _ := accounts.SplitMachineID(id)
		if acc, ok := s.cfg.Users.Get(account); ok && acc.Contact != "" {
			m.Description = acc.Contact
		} else {
			m.Description = "（无说明）"
		}
	}
	return m
}

// mcpSessionAudit 记一行 MCP-SESSION；同一客户端短时间内的重复调用
// （SDK 建会话期间会调两次 getServer）只记一次。
func (s *Server) mcpSessionAudit(client, ip string) {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	if s.mcpAuditAt == nil {
		s.mcpAuditAt = map[string]time.Time{}
	}
	key := client + "@" + ip
	if time.Since(s.mcpAuditAt[key]) > 30*time.Second {
		s.mcpAuditAt[key] = time.Now()
		s.audit.Log("MCP-SESSION", "client", client, "ip", ip)
	}
}

// mcpRunner 是服务器内嵌模式的执行后端：直接通过 Hub 在已连接的 agent
// 上跑命令，等价于一个不需要密码的 SSH exec。
type mcpRunner struct {
	s      *Server
	client string // mcp_clients.name，审计 from 用
	ip     string
}

func (r *mcpRunner) Connected(machine string) bool { return r.s.Hub.Has(machine) }

// Run 在指定机器上跑命令。machine 是完整机器 ID（账号+机器名）；
// 名字本身必须在客户端授权列表里（cfg.Machines 已在 mcpsrv 侧检查过，
// 这里再防一手不带 + 的裸账号名打进来）。
func (r *mcpRunner) Run(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int) (mcpsrv.Result, error) {
	res := mcpsrv.Result{ExitCode: -1}
	if len(cmd) > proto.MaxCommandBytes {
		return res, fmt.Errorf("命令太长（%d 字节 > 上限 %d）", len(cmd), proto.MaxCommandBytes)
	}
	a, err := r.s.Hub.Agent(machine)
	if err != nil {
		return res, fmt.Errorf("这台机器没上线（agent 未连接）")
	}
	// 开会话前复核凭据（和 handleSSH 一样）：撤权对已经连上的 agent
	// 立刻生效，而不是只挡新连接。
	if !r.s.agentCredentialValid(machine, a) {
		return res, fmt.Errorf("这台机器的接入凭据已失效（token 已更换或账号已删/停用），等它重连")
	}

	from := "mcp:" + r.client + "@" + r.ip
	sess, err := r.s.Hub.OpenShell(a, OpenReq{Pty: false, Cmd: cmd, From: from})
	if err != nil {
		return res, err
	}
	r.s.audit.Log("SESSION-START", "user", machine, "from", from,
		"id", sess.id, "mode", "mcp", "cmd", auditCmd(cmd))
	start := time.Now()
	code := -1
	defer func() {
		r.s.audit.Log("SESSION-END", "id", sess.id, "code", fmt.Sprintf("%d", code))
	}()

	out := mcpsrv.NewCapWriter(maxOut)
	errW := mcpsrv.NewCapWriter(maxOut)
	// kill 关 = pipe 返回 = 会话被摘掉 + agent 收到 TypeClose 杀进程。
	kill := make(chan struct{})
	finished := make(chan struct{})
	var why atomic.Value // "timeout" | "ctx"
	go func() {
		var w string
		select {
		case <-ctx.Done():
			w = "ctx"
		case <-time.After(timeout):
			w = "timeout"
		case <-finished:
			return
		}
		why.Store(w)
		close(kill)
	}()

	r.s.Hub.pipe(a, sess, bytes.NewReader(stdin), out, errW, false, kill)
	res.Duration = time.Since(start)
	close(finished)

	switch why.Load() {
	case "timeout":
		res.TimedOut = true
	case "ctx":
		return res, ctx.Err()
	default:
		code = sess.exitCode()
		res.ExitCode = code
	}
	res.Stdout = out.String()
	res.Stderr = errW.String()
	res.StdoutTruncated = out.Truncated()
	res.StderrTruncated = errW.Truncated()
	if t := sess.errText(); t != "" {
		if res.Stderr != "" {
			res.Stderr += "\n"
		}
		res.Stderr += "agent: " + t
	}
	return res, nil
}
