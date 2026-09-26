package server

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	glssh "github.com/gliderlabs/ssh"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/allow"
	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/mcpsrv"
	"github.com/towstrap/towstrap/internal/monitor"
)

type Config struct {
	HTTPAddr    string
	SSHAddr     string
	HostKeyPath string
	// TLS 为 true 时，网页口（/health、/agent、/status）走 HTTPS/WSS。
	// Cert/Key 为空会自动生成自签证书（仅适合内网或配合 agent --insecure 用）。
	TLS      bool
	CertPath string
	KeyPath  string
	// Users 是账号表：SSH 用户名密码和 agent token 都从这里校验。
	Users *accounts.Store
	// AdminToken 是查 /status 用的管理口令；账号 token 也能查。
	AdminToken string
	// AllowIPs 是全局白名单：谁能连 SSH。单个账号还能再设自己的白名单。
	AllowIPs *allow.List
	// IdleVerify 是绑了 TOTP 的账号的空闲重验阈值：SSH 会话挂机超过这个时长后，
	// 下一次敲键要先输入一个新验证码。0 = 关闭。
	IdleVerify time.Duration
	// MaxSessions 每台机器（= 每账号）的并发 SSH 会话上限，防一个账号在被控机
	// 上 fork 出一堆 shell。0 = 不限。
	MaxSessions int
	// MaxConns 是 SSH 和 HTTP 各自的并发连接总上限（超了直接拒，fail-closed，
	// 防连接洪水耗尽 fd）。0 = 不限。
	MaxConns int
	// MaxConnsPerIP 是 SSH 端口每来源 IP 的并发连接上限。只对 SSH 生效：
	// HTTP 端口上多台 agent 常共用一个出口 IP（NAT），卡每 IP 会误伤正常机群。
	// 0 = 不限。
	MaxConnsPerIP int
	// SSHIdleTimeout / SSHMaxTimeout 传给 SSH 服务端：前者按读写活动刷新（治
	// 未认证连接挂死，但也会断开空闲的交互会话，我们的空闲重验期望长挂机，
	// 所以默认 0 关闭）；后者是连接绝对寿命。0 = 不限。
	SSHIdleTimeout time.Duration
	SSHMaxTimeout  time.Duration
	// AuditLog 是服务器侧审计日志路径（认证成败、agent 上下线、会话开关），
	// 16MB 自动轮转。空 = 不写（测试用；正式跑由 CLI 给默认路径）。
	AuditLog string
	// MinAgentVersion 非空时，hello 自报版本低于它的 agent 拒绝接入
	//（机群版本淘汰用；版本是自报的，不是安全控制）。空 = 不限。
	MinAgentVersion string
	// PublicURL 是服务器对外的 wss:// 地址，用于给新加的机器生成 agent
	// 安装命令（SSH @machine add 等自助命令用到）。空 = 提示里放占位符。
	PublicURL string
	// AgentDefaults 是 server.yaml agent_defaults: 渲染出的 agent.yaml
	// 预设片段（config.Agent.InstallDefaults 的产物），/install.sh 下发
	// 时烤进装好的配置。空 = 无预设。
	AgentDefaults string
	// Register 开 /register 自助注册端点：agent 跑 `towstrap register`
	// 建账号拿 token。同一机器指纹只许注册一个账号，每 IP 限速。
	// RegisterInvite 非空时注册要带邀请码。
	Register       bool
	RegisterInvite string
	// AllowPlainHTTP：HTTP 口明文开在非回环地址上时的显式确认——
	// /register、/totp/*、/token/refresh、/oauth/*、/agent 全在这条通道
	// 收发密码和 token，明文 + 非回环监听没这个确认就拒绝启动。
	// MCPAllowPlainHTTP 表态的是同一回事，任一个开都算数。
	AllowPlainHTTP bool

	// MCP 非 nil 时在 HTTP 口挂 Streamable HTTP 的 MCP 服务（路径 MCPPath，
	// 默认 /mcp）。MCP.Machines 在这里只当元数据用（说明、roots）；实际
	// 能看到哪些机器由 MCP 客户端凭据决定。
	MCP               *mcpsrv.Config
	MCPPath           string
	MCPAllowPlainHTTP bool

	// Monitor 是旁路监控推送目标（monitor: 配置节）：URL 空 = 关闭。
	// 开启后审计事件流会实时复制推给外部接收端，另带周期指标快照；
	// 推送失败只丢帧计数，绝不影响主流程。
	Monitor           monitor.Config
	MonitorAllowPlain bool

	// OAuth 非空时挂 /oauth/* 端点：agent 可以替机器前的用户发起 OIDC
	// 授权，通过后下发短时效 SSH 凭据（见 oauth.go）。
	OAuth *OAuthConfig
}

type Server struct {
	cfg     Config
	Hub     *Hub
	guard   *authGuard
	audit   *auditSink
	mon     *monitor.Monitor
	started time.Time

	authOK   atomic.Int64
	authFail atomic.Int64

	mcpMu      sync.Mutex
	mcpAuditAt map[string]time.Time // MCP-SESSION 审计去重窗口

	sshMu   sync.Mutex
	sshSess map[glssh.Session]*sshOutbox // 活跃交互 SSH 会话 → 出队列（待批提示广播用）

	oauth *oauthFlow // nil = 未配置 OAuth

	regRL registerRL // /register 每 IP 限速器
}

// DefaultAuditPath 服务器审计日志默认位置：root 在 /var/lib/towstrap，
// 其他用户在 ~/.towstrap（和 agent 的约定一致）。
func DefaultAuditPath() string {
	if os.Geteuid() == 0 {
		return "/var/lib/towstrap/server-audit.log"
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "towstrap-server-audit.log"
	}
	return filepath.Join(home, ".towstrap", "server-audit.log")
}

func New(cfg Config) *Server {
	mon := monitor.New(cfg.Monitor)
	s := &Server{
		cfg:     cfg,
		Hub:     NewHub(cfg.MaxSessions),
		guard:   newAuthGuard(),
		mon:     mon,
		started: time.Now(),
	}
	s.audit = &auditSink{
		w:    auditlog.Open(cfg.AuditLog, 0),
		m:    mon,
		ok:   &s.authOK,
		fail: &s.authFail,
	}
	if mon != nil {
		mon.SetSnapshot(s.metricsSnapshot)
	}
	if cfg.OAuth != nil {
		s.oauth = newOAuthFlow(s)
	}
	return s
}

// MonitorDropped 是旁路监控累计丢帧数（接收端不在/队列满时增长）。
// 未开启监控时恒为 0。
func (s *Server) MonitorDropped() int64 { return s.mon.Dropped() }

// agentIPAllowed 复核这个调用的来源是否过得了机器的 agent_allow_ips：
// 空名单放行，解析失败/不在名单都拒（fail-closed）。和 /agent 的
// CheckAgentIP 同款判定，只是不写 agent_last_ip——token 复用型的
// HTTP 端点不该为一次读取改数据库。
func agentIPAllowed(m accounts.Machine, remote net.Addr) bool {
	if len(m.AgentAllowIPs) == 0 {
		return true
	}
	list, err := allow.Parse(m.AgentAllowIPs)
	return err == nil && list.AllowsAddr(remote)
}

func (s *Server) Run() error {
	// 凭据不能走明文出公网：整个 HTTP 口都收发密码/token（/register、
	// /totp/*、/token/refresh、/oauth/*、/agent、/mcp），明文 + 非回环
	// 监听默认拒绝启动；确认只在内网/隧道里用时显式 allow_plain_http。
	// mcp.allow_plain_http 是旧开关，表态的是同一回事，任一个开都算数。
	plainOK := s.cfg.AllowPlainHTTP || (s.cfg.MCP != nil && s.cfg.MCPAllowPlainHTTP)
	if plainHTTPListenerBlocked(s.cfg.HTTPAddr, s.cfg.TLS) && !plainOK {
		return fmt.Errorf("HTTP 监听开在明文非回环地址 %q 上：/register、/totp/*、/token/refresh、/agent 都会明文传凭据；请开 tls，或确认只在内网/隧道里用并设置 allow_plain_http: true", s.cfg.HTTPAddr)
	}
	// 监控事件同理：ws:// 明文只允许回环，否则要显式确认。
	if s.mon != nil {
		if err := monitorURLAllowed(s.cfg.Monitor.URL, s.cfg.MonitorAllowPlain); err != nil {
			return err
		}
		s.mon.Start()
		defer s.mon.Close()
		slog.Info("monitor 推送已开启", "url", s.cfg.Monitor.URL,
			"interval", s.cfg.Monitor.Interval)
	}
	errCh := make(chan error, 2)
	go func() { errCh <- s.startHTTP() }()
	go func() { errCh <- s.startSSH() }()
	go s.revokeLoop()
	err := <-errCh
	slog.Error("server stopped", "err", err)
	return err
}

// revokeLoop 每 30 秒复核一遍已连接的 agent：token 被换掉、账号被删/停用的
// 就地断开，不用重启服务器也不依赖下一次 SSH 尝试。
func (s *Server) revokeLoop() {
	for range time.Tick(30 * time.Second) {
		if revoked := s.revokeStaleAgents(); len(revoked) > 0 {
			slog.Info("revoked stale agents", "count", len(revoked))
		}
	}
}
