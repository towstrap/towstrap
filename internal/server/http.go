package server

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/version"
	"github.com/towstrap/towstrap/scripts"
	"github.com/towstrap/towstrap/skills"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// 网页终端已移除，agent 不是浏览器；仍保留同源检查以防将来加页面。
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	},
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	if s.cfg.MCP != nil {
		path := s.cfg.MCPPath
		if path == "" {
			path = "/mcp"
		}
		mux.Handle(path, s.mcpHandler())
	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok\n")
	})
	// /skill 公开提供随项目发布的 LLM skill 原文（公开文档，无秘密，
	// 不需要口令）：不装 towstrap-mcp 的用户也能 curl 下来手工放进
	// 编码助手的 skills 目录。
	mux.HandleFunc("/skill", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(skills.SkillMD())
	})
	// /install.sh、/install.ps1 下发一键安装脚本：地址占位符换成这台
	// 服务器自己的地址（public_url 优先，否则按请求 Host + 是否 TLS
	// 推导）——从哪台下载就默认连回哪台。公开内容，没有秘密。
	serveInstall := func(render func(string, string, string) []byte, ct string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", ct)
			w.Header().Set("Cache-Control", "no-cache") // 地址随请求推导，别缓存
			w.Write(render(s.installServerURL(r), s.cfg.AgentDefaults, s.sshPort()))
		}
	}
	mux.HandleFunc("/install.sh", serveInstall(scripts.InstallSH, "text/x-shellscript; charset=utf-8"))
	mux.HandleFunc("/install.ps1", serveInstall(scripts.InstallPS1, "text/plain; charset=utf-8"))
	// /install-server.sh 是服务端自己的一键安装——自包含脚本原样下发
	// （想自建的人从这拉，和 GitHub raw 是同一字节）。
	mux.HandleFunc("/install-server.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write(scripts.InstallServerSH())
	})
	// /register 是 agent 的自助建号口：server.yaml register: true 才受理，
	// 关了也挂路由——返回的 403 文案比连接失败更能告诉用户怎么回事。
	// /register/machine 是已有账号的登录加机口（等价 SSH @machine add），
	// 不靠 register 开关，任何时候都受理。
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/register/machine", s.handleMachineRegister)
	mux.HandleFunc("/totp/begin", s.handleTOTPBegin)
	mux.HandleFunc("/totp/confirm", s.handleTOTPConfirm)
	mux.HandleFunc("/totp/remove", s.handleTOTPRemove)
	if s.oauth != nil {
		mux.HandleFunc("/oauth/request", s.handleOAuthRequest)
		mux.HandleFunc("/oauth/begin", s.handleOAuthBegin)
		mux.HandleFunc("/oauth/callback", s.handleOAuthCallback)
		mux.HandleFunc("/oauth/result", s.handleOAuthResult)
	}
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/agent", s.handleAgent)
	mux.HandleFunc("/token/refresh", s.handleTokenRefresh)
	// / 是产品落地页（介绍 + 一键安装命令）；其余未匹配路径在 handleLanding
	// 里照旧 404。
	mux.HandleFunc("/", s.handleLanding)
	return mux
}

// installServerURL 推导给安装脚本填的 ws(s) 地址：public_url 优先；没配
// 用请求的 Host（有 TLS 就 wss，否则 ws）。本项目不建议放反代后，r.Host
// 就是用户 curl 时看到的地址。
func (s *Server) installServerURL(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return s.cfg.PublicURL
	}
	scheme := "ws"
	if r.TLS != nil {
		scheme = "wss"
	}
	host := cleanHost(r.Host)
	if host == "" {
		// Host 头不干净时不回显——宁可退回监听地址也不让客户端
		// 控制渲染出来的安装命令。
		return scheme + "://" + s.cfg.HTTPAddr
	}
	return scheme + "://" + host
}

// cleanHost 把请求方给的 Host 收成干净形态：只放行主机名/IPv6 合法的
// 字符集（字母数字 . _ - : [ ]），其他写法返回空串。r.Host 可能被客户端
// 控制（absolute-form 请求行还绕得过 Go 的 Host 校验），而它要进安装
// 脚本和落地页——$()、< > 这类字符混进去就是命令注入/插标记，白名单
// 字符集里这些一个都没有。
func cleanHost(h string) string {
	if h == "" || len(h) > 253 {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' ||
			c == ':' || c == '[' || c == ']'
		if !ok {
			return ""
		}
	}
	return h
}

// sshPort 从配置的 SSH 监听地址里取端口号，给落地页和安装脚本结尾的
// SSH 提示用。取不到时返回整个 SSHAddr（调用方原样显示，便于发现错配）。
func (s *Server) sshPort() string {
	if _, p, err := net.SplitHostPort(s.cfg.SSHAddr); err == nil {
		return p
	}
	return s.cfg.SSHAddr
}

// handleAgent 是 agent 连入的地方：token 对上哪个账号，机器就挂到那个用户名下。
// 来源 IP 也要过：账号设了 agent 来源白名单就不在名单里就拒；没设则放行，
// 但换了地方连会记 AGENT-IPCHANGE——偷走的 token 换个环境用，第一时间可见。
func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Agent-Token")
	m, ok := s.cfg.Users.MachineByToken(token)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	machineID := m.ID()
	prevIP, err := s.cfg.Users.CheckAgentIP(m.Username, m.Name, tcpAddr(r.RemoteAddr))
	if err != nil {
		ip := hostOnly(r.RemoteAddr)
		s.audit.Log("AGENT-DENY", "id", machineID, "ip", ip, "reason", "agent-allow")
		slog.Warn("agent 来源被拒", "id", machineID, "ip", ip, "err", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	// 单条消息上限：持 token 的人也不能用一条超大消息把内存打爆。
	conn.SetReadLimit(proto.MaxMessageBytes)

	hello, err := readAgentHello(conn, agentHelloWait)
	if err != nil || hello.T != proto.TypeHello {
		_ = conn.WriteMessage(websocket.TextMessage, proto.Msg{T: proto.TypeErr, Err: "need hello"}.Bytes())
		return
	}

	ip := hostOnly(r.RemoteAddr)
	// 版本门槛：agent 自报版本过低就拒（用于机群版本淘汰；版本可伪造，
	// 不是安全控制）。不上报的旧 agent 按 0.0.0 算。
	if s.cfg.MinAgentVersion != "" && version.LessThan(hello.Ver, s.cfg.MinAgentVersion) {
		s.audit.Log("AGENT-DENY", "id", machineID, "ip", ip, "reason", "old-version",
			"ver", hello.Ver, "min", s.cfg.MinAgentVersion)
		slog.Warn("agent 版本过低被拒", "id", machineID, "ip", ip, "ver", hello.Ver, "min", s.cfg.MinAgentVersion)
		_ = conn.WriteMessage(websocket.TextMessage, proto.Msg{T: proto.TypeErr, Err: "agent 版本过低，请升级"}.Bytes())
		return
	}
	if prevIP != "" && prevIP != ip {
		s.audit.Log("AGENT-IPCHANGE", "id", machineID, "old", prevIP, "new", ip)
		slog.Warn("agent 换了来源 IP（token 泄露的典型信号，确认是机器换网络再放心）",
			"id", machineID, "old", prevIP, "new", ip)
	}
	if s.Hub.Has(machineID) {
		s.audit.Log("AGENT-REPLACE", "id", machineID, "ip", ip)
	}
	a := s.Hub.Attach(machineID, token, conn, AgentHello{
		Ver: hello.Ver, Protect: hello.Protect, Home: hello.Home, Dir: hello.Dir,
		MCPPol: hello.MCPPol,
	})
	s.audit.Log("AGENT-CONNECT", "id", machineID, "ip", ip, "version", hello.Ver)
	a.readLoop()
	s.Hub.Detach(conn)
	s.audit.Log("AGENT-DISCONNECT", "id", machineID, "ip", ip)
}

const agentHelloWait = 10 * time.Second

func readAgentHello(conn *websocket.Conn, timeout time.Duration) (proto.Msg, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		return proto.Msg{}, err
	}
	return proto.Decode(raw)
}

// tcpAddr 把 "host:port" 字符串变成 net.Addr（白名单匹配用）。
func tcpAddr(s string) net.Addr {
	if host, portStr, err := net.SplitHostPort(s); err == nil {
		port, _ := strconv.Atoi(portStr)
		return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
	}
	return &net.TCPAddr{IP: net.ParseIP(s)}
}

func (s *Server) startHTTP() error {
	ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
	if err != nil {
		return err
	}
	// 连接总上限（fail-closed）。这里不加每 IP 限制：多台 agent 常共用
	// 一个出口 IP（NAT），卡每 IP 会把正常机群拒之门外。
	ln = newConnCap(ln, s.cfg.MaxConns, 0)
	srv := &http.Server{
		Handler: s.routes(),
		// 防 Slowloris：请求头读太久就断。不设 ReadTimeout/WriteTimeout——
		// /agent 是长连接 WebSocket，设了会把活着的 agent 定期掐断
		//（gorilla 升级时会清掉继承的 deadline）。
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	if s.cfg.TLS {
		cert, key, err := ensureCert(s.cfg.CertPath, s.cfg.KeyPath)
		if err != nil {
			return err
		}
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{pair},
			MinVersion:   tls.VersionTLS12,
		})
		slog.Info("https listen", "addr", s.cfg.HTTPAddr)
		return srv.Serve(ln)
	}
	slog.Info("http listen", "addr", s.cfg.HTTPAddr)
	return srv.Serve(ln)
}
