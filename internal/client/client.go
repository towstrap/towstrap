package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"

	"ws2ssh/internal/proto"
	"ws2ssh/internal/version"
)

type Config struct {
	ID         string
	Server     string
	AgentToken string
	Shell      string
	// Insecure 跳过 TLS 证书校验，只用于连自签证书的服务器。
	Insecure bool
	// Quiet 关掉会话开始/结束的桌面通知和 wall 广播（审计日志不受影响）。
	Quiet bool
	// AuditLog 审计日志路径；空 = DefaultAuditPath()。
	AuditLog string
}

func DefaultID() string {
	h, err := os.Hostname()
	if err != nil {
		return "agent"
	}
	return proto.SanitizeName(h)
}

func prepare(cfg Config) (Config, error) {
	if cfg.ID == "" {
		cfg.ID = DefaultID()
	}
	if !proto.ValidName(cfg.ID) {
		return cfg, fmt.Errorf("agent 名字不合法，只能用字母、数字、点、下划线和短横线")
	}
	if cfg.Shell == "" {
		cfg.Shell = os.Getenv("SHELL")
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/bash"
	}
	return cfg, nil
}

func ConnectOnce(cfg Config) error {
	cfg, err := prepare(cfg)
	if err != nil {
		return err
	}
	p := newPresence(cfg)
	p.Startup(cfg.ID, cfg.Server, cfg.Shell, cfg.Insecure, cfg.Quiet, version.String())
	return dialOnce(cfg, p)
}

func Run(cfg Config) error {
	var err error
	cfg, err = prepare(cfg)
	if err != nil {
		return err
	}
	p := newPresence(cfg)
	p.Startup(cfg.ID, cfg.Server, cfg.Shell, cfg.Insecure, cfg.Quiet, version.String())
	slog.Info("ws2ssh agent 运行中（远程访问，本机可感知）",
		"server", cfg.Server, "shell", cfg.Shell, "insecure", cfg.Insecure,
		"audit_log", p.path, "notify", !cfg.Quiet)

	// 连不上就指数退避（带随机抖动）：服务器重启时几千台 agent 不会在
	// 同一毫秒全部冲回来把握手打爆。
	const base = 2 * time.Second
	delay := base
	for {
		start := time.Now()
		if err := dialOnce(cfg, p); err != nil {
			slog.Error("agent disconnected", "err", err)
		}
		if time.Since(start) >= time.Minute {
			delay = base // 上一条连接活得久：不是服务器的问题，重置退避
		}
		time.Sleep(delay + time.Duration(mrand.Int63n(int64(delay))))
		delay = backoff(delay)
	}
}

// backoff 每失败一轮等待时长翻倍，封顶 30 秒。
func backoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > 30*time.Second {
		return 30 * time.Second
	}
	return next
}

type agent struct {
	cfg      Config
	conn     *websocket.Conn
	writeMu  sync.Mutex
	sessMu   sync.Mutex
	sess     map[string]io.Closer
	presence *presence
}

func (a *agent) send(m proto.Msg) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_ = a.conn.SetWriteDeadline(time.Now().Add(proto.WriteWait))
	return a.conn.WriteMessage(websocket.TextMessage, m.Bytes())
}

// keepalive 定期 ping 服务器：对端死了（收不到 pong）或卡住不读（写超时）
// 都要让连接退出，重连循环才有机会把机器重新挂上去。
func (a *agent) keepalive() {
	t := time.NewTicker(proto.PingPeriod)
	defer t.Stop()
	for range t.C {
		if err := a.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(proto.WriteWait)); err != nil {
			_ = a.conn.Close()
			return
		}
	}
}

func (a *agent) setSession(id string, c io.Closer) {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	a.sess[id] = c
}

func (a *agent) takeSession(id string) io.Closer {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	c := a.sess[id]
	delete(a.sess, id)
	return c
}

func (a *agent) getSession(id string) io.Closer {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	return a.sess[id]
}

func (a *agent) closeAll() {
	a.sessMu.Lock()
	for id, c := range a.sess {
		_ = c.Close()
		delete(a.sess, id)
	}
	a.sessMu.Unlock()
}

func dialOnce(cfg Config, p *presence) error {
	u, err := url.Parse(cfg.Server)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return fmt.Errorf("server 应为 ws:// 或 wss://")
	}
	u.Path = "/agent"
	u.RawQuery = ""

	hdr := http.Header{}
	hdr.Set("X-Agent-Token", cfg.AgentToken)
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
	}
	if cfg.Insecure {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	conn, _, err := dialer.Dial(u.String(), hdr)
	if err != nil {
		return err
	}
	defer conn.Close()

	a := &agent{cfg: cfg, conn: conn, sess: make(map[string]io.Closer), presence: p}
	defer a.closeAll()

	if err := a.send(proto.Msg{T: proto.TypeHello, Name: cfg.ID, Ver: version.String()}); err != nil {
		return err
	}
	slog.Info("connected", "id", cfg.ID, "server", u.String())
	return a.loop()
}

func (a *agent) loop() error {
	// 与服务器对称的保活：单条消息上限、读超时 + pong 刷新、定期 ping。
	a.conn.SetReadLimit(proto.MaxMessageBytes)
	_ = a.conn.SetReadDeadline(time.Now().Add(proto.PongWait))
	a.conn.SetPongHandler(func(string) error {
		return a.conn.SetReadDeadline(time.Now().Add(proto.PongWait))
	})
	go a.keepalive()
	for {
		_, raw, err := a.conn.ReadMessage()
		if err != nil {
			return err
		}
		msg, err := proto.Decode(raw)
		if err != nil {
			continue
		}
		switch msg.T {
		case proto.TypeOpen:
			go a.openShell(msg)
		case proto.TypeData:
			a.onData(msg)
		case proto.TypeResize:
			a.onResize(msg)
		case proto.TypeClose:
			if c := a.takeSession(msg.ID); c != nil {
				_ = c.Close()
			}
		}
	}
}

type ptyFile struct {
	file *os.File
	cmd  *exec.Cmd
}

func (p *ptyFile) Close() error {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

func (a *agent) openShell(msg proto.Msg) {
	cmd := exec.Command(a.cfg.Shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	f, err := pty.Start(cmd)
	if err != nil {
		_ = a.send(proto.Msg{T: proto.TypeErr, ID: msg.ID, Err: err.Error()})
		return
	}
	if msg.Cols > 0 && msg.Rows > 0 {
		_ = pty.Setsize(f, &pty.Winsize{Rows: uint16(msg.Rows), Cols: uint16(msg.Cols)})
	}
	a.setSession(msg.ID, &ptyFile{file: f, cmd: cmd})
	if a.presence != nil {
		a.presence.sessionStart(msg.ID, msg.From)
		defer a.presence.sessionEnd(msg.ID)
	}
	_ = a.send(proto.Msg{T: proto.TypeOK, ID: msg.ID})

	buf := make([]byte, 32*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if werr := a.send(proto.EncodeData(msg.ID, buf[:n])); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if c := a.takeSession(msg.ID); c != nil {
		_ = c.Close()
	}
	_ = a.send(proto.Msg{T: proto.TypeClose, ID: msg.ID})
}

func (a *agent) onData(msg proto.Msg) {
	payload, err := msg.Payload()
	if err != nil || len(payload) == 0 {
		return
	}
	c := a.getSession(msg.ID)
	if p, ok := c.(*ptyFile); ok {
		_, _ = p.file.Write(payload)
	}
}

func (a *agent) onResize(msg proto.Msg) {
	c := a.getSession(msg.ID)
	p, ok := c.(*ptyFile)
	if !ok || p.file == nil || msg.Cols <= 0 || msg.Rows <= 0 {
		return
	}
	_ = pty.Setsize(p.file, &pty.Winsize{Rows: uint16(msg.Rows), Cols: uint16(msg.Cols)})
}
