package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/version"
)

type Config struct {
	ID         string
	Server     string
	AgentToken string
	// TokenFile 是 token 的来源文件路径（--agent-token-file 或配置
	// agent_token_file）；空 = token 不是从文件来的，服务器不能远程换发，
	// 重连也不会重读文件。
	TokenFile string
	Shell     string
	// Insecure 跳过 TLS 证书校验，只用于连自签证书的服务器。
	Insecure bool
	// Quiet 关掉会话开始/结束的桌面通知和 wall 广播（审计日志不受影响）。
	Quiet bool
	// AuditLog 审计日志路径；空 = DefaultAuditPath()。
	AuditLog string
	// MirrorIdle 镜像终端闲置多久终结（按最后一次输入/输出算）；<=0 不启用。
	MirrorIdle time.Duration
	// ProtectPaths 是 agent 要服务器帮忙挡住的文件（token 文件、agent
	// 配置文件），hello 时上报；服务器把它们加进 MCP read_file/
	// write_file 的拒名单。只写文件路径，目录不支持。
	ProtectPaths []string
	// MCPPolicy 是这台机器对 MCP 批准环节的姿态，hello 时上报：
	// "open" = 免批准（deny 保底）；空 = 跟服务端策略走。
	MCPPolicy string
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
		cfg.Shell = defaultShell()
	}
	switch cfg.MCPPolicy {
	case "", "server":
		cfg.MCPPolicy = ""
	case "open":
	default:
		return cfg, fmt.Errorf("mcp_policy 只能是 server/open，现在是 %q", cfg.MCPPolicy)
	}
	return cfg, nil
}

// warnIfRoot agent 以 root 跑意味着每个远程会话都是 root shell，提醒使用者
// 换专用低权限用户。Run 和 ConnectOnce 都查一次。
func warnIfRoot() {
	if os.Geteuid() == 0 {
		slog.Warn("agent 正以 root 运行：远程登录者将拿到 root shell。强烈建议建一个专用低权限用户运行 agent（见 README「被控端感知」节）")
	}
}

// tokenState 是 agent 当前用的 token：服务器换发成功后 onToken 就地更新，
// 每次重连前还会重读 token 文件（手动改过文件的也认）。prev 记着上一个
// token——换发是「先写本地文件、再让服务端提交」的两步，服务端那步失败
// 后本地拿新 token 永远 401，prev 兜底让下轮重连退回旧 token 自愈。
type tokenState struct {
	mu   sync.Mutex
	cur  string
	prev string
}

func (t *tokenState) get() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cur
}

func (t *tokenState) set(tok string) {
	t.mu.Lock()
	if tok != t.cur {
		t.prev = t.cur
	}
	t.cur = tok
	t.mu.Unlock()
}

// fallback 在服务端拒了当前 token 时退回上一个：有 prev 则换上并把 prev
// 清掉（只退一次，避免新旧都无效时来回抖），没有 prev 返回 false。
func (t *tokenState) fallback() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.prev == "" {
		return false
	}
	t.cur, t.prev = t.prev, ""
	return true
}

// reloadFrom 重读 token 文件：内容变了（非空且和当前不同）就换上并返回
// true；文件读不到/是空/内容没变都返回 false，当前 token 不动。
func (t *tokenState) reloadFrom(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if tok == t.cur {
		return false
	}
	t.cur = tok
	return true
}

// newMirrors 装配镜像终端登记处：闲置终结阈值和审计都跟着 cfg/presence 走。
func newMirrors(cfg Config, p *presence) *mirrorManager {
	m := newMirrorManager(cfg.Shell)
	m.idleTTL = cfg.MirrorIdle
	m.audit = p.audit
	m.startIdleSweep()
	return m
}

func ConnectOnce(cfg Config) error {
	warnIfRoot()
	cfg, err := prepare(cfg)
	if err != nil {
		return err
	}
	p := newPresence(cfg)
	p.Startup(cfg.ID, cfg.Server, cfg.Shell, cfg.Insecure, cfg.Quiet, version.String())
	st := newConnState(cfg.ID, cfg.Server)
	serveMirrorSock(newMirrors(cfg, p), p, st)
	return dialOnce(cfg, p, &tokenState{cur: cfg.AgentToken}, st)
}

func Run(cfg Config) error {
	warnIfRoot()
	var err error
	cfg, err = prepare(cfg)
	if err != nil {
		return err
	}
	p := newPresence(cfg)
	p.Startup(cfg.ID, cfg.Server, cfg.Shell, cfg.Insecure, cfg.Quiet, version.String())
	//镜像终端登记处和本机 socket 都建在连接循环外：服务器断线期间
	//镜像和本机接入照常活着。
	st := newConnState(cfg.ID, cfg.Server)
	serveMirrorSock(newMirrors(cfg, p), p, st)
	slog.Info("towstrap agent 运行中（远程访问，本机可感知）",
		"server", cfg.Server, "shell", cfg.Shell, "insecure", cfg.Insecure,
		"audit_log", p.path, "notify", !cfg.Quiet)

	tokens := &tokenState{cur: cfg.AgentToken}
	// 连不上就指数退避（带随机抖动）：服务器重启时几千台 agent 不会在
	// 同一毫秒全部冲回来把握手打爆。
	const base = 2 * time.Second
	delay := base
	for {
		// 每次重连前重读 token 文件：服务器换发会写文件，手动换过文件
		// 也在这里生效。
		if cfg.TokenFile != "" && tokens.reloadFrom(cfg.TokenFile) {
			slog.Info("token 文件已更新，改用新 token", "path", cfg.TokenFile)
		}
		start := time.Now()
		if err := dialOnce(cfg, p, tokens, st); err != nil {
			st.disconnected(err)
			if errors.Is(err, errTokenRejected) && tokens.fallback() {
				// 换发半途失败：本地文件已是新 token、服务端还认旧的。
				// 把 prev 写回文件（reloadFrom 下轮会再读），用旧 token
				// 重连自愈；prev 只退一次，服务端真换了库也不会死循环。
				if cfg.TokenFile != "" {
					if werr := writeTokenFile(cfg.TokenFile, tokens.get()); werr != nil {
						slog.Error("回退 token 写文件失败", "err", werr)
					}
				}
				slog.Warn("新 token 未被服务端接受，已回退旧 token 重试")
			}
			slog.Error("agent disconnected", "err", err)
		}
		if time.Since(start) >= time.Minute {
			delay = base // 上一条连接活得久：不是服务器的问题，重置退避
		}
		time.Sleep(delay + time.Duration(mrand.Int63n(int64(delay))))
		delay = backoff(delay)
	}
}

// errTokenRejected 标记握手被服务器以 401 拒绝——Run 循环据此触发
// prev token 回退（换发半途失败的自愈路径）。
var errTokenRejected = errors.New("token rejected")

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
	sess     map[string]*sessionEntry
	presence *presence
	tokens   *tokenState
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

type inputItem struct {
	data []byte
	eof  bool
}

const sessionInputLen = 64

type sessionEntry struct {
	proc io.Closer
	w    io.Writer
	pty  bool
	in   chan inputItem
	done chan struct{}
	once sync.Once
}

func (e *sessionEntry) Close() error {
	e.once.Do(func() {
		close(e.done)
	})
	return e.proc.Close()
}

func (a *agent) setSession(id string, e *sessionEntry) {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	a.sess[id] = e
}

func (a *agent) takeSession(id string) *sessionEntry {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	e := a.sess[id]
	delete(a.sess, id)
	return e
}

func (a *agent) getSession(id string) *sessionEntry {
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

func dialOnce(cfg Config, p *presence, tokens *tokenState, st *connState) error {
	st.dialing()
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
	// --server 里的路径当前缀：wss://host → /agent，wss://host/ts → /ts/agent。
	// 部署在反代子路径下（nginx 按路径分发）就靠这个区分端点。
	u.Path = path.Join(u.Path, "/agent")
	u.RawQuery = ""

	hdr := http.Header{}
	hdr.Set("X-Agent-Token", tokens.get())
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
	}
	if cfg.Insecure {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	conn, resp, err := dialer.Dial(u.String(), hdr)
	if err != nil {
		// 401 = 服务器明确不认这个 token（换过/作废）：包一层哨兵错误，
		// Run 循环认它做 prev 回退自愈，提示照旧能看懂。
		if errors.Is(err, websocket.ErrBadHandshake) && resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("服务器拒绝了 token（可能已被更换或作废）：%w", errTokenRejected)
		}
		return err
	}
	defer conn.Close()

	a := &agent{cfg: cfg, conn: conn, sess: make(map[string]*sessionEntry), presence: p, tokens: tokens}
	defer a.closeAll()

	// Home/Dir 随 hello 上报：服务器拿它们把 MCP 文件工具收到的 ~/
	// 和相对路径解析成绝对路径，才能和 ProtectPaths 精确对上。
	// 上报前先过 EvalSymlinks：服务器把用户输入也解成文件系统真实路径
	// 才比对——/var→/private/var、链接目录这类两边必须同一形态。
	canon := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	protect := make([]string, len(cfg.ProtectPaths))
	for i, p := range cfg.ProtectPaths {
		protect[i] = canon(p)
	}
	home, _ := os.UserHomeDir()
	home = canon(home)
	wd, _ := os.Getwd()
	wd = canon(wd)
	if err := a.send(proto.Msg{T: proto.TypeHello, Name: cfg.ID, Ver: version.String(),
		Protect: protect, Home: home, Dir: wd, MCPPol: cfg.MCPPolicy}); err != nil {
		return err
	}
	slog.Info("connected", "id", cfg.ID, "server", u.String())
	st.connected()
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
			// 同步跑到会话挂上 sess 表为止（openShell 内部起 goroutine 干
			// 长活）——否则紧随 open 的 data/eof 会先于注册被丢掉，exec
			// 会话的 stdin 数据就丢了。
			a.openShell(msg)
		case proto.TypeData:
			a.onData(msg)
		case proto.TypeEOF:
			a.onEOF(msg)
		case proto.TypeResize:
			a.onResize(msg)
		case proto.TypeClose:
			if c := a.takeSession(msg.ID); c != nil {
				_ = c.Close()
			}
		case proto.TypeToken:
			a.onToken(msg)
		}
	}
}

// onToken 处理服务器下推的新 token：原子写进 token 文件才算数——写成功
// 回 ok 并就地换当前 token（这条连接不用断）；token 不是从文件读的或
// 写失败回 err，服务器那边就不换库。
func (a *agent) onToken(msg proto.Msg) {
	if a.cfg.TokenFile == "" {
		_ = a.send(proto.Msg{T: proto.TypeErr, ID: msg.ID, Err: "token 不是从文件读的，无法远程更换"})
		return
	}
	if err := writeTokenFile(a.cfg.TokenFile, msg.D); err != nil {
		_ = a.send(proto.Msg{T: proto.TypeErr, ID: msg.ID, Err: err.Error()})
		return
	}
	if a.tokens != nil {
		a.tokens.set(msg.D)
	}
	if a.presence != nil {
		a.presence.audit.Log("TOKEN-ROTATED", "id", a.cfg.ID)
	}
	_ = a.send(proto.Msg{T: proto.TypeOK, ID: msg.ID})
}

// writeTokenFile 原子写 token 文件：同目录临时文件（0600）→ 写入 → Sync →
// Rename 覆盖，任何一步失败都不动原文件、不留临时文件。
func writeTokenFile(path, tok string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".token-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // rename 成功后是空操作
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.WriteString(tok + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// execProc 无 PTY 会话的句柄：Close 先关 stdin（让子进程读到 EOF）再杀
// 整个进程组兜底——只杀 shell 的话它正在跑的前台命令会成孤儿继续跑，
// 「超时已杀」就成假话了。服务器端 close 过来时两条都要做。
type execProc struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

func (p *execProc) Close() error {
	if p.stdin != nil {
		_ = p.stdin.Close()
	}
	killProc(p.cmd)
	return nil
}

// childEnv 给远程会话起 shell 用的环境：剥掉 TOWSTRAP_AGENT_TOKEN——远程用户
// 拿到的是本机 shell，没必要再把 agent 自己的凭据白送给他。TERM 统一换成
// xterm-256color：直接追加会和继承的旧 TERM 并存（execve 里重复的变量
// 生效的是第一个），彩色能力取决于 agent 启动环境，必须滤掉再设。
func childEnv() []string {
	env := make([]string, 0, 32)
	for _, kv := range os.Environ() {
		// TOWSTRAP_MIRROR 是镜像的套娃标记，只能由起进程的调用方显式给——
		// 继承到的不算数（agent 自己在镜像里跑时，子进程不该假装在镜像里）。
		if strings.HasPrefix(kv, "TOWSTRAP_AGENT_TOKEN=") || strings.HasPrefix(kv, "TERM=") ||
			strings.HasPrefix(kv, "TOWSTRAP_MIRROR=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "TERM=xterm-256color")
}

// openShell 在 read 循环里同步调用：它只负责把子进程起好、会话挂上 sess
// 表，然后自己起 goroutine 干长活（不能全程 goroutine——紧随 open 的
// data/eof 消息会在注册前先被读到，getSession 落空就丢数据）。
func (a *agent) openShell(msg proto.Msg) {
	if msg.Pty {
		a.openPty(msg)
		return
	}
	a.openExec(msg)
}

// openPty PTY 模式：交互终端，或客户端带命令的 PTY 会话（ssh -t host cmd）。
// 输入输出走伪终端，退出码随 close 带回。
func (a *agent) openPty(msg proto.Msg) {
	p, err := startPty(a.cfg.Shell, msg.Cmd, msg.Cwd, uint32(msg.Cols), uint32(msg.Rows))
	if err != nil {
		_ = a.send(proto.Msg{T: proto.TypeErr, ID: msg.ID, Err: err.Error()})
		return
	}
	e := &sessionEntry{proc: p, w: p, pty: true, in: make(chan inputItem, sessionInputLen), done: make(chan struct{})}
	a.setSession(msg.ID, e)
	go a.pumpInput(e)
	if a.presence != nil {
		a.presence.sessionStart(msg.ID, msg.From, "pty", msg.Cmd)
	}
	_ = a.send(proto.Msg{T: proto.TypeOK, ID: msg.ID})

	go func() {
		if a.presence != nil {
			defer a.presence.sessionEnd(msg.ID)
		}
		buf := make([]byte, 32*1024)
		for {
			n, err := p.Read(buf)
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
		// 读循环结束说明 PTY 关了，Wait 回收子进程拿退出码
		code := p.Wait()
		_ = a.send(proto.Msg{T: proto.TypeClose, ID: msg.ID, Code: code})
	}()
}

// streamWriter 把子进程的一条输出流接成 data 消息：按 32KB 切片发送
// （对上单条 WebSocket 消息上限），stream 为空是 stdout、"e" 是 stderr。
// send 失败就返回错误，子进程那边表现为写管道失败。
type streamWriter struct {
	a      *agent
	id     string
	stream string
}

func (w *streamWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > 32*1024 {
			n = 32 * 1024
		}
		if err := w.a.send(proto.EncodeStream(w.id, w.stream, p[:n])); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// openExec exec 模式：无 PTY，stdout/stderr 分成两条流转发（stderr 打 "e"
// 标），退出码随 close 带回——`ssh host '命令'` 和 `ssh -T` 走的是这条路。
func (a *agent) openExec(msg proto.Msg) {
	var cmd *exec.Cmd
	if msg.Cmd != "" {
		cmd = shellCmd(a.cfg.Shell, msg.Cmd)
	} else if msg.NoExpand && strings.Contains(filepath.Base(a.cfg.Shell), "zsh") {
		// 常驻 shell + zsh：必须在读第一条命令前就关掉两个会改写字面量
		// 或杀掉会话的展开——写 stdin 的初始化行来不及（zsh 读入阶段就
		// abort），只能用启动旗标：
		//   nomatch：echo items[0]（LLM 常写）没匹配就 abort 整个会话
		//   banghist：echo ! 会展开成上一条命令的字面量
		// bash/dash 的非交互模式本来就没有这些读入期行为，原样起。
		cmd = exec.Command(a.cfg.Shell, "+o", "nomatch", "+o", "banghist")
	} else {
		cmd = exec.Command(a.cfg.Shell)
	}
	setPgid(cmd)
	cmd.Env = childEnv()
	if msg.Cwd != "" {
		cmd.Dir = expandHome(msg.Cwd)
	}
	cmd.Stdout = &streamWriter{a: a, id: msg.ID}
	cmd.Stderr = &streamWriter{a: a, id: msg.ID, stream: "e"}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = a.send(proto.Msg{T: proto.TypeErr, ID: msg.ID, Err: err.Error()})
		return
	}
	if err := cmd.Start(); err != nil {
		_ = a.send(proto.Msg{T: proto.TypeErr, ID: msg.ID, Err: err.Error()})
		return
	}
	e := &sessionEntry{proc: &execProc{cmd: cmd, stdin: stdin}, w: stdin, in: make(chan inputItem, sessionInputLen), done: make(chan struct{})}
	a.setSession(msg.ID, e)
	go a.pumpInput(e)
	if a.presence != nil {
		a.presence.sessionStart(msg.ID, msg.From, "exec", msg.Cmd)
	}
	_ = a.send(proto.Msg{T: proto.TypeOK, ID: msg.ID})
	go func() {
		if a.presence != nil {
			defer a.presence.sessionEnd(msg.ID)
		}
		// Wait 会等 stdout/stderr 的拷贝结束，所有输出必然先于 close 发出
		werr := cmd.Wait()
		if c := a.takeSession(msg.ID); c != nil {
			_ = c.Close()
		}
		_ = a.send(proto.Msg{T: proto.TypeClose, ID: msg.ID, Code: exitCode(werr)})
	}()
}

// exitCode 把 cmd.Wait 的错误翻译成退出码：正常退出取 ExitCode；被信号杀
// 按 shell 惯例取 128+信号号；其他错误（比如根本没起来）取 255。
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if c := ee.ExitCode(); c >= 0 {
			return c
		}
		if ws, ok := ee.ProcessState.Sys().(syscall.WaitStatus); ok {
			if sig := ws.Signal(); sig > 0 {
				return 128 + int(sig)
			}
		}
	}
	return 255
}

func (a *agent) pumpInput(e *sessionEntry) {
	for {
		select {
		case it := <-e.in:
			if it.eof {
				if !e.pty {
					if c, ok := e.w.(io.Closer); ok {
						_ = c.Close()
					}
				}
				continue
			}
			for len(it.data) > 0 {
				n, err := e.w.Write(it.data)
				it.data = it.data[n:]
				if err != nil {
					return
				}
			}
		case <-e.done:
			return
		}
	}
}

func (a *agent) pushInput(id string, it inputItem) {
	e := a.getSession(id)
	if e == nil {
		return
	}
	select {
	case e.in <- it:
	case <-e.done:
	default:
		if dead := a.takeSession(id); dead != nil {
			_ = dead.Close()
			_ = a.send(proto.Msg{T: proto.TypeErr, ID: id, Err: "stdin 输入堆积超限：子进程不读取，已终止该会话"})
		}
	}
}

func (a *agent) onData(msg proto.Msg) {
	payload, err := msg.Payload()
	if err != nil || len(payload) == 0 {
		return
	}
	// 客户端 → agent 只有 stdin 一条流，msg.S 用不上
	a.pushInput(msg.ID, inputItem{data: payload})
}

// onEOF 客户端关了 stdin：无 PTY 会话把它传给子进程（cat 这类程序靠 EOF
// 收尾）；PTY 会话忽略——终端语义下 Ctrl-D 本来就是 data 里的一个字符。
func (a *agent) onEOF(msg proto.Msg) {
	a.pushInput(msg.ID, inputItem{eof: true})
}

func (a *agent) onResize(msg proto.Msg) {
	e := a.getSession(msg.ID)
	if e == nil || msg.Cols <= 0 || msg.Rows <= 0 {
		return
	}
	p, ok := e.proc.(*ptyFile)
	if !ok {
		return
	}
	_ = p.resize(uint32(msg.Cols), uint32(msg.Rows))
}

func expandHome(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}
