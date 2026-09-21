package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"ws2ssh/internal/proto"
)

// chunk 是转发给 SSH 客户端的一片输出；stderr 为 true 时走 SSH 的扩展数据
// 通道（stderr），false 是主输出（PTY 会话一切输出都在这里）。
type chunk struct {
	stderr bool
	b      []byte
}

type session struct {
	id     string
	ch     chan chunk
	closed chan struct{}
	ready  chan error

	mu     sync.Mutex
	code   int    // 子进程退出码，agent 在 close 消息里带回
	errMsg string // agent 起命令失败的原因（err 消息），透传给 SSH 客户端的 stderr
}

func (s *session) setCode(c int) {
	s.mu.Lock()
	s.code = c
	s.mu.Unlock()
}

func (s *session) exitCode() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.code
}

func (s *session) setErr(msg string) {
	s.mu.Lock()
	s.errMsg = msg
	s.mu.Unlock()
}

func (s *session) errText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.errMsg
}

// agentConn 是一台已上线的机器。名字就是账号用户名（由 token 决定）。
// token 记住接入时用的那个：开会话前和巡检时都要复核它是否仍然有效，
// 这样 user token --regen / user remove / --disable 对已连接的 agent 也能
// 立刻生效（不然撤权只挡新连接，攻击者已经连上的那条一直有效）。
type agentConn struct {
	name     string
	token    string
	conn     *websocket.Conn
	writeMu  sync.Mutex
	sessMu   sync.Mutex
	sessions map[string]*session
}

func newAgent(name, token string, conn *websocket.Conn) *agentConn {
	return &agentConn{
		name:     name,
		token:    token,
		conn:     conn,
		sessions: make(map[string]*session),
	}
}

func (a *agentConn) send(m proto.Msg) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	// 写超时：对端不读时不能无限等——同一台机器的会话共用一个写锁。
	_ = a.conn.SetWriteDeadline(time.Now().Add(proto.WriteWait))
	return a.conn.WriteMessage(websocket.TextMessage, m.Bytes())
}

// keepalive 定期 ping：对端已经死了（收不到 pong，读超时会断）或卡住不读
// （写超时报错）都会结束，不让 hub 里挂着僵尸连接、会话永久挂起。
func (a *agentConn) keepalive() {
	t := time.NewTicker(proto.PingPeriod)
	defer t.Stop()
	for range t.C {
		if err := a.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(proto.WriteWait)); err != nil {
			_ = a.conn.Close()
			return
		}
	}
}

// openShell 开会话；max > 0 时限制同一台机器的并发会话数（防一个账号在被控机
// 上 fork 出一堆 shell）。
func (a *agentConn) openShell(id string, req OpenReq, max int) (*session, error) {
	s, err := a.addSession(id, max)
	if err != nil {
		return nil, err
	}
	if err := a.send(proto.Msg{T: proto.TypeOpen, ID: id, Cols: req.Cols, Rows: req.Rows, Pty: req.Pty, Cmd: req.Cmd, From: req.From}); err != nil {
		a.removeSession(id)
		return nil, err
	}
	return s, nil
}

func (a *agentConn) addSession(id string, max int) (*session, error) {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	if max > 0 && len(a.sessions) >= max {
		return nil, fmt.Errorf("这台机器的并发会话数已达上限（%d），稍后再试", max)
	}
	// code 默认 255：只有收到 agent 的 close 消息才会覆盖成真实退出码——
	// agent 掉线、命令没起来这类中断不能记 0，不然自动化会把失败当成功。
	s := &session{id: id, ch: make(chan chunk, 64), closed: make(chan struct{}), ready: make(chan error, 1), code: 255}
	a.sessions[id] = s
	return s, nil
}

func (a *agentConn) removeSession(id string) {
	a.sessMu.Lock()
	s, ok := a.sessions[id]
	if ok {
		delete(a.sessions, id)
	}
	a.sessMu.Unlock()
	if ok {
		select {
		case <-s.closed:
		default:
			close(s.closed)
		}
	}
}

func (a *agentConn) getSession(id string) *session {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	return a.sessions[id]
}

func (a *agentConn) closeAll() {
	a.sessMu.Lock()
	ids := make([]string, 0, len(a.sessions))
	for id := range a.sessions {
		ids = append(ids, id)
	}
	a.sessMu.Unlock()
	for _, id := range ids {
		a.removeSession(id)
	}
}

func (a *agentConn) signalReady(id string, err error) {
	s := a.getSession(id)
	if s == nil {
		return
	}
	select {
	case s.ready <- err:
	default:
	}
}

func waitReady(s *session, d time.Duration) error {
	select {
	case err := <-s.ready:
		return err
	case <-s.closed:
		return fmt.Errorf("会话已关闭")
	case <-time.After(d):
		return fmt.Errorf("等待 agent 接通超时")
	}
}

func (a *agentConn) readLoop() {
	defer a.closeAll()
	_ = a.conn.SetReadDeadline(time.Now().Add(proto.PongWait))
	a.conn.SetPongHandler(func(string) error {
		return a.conn.SetReadDeadline(time.Now().Add(proto.PongWait))
	})
	go a.keepalive()
	for {
		_, raw, err := a.conn.ReadMessage()
		if err != nil {
			return
		}
		msg, err := proto.Decode(raw)
		if err != nil {
			continue
		}
		s := a.getSession(msg.ID)
		if s == nil {
			continue
		}
		switch msg.T {
		case proto.TypeOK:
			a.signalReady(msg.ID, nil)
		case proto.TypeData:
			payload, err := msg.Payload()
			if err != nil || len(payload) == 0 {
				continue
			}
			select {
			case s.ch <- chunk{stderr: msg.S == "e", b: payload}:
			case <-s.closed:
			}
		case proto.TypeErr:
			s.setErr(msg.Err)
			a.signalReady(msg.ID, fmt.Errorf("%s", msg.Err))
			a.removeSession(msg.ID)
		case proto.TypeClose:
			s.setCode(msg.Code)
			a.removeSession(msg.ID)
		}
	}
}

type Hub struct {
	mu     sync.Mutex
	agents map[string]*agentConn
	seq    uint64
	// maxSessions 每台机器（= 每账号）的并发会话上限；0 = 不限。
	maxSessions int
}

func NewHub(maxSessions int) *Hub {
	return &Hub{agents: make(map[string]*agentConn), maxSessions: maxSessions}
}

// Attach 注册一台机器。同名（= 同账号）再连会顶掉旧连接。
func (h *Hub) Attach(name, token string, conn *websocket.Conn) *agentConn {
	h.mu.Lock()
	if old, ok := h.agents[name]; ok {
		_ = old.conn.Close()
		old.closeAll()
		slog.Info("agent replaced", "id", name)
	}
	a := newAgent(name, token, conn)
	h.agents[name] = a
	h.mu.Unlock()

	slog.Info("agent connected", "id", name)
	return a
}

// PruneInvalid 复核所有已连接的 agent：check 返回 false 的（token 被换掉、
// 账号被删/停用）当场断开——它们的 readLoop 会以错误退出并走 Detach。
// 返回被断开的名单。
func (h *Hub) PruneInvalid(check func(name, token string) bool) []string {
	type entry struct {
		name  string
		token string
		a     *agentConn
	}
	var all []entry
	h.mu.Lock()
	for name, a := range h.agents {
		all = append(all, entry{name: name, token: a.token, a: a})
	}
	h.mu.Unlock()

	var revoked []string
	for _, e := range all {
		if check(e.name, e.token) {
			continue
		}
		slog.Warn("agent revoked", "id", e.name)
		_ = e.a.conn.Close()
		revoked = append(revoked, e.name)
	}
	return revoked
}

func (h *Hub) Detach(conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for name, a := range h.agents {
		if a.conn == conn {
			a.closeAll()
			delete(h.agents, name)
			slog.Info("agent disconnected", "id", name)
			return
		}
	}
}

func (h *Hub) Has(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.agents[name]
	return ok
}

func (h *Hub) Names() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	names := make([]string, 0, len(h.agents))
	for name := range h.agents {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Agent 按账号用户名取在线机器。
func (h *Hub) Agent(name string) (*agentConn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a, ok := h.agents[name]
	if !ok {
		return nil, fmt.Errorf("机器 %s 未连接", name)
	}
	return a, nil
}

func (h *Hub) nextID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	return fmt.Sprintf("s%d", h.seq)
}

// OpenReq 一次开壳请求：终端尺寸、要不要 PTY（SSH 客户端申请了才 true）、
// 要执行的命令（空 = 交互 shell）、来源说明（「SSH 登录账号@来源 IP」，
// 随 open 消息下发给 agent，用于被控机上的会话告知和审计）。
type OpenReq struct {
	Cols, Rows int
	Pty        bool
	Cmd, From  string
}

// OpenShell 在已复核过的 agent 连接上开会话。
func (h *Hub) OpenShell(a *agentConn, req OpenReq) (*session, error) {
	if req.Cols <= 0 {
		req.Cols = 80
	}
	if req.Rows <= 0 {
		req.Rows = 24
	}
	return a.openShell(h.nextID(), req, h.maxSessions)
}

// pipe 双向搬运：客户端输入 → agent 子进程，agent 输出 → 客户端（stderr
// 标记的分片走 errOut）。pty 标记会话有没有伪终端；clientDone 在客户端
// 连接/会话结束时关闭（gliderlabs 的 session context）。
func (h *Hub) pipe(a *agentConn, s *session, in io.Reader, out, errOut io.Writer, pty bool, clientDone <-chan struct{}) {
	defer func() {
		_ = a.send(proto.Msg{T: proto.TypeClose, ID: s.id})
		a.removeSession(s.id)
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := in.Read(buf)
			if n > 0 {
				if werr := a.send(proto.EncodeData(s.id, buf[:n])); werr != nil {
					a.removeSession(s.id)
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					// 客户端关掉 stdin：无 PTY 时要传给子进程（cat 这类
					// 程序靠 EOF 收尾，真实 sshd 也这么干）；PTY 会话
					// 的 EOF 不等于会话结束，等 pty 那边的 shell 自己
					// 退出，真正断开由 clientDone 兜底。
					if !pty {
						_ = a.send(proto.Msg{T: proto.TypeEOF, ID: s.id})
					}
				} else {
					// 其他错误是通道断了，整场结束
					a.removeSession(s.id)
				}
				return
			}
		}
	}()

	for {
		select {
		case <-s.closed:
			// readLoop 是顺序处理消息的：close 之前到的 data 已经全部推进
			// s.ch（阻塞 select 推的）。关门前把剩在缓冲里的输出写完，
			// 不然末尾数据会丢——exec 会话 stdout 的完整性就靠这一步。
			for {
				select {
				case c := <-s.ch:
					w := out
					if c.stderr && errOut != nil {
						w = errOut
					}
					if _, err := w.Write(c.b); err != nil {
						return
					}
				default:
					return
				}
			}
		case <-clientDone:
			return
		case c, ok := <-s.ch:
			if !ok {
				return
			}
			w := out
			if c.stderr && errOut != nil {
				w = errOut
			}
			if _, err := w.Write(c.b); err != nil {
				return
			}
		}
	}
}

func (h *Hub) Resize(a *agentConn, id string, cols, rows int) {
	if a == nil {
		return
	}
	_ = a.send(proto.Msg{T: proto.TypeResize, ID: id, Cols: cols, Rows: rows})
}
