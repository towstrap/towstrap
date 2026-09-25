package client

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/proto"
)

//镜像终端（接力终端）：PTY 主端和子进程由 agent 进程持有，名字在整台机器
// 的登记处里唯一。和 openPty 的普通会话不同——普通会话的 PTY 跟着接入方
// （SSH/MCP 会话）走，断开即杀；镜像终端的接入方断开只是「脱离」，进程
// 继续跑，之后任何人都能用同一个名字重新接入。
//
// 接入只走本机 mirror.sock（towstrap mirror 命令）：远端要用的话，SSH 上这台
// 机器（直连 sshd 或经 towstrap 都行）再跑 towstrap mirror <名字>。
//
// 生命周期边界：镜像只活在 agent 进程里——agent 重启镜像就没了（PTY 主端
// 随进程死，子进程收 SIGHUP）。登记处建在 Run/ConnectOnce 层、跨 WS 重连
// 共享，所以服务器掉线重连不影响镜像本身。
//
// 脱离键在接入端（towstrap mirror 的 Ctrl-\；socket 断开也算脱离）。

const (
	// maxMirrors 单台 agent 的镜像终端上限：没人管的常驻终端不能无限攒。
	maxMirrors = 32
	// mirrorReplayBytes 接入时重放的输出保留量：接入方靠它看到之前的画面，
	// 接入时再让前台程序重画一遍（尺寸变了走 SIGWINCH，没变也补发一个），
	// 截断处的半截转义序列很快被重画盖掉。
	mirrorReplayBytes = 256 << 10
	mirrorChunk       = 32 << 10
	// mirrorExitDrain 镜像退出后给每个接入方把积压发完的时间，超时就踢掉。
	mirrorExitDrain = 10 * time.Second
	// mirrorReapDelay 主进程退出后再等这么久把 PTY 主端关掉：让最后的输出
	// 读完；后台任务攥着从端时读端等不到 EOF，靠这一步收尾。
	mirrorReapDelay = 200 * time.Millisecond
)

// mirrorAttQueue 每个接入方的待发积压上限（分片数，单片 ≤32KB）。超了说明
// 这个接入方卡住了（手机断网、ssh 客户端被挂起……），直接踢掉——不能让
// 它拖住输出泵和别的接入方。变量是为了测试能调小。
var mirrorAttQueue = 512

var errDropped = errors.New("接入已被踢掉")

// mirrorSink 是一个接入方的输出出口：带线接入走 WebSocket data/close 帧，
// 本机接入走 socket 的 NDJSON。每个 sink 由自己的发送协程串行调用。
type mirrorSink interface {
	SendData(b []byte) error
	SendExit(code int)
	// Drop 踢掉这个接入（积压超限、发送出错、退出后发不完）：关掉它的
	// 连接让对端知道，镜像本身不受影响。可能在 SendData 阻塞时被并发调用。
	Drop(reason string)
}

// mirrorAtt 一个接入方：独立的发送队列 + 发送协程，输出泵只往队列里放、
// 从不等接入方。cols/rows/seq 记它最近报的尺寸——有人脱离后按最近
// 活跃的那个接入方恢复尺寸。
type mirrorAtt struct {
	sink       mirrorSink
	q          chan []byte
	stop       chan struct{} // 脱离/踢掉：发送协程不发了
	done       chan struct{} // 发送协程已退出
	cols, rows int
	seq        uint64
	code       int // exit 关队列前写入，发送协程收尾时报出去
}

// mirror 一个带名常驻终端。buf 是保留的输出尾部（给新接入方重放），atts 是
// 当前接入方集合。t.mu 罩住 buf/atts/尺寸/退出态——入队和接入登记都在锁内
// 做，保证接入方拿到的重放和后续实时输出不重叠不缺口；锁内不做任何可能
// 阻塞的发送。
type mirror struct {
	name string
	pty  *ptyFile
	cmd  string
	cwd  string

	m        *mirrorManager
	mu       sync.Mutex
	cols     int
	rows     int
	created  time.Time
	lastIO   time.Time
	buf      []byte
	alt      AltScreen // 程序是不是在备用屏幕里：接入时要先把新终端切过去
	atts     map[string]*mirrorAtt
	seq      uint64
	exited   bool
	exitCode int
	dead     atomic.Bool // = exited，给登记处不拿 t.mu 查
}

// mirrorInfo 是 mirror ls 对外的一条记录。
type mirrorInfo struct {
	Name     string `json:"name"`
	Cmd      string `json:"cmd,omitempty"`
	Cwd      string `json:"cwd,omitempty"`
	Cols     int    `json:"cols"`
	Rows     int    `json:"rows"`
	Attached int    `json:"attached"`         // 当前接入数
	Exited   bool   `json:"exited,omitempty"` // 进程已退出（即将消失，仅过渡态）
	Created  string `json:"created"`
	LastIO   string `json:"last_io"`
}

type mirrorManager struct {
	shell   string
	mu      sync.Mutex
	mirrors map[string]*mirror

	// idleTTL 闲置终结：lastIO（输入或输出，哪个晚算哪个）超过它就 kill；
	// <=0 表示不启用。audit 非空时闲置终结写 MIRROR-KILL via=idle。
	idleTTL time.Duration
	audit   *auditlog.Writer
}

func newMirrorManager(shell string) *mirrorManager {
	return &mirrorManager{shell: shell, mirrors: make(map[string]*mirror)}
}

// startIdleSweep 每分钟扫一轮闲置终结。登记处建在连接循环外，清扫协程
// 跟着它常驻；idleTTL<=0 不起协程。
func (m *mirrorManager) startIdleSweep() {
	if m.idleTTL <= 0 {
		return
	}
	go func() {
		tk := time.NewTicker(time.Minute)
		defer tk.Stop()
		for range tk.C {
			m.sweepIdle()
		}
	}()
}

// sweepIdle 扫一轮：闲置超过 idleTTL 的镜像终结。判断只看 lastIO——有
// 人接着但没动静同样算闲置（接入方会收到退出通知，重接即可）。
func (m *mirrorManager) sweepIdle() {
	if m.idleTTL <= 0 {
		return
	}
	m.mu.Lock()
	all := make([]*mirror, 0, len(m.mirrors))
	for _, t := range m.mirrors {
		all = append(all, t)
	}
	m.mu.Unlock()
	for _, t := range all {
		idle := t.idleFor()
		if idle <= m.idleTTL {
			continue
		}
		slog.Info("镜像闲置超时被终结", "name", t.name,
			"idle", idle.Round(time.Second), "ttl", m.idleTTL)
		if m.audit != nil {
			m.audit.Log("MIRROR-KILL", "name", t.name, "via", "idle")
		}
		m.kill(t.name)
	}
}

// idleFor 距最后一次输入/输出过了多久（write 和 broadcast 都刷新 lastIO）。
func (t *mirror) idleFor() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Since(t.lastIO)
}

// open 按名字取或建镜像：存在就返回现成的（cmd/cwd 被忽略，和 tmux -A 一致），
// 不存在用 cmd 新建（cmd 空 = 登录 shell）。cols/rows 只记个初始值，接入方
// 的尺寸在 attach 时应用。
func (m *mirrorManager) open(name, cmd, cwd string, cols, rows int) (*mirror, bool, error) {
	if !proto.ValidName(name) {
		return nil, false, fmt.Errorf("镜像名字 %q 不合法（字母、数字、点、下划线、短横线，最长 64）", name)
	}
	full := func() error {
		// 已退出还没摘掉的不占名额
		n := 0
		for _, t := range m.mirrors {
			if !t.dead.Load() {
				n++
			}
		}
		if n >= maxMirrors {
			return fmt.Errorf("镜像终端已达上限（%d 个）——用 towstrap mirror kill <名字> 清掉不用的", maxMirrors)
		}
		return nil
	}
	m.mu.Lock()
	if t := m.mirrors[name]; t != nil && !t.dead.Load() {
		m.mu.Unlock()
		return t, false, nil
	}
	if err := full(); err != nil {
		m.mu.Unlock()
		return nil, false, err
	}
	m.mu.Unlock()

	p, err := startPtyEnv(m.shell, cmd, cwd, uint32(cols), uint32(rows),
		[]string{"TOWSTRAP_MIRROR=" + name})
	if err != nil {
		return nil, false, err
	}
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	t := &mirror{name: name, pty: p, cmd: cmd, cwd: cwd, m: m,
		cols: cols, rows: rows, created: time.Now(), lastIO: time.Now(),
		atts: make(map[string]*mirrorAtt)}

	m.mu.Lock()
	// 起进程这段窗口里可能有人同名抢先建了、或别的名字把名额占满了：
	// 慢的那个弃掉（杀掉并收尸，不留僵尸进程）
	old := m.mirrors[name]
	if old != nil && !old.dead.Load() {
		m.mu.Unlock()
		_ = p.Close()
		go p.Wait()
		return old, false, nil
	}
	if err := full(); err != nil {
		m.mu.Unlock()
		_ = p.Close()
		go p.Wait()
		return nil, false, err
	}
	m.mirrors[name] = t
	m.mu.Unlock()
	go t.pump()
	return t, true, nil
}

func (m *mirrorManager) get(name string) *mirror {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mirrors[name]
}

func (m *mirrorManager) remove(name string, t *mirror) {
	m.mu.Lock()
	if m.mirrors[name] == t {
		delete(m.mirrors, name)
	}
	m.mu.Unlock()
}

// kill 终结一个镜像：杀进程、关 PTY、通知所有接入方。名字不存在返回 false。
func (m *mirrorManager) kill(name string) bool {
	t := m.get(name)
	if t == nil {
		return false
	}
	_ = t.pty.Close() // 触发 pump 读端出错 → 走 exit 收尾（通知接入方+摘登记处）
	return true
}

func (m *mirrorManager) list() []mirrorInfo {
	m.mu.Lock()
	all := make([]*mirror, 0, len(m.mirrors))
	for _, t := range m.mirrors {
		all = append(all, t)
	}
	m.mu.Unlock()
	out := make([]mirrorInfo, 0, len(all))
	for _, t := range all {
		out = append(out, t.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// attach 把 sink 登记为接入方，重放保留输出，再让前台程序重画一遍：
// cols/rows >0 且和当前尺寸不同就改尺寸（SIGWINCH 让全屏程序按新尺寸
// 重画）；尺寸没变就直接补发 SIGWINCH。重放快照和入队都在锁内：快照之后
// 的实时输出只会排在它后面，不重叠不缺口。
func (t *mirror) attach(id string, sink mirrorSink, cols, rows int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.exited {
		return errors.New("镜像已退出")
	}
	if old := t.atts[id]; old != nil {
		// 同 ID 重复接入（不该发生）：旧的先摘掉，免得发送协程泄漏
		delete(t.atts, id)
		old.halt()
	}
	t.seq++
	a := &mirrorAtt{sink: sink, seq: t.seq,
		q:    make(chan []byte, mirrorAttQueue+mirrorReplayBytes/mirrorChunk+2),
		stop: make(chan struct{}), done: make(chan struct{})}
	resized := false
	if cols > 0 && rows > 0 {
		a.cols, a.rows = cols, rows
		if cols != t.cols || rows != t.rows {
			if err := t.pty.resize(uint32(cols), uint32(rows)); err == nil {
				t.cols, t.rows = cols, rows
				resized = true
			}
		}
	}
	// 重放按 32KB 切片：wire 接入一片就是一条 WebSocket 消息，整块发会撞
	// 单条消息上限。拷一份快照——t.buf 之后会原地挪动。剥掉历史输出里的
	// 终端查询序列：回放了它们，新接入方的终端会把应答打进共享输入。
	snap := stripTermQueries(append([]byte(nil), t.buf...))
	if t.alt.On() {
		a.q <- []byte(EnterAltScreen)
	}
	for i := 0; i < len(snap); i += mirrorChunk {
		a.q <- snap[i:min(i+mirrorChunk, len(snap))]
	}
	t.atts[id] = a
	go t.sender(id, a)
	if !resized && len(snap) > 0 {
		t.pty.redraw()
	}
	return nil
}

// sender 一个接入方的发送协程：按序把队列里的输出发出去；队列被 exit
// 关掉 = 输出发完了，报退出码收尾；发送出错就把自己踢掉。
func (t *mirror) sender(id string, a *mirrorAtt) {
	defer close(a.done)
	for {
		select {
		case <-a.stop:
			return
		case b, ok := <-a.q:
			if !ok {
				a.sink.SendExit(a.code)
				return
			}
			if err := a.sink.SendData(b); err != nil {
				t.drop(id, a, "发送失败")
				return
			}
		}
	}
}

func (a *mirrorAtt) halt() {
	select {
	case <-a.stop:
	default:
		close(a.stop)
	}
}

// drop 踢掉一个接入方（发送出错/积压超限/退出后发不完）。调用方不能持 t.mu。
func (t *mirror) drop(id string, a *mirrorAtt, reason string) {
	t.mu.Lock()
	if t.atts[id] == a {
		delete(t.atts, id)
		t.restoreSizeLocked()
	}
	a.halt()
	t.mu.Unlock()
	go a.sink.Drop(reason)
}

// detach 摘掉一个接入方；镜像本身继续跑。尺寸退回到还在的、最近活跃
// 的接入方那里（手机小屏接入后脱离，桌面那边不会一直憋在小尺寸）。
func (t *mirror) detach(id string) {
	t.mu.Lock()
	if a := t.atts[id]; a != nil {
		delete(t.atts, id)
		a.halt()
		t.restoreSizeLocked()
	}
	t.mu.Unlock()
}

// restoreSizeLocked 按最近活跃（seq 最大）且报过尺寸的接入方恢复尺寸。
func (t *mirror) restoreSizeLocked() {
	var best *mirrorAtt
	for _, a := range t.atts {
		if a.cols > 0 && a.rows > 0 && (best == nil || a.seq > best.seq) {
			best = a
		}
	}
	if best == nil || (best.cols == t.cols && best.rows == t.rows) {
		return
	}
	if err := t.pty.resize(uint32(best.cols), uint32(best.rows)); err == nil {
		t.cols, t.rows = best.cols, best.rows
	}
}

// write 给子进程喂输入（任意接入方的按键都汇到同一个 PTY）。输入也算
// 活动——敲了键即使程序不回显也不能算闲置。
func (t *mirror) write(b []byte) error {
	_, err := t.pty.Write(b)
	if err == nil {
		t.mu.Lock()
		t.lastIO = time.Now()
		t.mu.Unlock()
	}
	return err
}

// resize 接入方 id 报了新尺寸：记到它名下（脱离恢复时用），并立即生效。
func (t *mirror) resize(id string, cols, rows uint32) {
	if cols == 0 || rows == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if a := t.atts[id]; a != nil {
		t.seq++
		a.cols, a.rows, a.seq = int(cols), int(rows), t.seq
	}
	if err := t.pty.resize(cols, rows); err == nil {
		t.cols, t.rows = int(cols), int(rows)
	}
}

func (t *mirror) isExited() bool { return t.dead.Load() }

func (t *mirror) info() mirrorInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return mirrorInfo{
		Name: t.name, Cmd: t.cmd, Cwd: t.cwd, Cols: t.cols, Rows: t.rows,
		Attached: len(t.atts), Exited: t.exited,
		Created: t.created.Format(time.RFC3339), LastIO: t.lastIO.Format(time.RFC3339),
	}
}

// pump 是镜像的输出泵：读 PTY → 留档尾部 → 扇出给全部接入方。
// 收尾以主进程退出为准：Wait 返回后稍等把尾巴读完就关主端——后台任务
// 攥着从端时读端永远等不到 EOF，不关的话镜像会一直挂在登记处里。
func (t *mirror) pump() {
	codeCh := make(chan int, 1)
	go func() {
		codeCh <- t.pty.Wait()
		time.Sleep(mirrorReapDelay)
		_ = t.pty.Close()
	}()
	buf := make([]byte, mirrorChunk)
	for {
		n, err := t.pty.Read(buf)
		if n > 0 {
			t.broadcast(buf[:n])
		}
		if err != nil {
			break
		}
	}
	t.exit(<-codeCh)
}

// broadcast 留档 + 扇出：只往各接入方队列里放，满了就踢掉那个接入方，
// 从不在锁内等任何人。
func (t *mirror) broadcast(b []byte) {
	c := append([]byte(nil), b...)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastIO = time.Now()
	t.keepTail(c)
	t.alt.Feed(c)
	kicked := false
	for id, a := range t.atts {
		select {
		case a.q <- c:
		default:
			delete(t.atts, id)
			a.halt()
			go a.sink.Drop("接入方跟不上输出（网络卡住？），已断开——镜像仍在运行，重新接入即可")
			kicked = true
		}
	}
	if kicked {
		t.restoreSizeLocked()
	}
}

// keepTail 把新输出追加进留档，只留最后 mirrorReplayBytes。截断点不能落在
// 转义序列中间——那截序列尾巴会被接入方的终端打成可见文字：回扫看截断
// 点是不是在某条序列中间，是就从那条序列开头截（整条保住）；再往后挪过
// UTF-8 续字节，重放开头也不出半个汉字。
func (t *mirror) keepTail(c []byte) {
	t.buf = append(t.buf, c...)
	over := len(t.buf) - mirrorReplayBytes
	if over <= 0 {
		return
	}
	if s, ok := seqStartBefore(t.buf, over); ok {
		over = s
	}
	for limit := over + 3; over < limit && over < len(t.buf) && t.buf[over]&0xC0 == 0x80; {
		over++
	}
	t.buf = append(t.buf[:0], t.buf[over:]...)
}

// exit 进程收尾：标记退出、关掉各接入方的队列（发送协程把积压发完后报
// 退出码）、从登记处摘除。发不完的接入方 mirrorExitDrain 后踢掉。
func (t *mirror) exit(code int) {
	t.mu.Lock()
	if t.exited {
		t.mu.Unlock()
		return
	}
	t.exited = true
	t.dead.Store(true)
	t.exitCode = code
	atts := t.atts
	t.atts = make(map[string]*mirrorAtt)
	for _, a := range atts {
		a.code = code
		close(a.q)
	}
	t.mu.Unlock()
	t.m.remove(t.name, t)
	if len(atts) > 0 {
		time.AfterFunc(mirrorExitDrain, func() {
			for _, a := range atts {
				select {
				case <-a.done:
				default:
					a.halt()
					a.sink.Drop("镜像已退出，退出通知发不出去")
				}
			}
		})
	}
}
