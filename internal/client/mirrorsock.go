package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// mirror 本机接入通道：Unix 上是 mirror.sock（unix socket），Windows 上是
// 命名管道 \\.\pipe\towstrap-mirror-<owner SID>。两个平台的线缆格式完全相同
// ——NDJSON（一行一个 JSON 对象，base64 装终端字节）：
//
//	客户端 → {"op":"ls"} / {"op":"attach","name":..,"cmd":..,"cols":..,"rows":..}
//	         / {"op":"kill","name":..} / {"d":".."} / {"cols":..,"rows":..}
//	         / {"op":"detach"}
//	服务端 → {"ok":true,"created":bool,"mirrors":[..]} / {"err":".."}
//	         / {"d":".."} / {"code":N}
//
// 平台差异只有三处，在 mirrorsock_<os>.go：怎么监听（serveMirrorSock）、
// 客户端往哪儿拨（defaultMirrorDialTargets）、拨号本身（DialMirror——
// Windows 版额外核对管道服务端进程身份，防名字抢占）。

// mirrorSockMsg socket/管道上一来一回的消息。op 只在首行带；接入后客户端只发
// d/cols/rows/detach，服务端只发 d/code。
type mirrorSockMsg struct {
	Op      string       `json:"op,omitempty"`
	Name    string       `json:"name,omitempty"`
	Cmd     string       `json:"cmd,omitempty"`
	Cwd     string       `json:"cwd,omitempty"`
	Cols    int          `json:"cols,omitempty"`
	Rows    int          `json:"rows,omitempty"`
	D       string       `json:"d,omitempty"`
	Code    *int         `json:"code,omitempty"`
	OK      bool         `json:"ok,omitempty"`
	Created bool         `json:"created,omitempty"`
	Err     string       `json:"err,omitempty"`
	Mirrors []mirrorInfo `json:"mirrors,omitempty"`
	Status  *StatusInfo  `json:"status,omitempty"`
}

var mirrorLocalSeq atomic.Int64

// —— 命名管道名的纯字符串规则：写在这（无平台标记）是为了测试——管道
// 名格式和候选清单的逻辑在 macOS/Linux 上也能直接跑单测验证。

// mirrorPipePrefix Windows 本机接入的命名管道前缀；后缀是 agent 进程
// owner 的 SID。
const mirrorPipePrefix = `\\.\pipe\towstrap-mirror-`

// systemSID NT AUTHORITY\SYSTEM 的 SID——服务装法的 agent 用它命名管道。
const systemSID = "S-1-5-18"

// pipeSID 从默认形态的管道名里取 owner SID；名字不是
// towstrap-mirror-<SID> 形态（--sock 自定义的）返回空串。
func pipeSID(path string) string {
	if !strings.HasPrefix(path, mirrorPipePrefix) {
		return ""
	}
	sid := strings.TrimPrefix(path, mirrorPipePrefix)
	if !strings.HasPrefix(sid, "S-") || strings.ContainsAny(sid, `\/" `) {
		return ""
	}
	return sid
}

// mirrorPipeTargets 客户端候选管道清单：先自己 owner 的（普通用户跑的
// agent），再 SYSTEM 的（服务装的 agent，本机接入要求管理员）。own SID
// 是 SYSTEM 时只有一条——别重复。
func mirrorPipeTargets(ownSID string) []string {
	if ownSID == "" {
		return nil
	}
	own := mirrorPipePrefix + ownSID
	if ownSID == systemSID {
		return []string{own}
	}
	return []string{own, mirrorPipePrefix + systemSID}
}

// serveMirrorConn 处理一条本机连接：首行是操作，ls/kill/status 一答即走，
// attach 进入双向流直到脱离/断连/镜像退出。restricted 连接（unix 上 root
// 查别的用户起的 agent）只允许 status 只读操作；Windows 的权限边界由
// 管道 ACL 把关，调用方恒传 false。
func serveMirrorConn(c net.Conn, m *mirrorManager, p *presence, st *connState, restricted bool) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	dec := json.NewDecoder(c)
	var first mirrorSockMsg
	if err := dec.Decode(&first); err != nil {
		return
	}
	enc := json.NewEncoder(c)
	replyErr := func(format string, args ...any) {
		_ = enc.Encode(mirrorSockMsg{Err: fmt.Sprintf(format, args...)})
	}
	if restricted && first.Op != "status" {
		if p != nil {
			p.audit.Log("MIRROR-DENY", "op", first.Op, "reason", "restricted")
		}
		replyErr("受限连接只允许 status 查询")
		return
	}

	switch first.Op {
	case "ls":
		// 只读查询也留痕：status/ls 会泄露「机器上有哪些镜像、谁在
		// 连着」，跨用户受限查询尤其要有账可查。
		if p != nil {
			p.audit.Log("MIRROR-LS", "restricted", fmt.Sprint(restricted))
		}
		_ = enc.Encode(mirrorSockMsg{OK: true, Mirrors: m.list()})
		return
	case "status":
		if p != nil {
			p.audit.Log("MIRROR-STATUS", "restricted", fmt.Sprint(restricted))
		}
		info := st.snapshot()
		if p != nil {
			info.Sessions = p.sessions()
		}
		for _, t := range m.list() {
			if !t.Exited {
				info.Mirrors++
			}
		}
		_ = enc.Encode(mirrorSockMsg{OK: true, Status: &info})
		return
	case "kill":
		if !m.kill(first.Name) {
			replyErr("镜像 %q 不存在", first.Name)
			return
		}
		if p != nil {
			p.audit.Log("MIRROR-KILL", "name", first.Name, "via", "local")
		}
		_ = enc.Encode(mirrorSockMsg{OK: true})
		return
	case "attach":
		// 下面继续
	default:
		replyErr("未知操作 %q", first.Op)
		return
	}

	if first.Name == "" {
		replyErr("attach 需要 name")
		return
	}
	t, created, err := m.open(first.Name, first.Cmd, first.Cwd, first.Cols, first.Rows)
	if err != nil {
		replyErr("%v", err)
		return
	}
	id := fmt.Sprintf("local-%d", mirrorLocalSeq.Add(1))
	sink := &sockSink{enc: enc, c: c}
	sessID := "sock-" + id
	if p != nil {
		p.sessionStart(sessID, "local@localhost", "mirror", "mirror:"+first.Name)
	}
	// ok 先走：attach 内部的重放/实时输出都排在它后面，客户端看到 ok
	// 就知道进入流式状态。
	_ = enc.Encode(mirrorSockMsg{OK: true, Name: first.Name, Created: created})
	if err := t.attach(id, sink, first.Cols, first.Rows); err != nil {
		// ok 已经发出，失败只能以 err 行收尾，客户端按退出处理
		replyErr("%v", err)
		if p != nil {
			p.sessionEnd(sessID)
		}
		return
	}
	if created {
		slog.Info("镜像已创建（本机接入）", "name", first.Name, "cmd", oneLine(first.Cmd, 160))
	}
	// 接入后双向都是长连接：握手期那个 30s deadline 是读写一起算的，
	// 只清读会让写超时留着——接入超过 30 秒后输出全发不出去。
	_ = c.SetDeadline(time.Time{})
	defer func() {
		t.detach(id)
		if p != nil {
			p.sessionEnd(sessID)
		}
	}()
	for {
		var m2 mirrorSockMsg
		if err := dec.Decode(&m2); err != nil {
			return
		}
		switch {
		case m2.Op == "detach":
			return
		case m2.D != "":
			b, err := base64.StdEncoding.DecodeString(m2.D)
			if err == nil && len(b) > 0 {
				_ = t.write(b)
			}
		case m2.Cols > 0 && m2.Rows > 0:
			t.resize(id, uint32(m2.Cols), uint32(m2.Rows))
		}
	}
}

// sockSink 本机接入的输出出口：数据包成 {"d":b64}，退出包成 {"code":N}。
// Drop 直接关连接：卡住的 Encode 随之返回，读循环出错收尾，客户端看到断开。
type sockSink struct {
	enc *json.Encoder
	c   net.Conn
	mu  sync.Mutex
}

func (s *sockSink) Drop(reason string) {
	slog.Warn("本机镜像接入被断开", "reason", reason)
	_ = s.c.Close()
}

func (s *sockSink) SendData(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(mirrorSockMsg{D: base64.StdEncoding.EncodeToString(b)})
}

// SendExit 报完退出码就关连接：镜像没了，这条接入也没有存在的意义，
// 不关的话服务端读循环会一直等一个不再说话的客户端。
func (s *sockSink) SendExit(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(mirrorSockMsg{Code: &code})
	_ = s.c.Close()
}

// MirrorDialTargets 本机接入通道的候选拨号地址：override 非空（--sock 旗标或
// TOWSTRAP_MIRROR_SOCK）就用它一个；否则走平台默认清单——Unix 是
// mirror.sock 一条；Windows 是按 owner SID 命名的管道，可能有「自己的」和
// 「SYSTEM 服务」两个候选（客户端可能是本机用户也可能是服务会话里的
// SYSTEM 进程）。
func MirrorDialTargets(override string) []string {
	if override == "" {
		return defaultMirrorDialTargets()
	}
	return []string{override}
}

// DialMirror 拨本机接入通道（unix socket 或 Windows 命名管道）。Windows 版
// 会核对管道服务端进程的用户 SID 与管道名编码的 owner 一致——命名管道是
// 全局名字，抢占者可以偷到管理员的按键；对不上就拒连。
func DialMirror(path string) (net.Conn, error) {
	return dialMirror(path, 10*time.Second)
}

// QueryStatus 向本机接入通道发 status 查询。三个返回值分三种情况：
//
//	info 非空    —— agent 在跑且应答了实时状态
//	errReply 非空 —— 通道活着但 op 被拒（旧版本 agent 不认识 status，
//	                或受限对端）——进程在跑，只是拿不到详情
//	err 非空     —— 传输层失败（socket/管道不存在或连不上），agent 多半没在跑
func QueryStatus(path string) (info *StatusInfo, errReply string, err error) {
	c, err := dialMirror(path, 3*time.Second)
	if err != nil {
		return nil, "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(c).Encode(mirrorSockMsg{Op: "status"}); err != nil {
		return nil, "", err
	}
	var m mirrorSockMsg
	if err := json.NewDecoder(c).Decode(&m); err != nil {
		return nil, "", err
	}
	if m.Err != "" {
		return nil, m.Err, nil
	}
	return m.Status, "", nil
}
