//go:build !windows

package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// mirror.sock：本机接入镜像终端的通道。towstrap mirror 子命令（以及任何
// 登上这台机器的 shell——直连 sshd、控制台、towstrap SSH 都算）连上这个
// unix socket 就能列/接入/新建/终结镜像，不依赖 agent 跟服务器的连接。
//
// 协议是 NDJSON（一行一个 JSON 对象，base64 装终端字节）：
//   客户端 → {"op":"ls"} / {"op":"attach","name":..,"cmd":..,"cols":..,"rows":..}
//            / {"op":"kill","name":..} / {"d":".."} / {"cols":..,"rows":..}
//            / {"op":"detach"}
//   服务端 → {"ok":true,"created":bool,"mirrors":[..]} / {"err":".."}
//            / {"d":".."} / {"code":N}
//
// 安全边界：socket 文件 0600 + 目录 0700，只有跑 agent 的那个用户能连——
// 和「能在本机给这个用户开 shell」等价，不扩大权限面。

// mirrorSockMsg socket 上一来一回的消息。op 只在首行带；接入后客户端只发
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
}

// DefaultMirrorSockPath socket 默认位置：审计日志同目录（root 装法
// /var/lib/towstrap/mirror.sock，普通用户 ~/.towstrap/mirror.sock）。
func DefaultMirrorSockPath() string {
	return filepath.Join(filepath.Dir(DefaultAuditPath()), "mirror.sock")
}

// serveMirrorSock 起本机 socket 监听；起不来只告警不致命（远端接入不受影响）。
// 监听贯穿 agent 整个进程生命，跟连接循环无关。
func serveMirrorSock(m *mirrorManager, p *presence) {
	path := os.Getenv("TOWSTRAP_MIRROR_SOCK")
	if path == "" {
		path = DefaultMirrorSockPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		slog.Warn("mirror socket 目录建不了，本机 mirror 接入不可用", "path", path, "err", err)
		return
	}
	// 旧 socket 文件可能是上次没清掉的：unix Listen 遇到已存在的文件会失败，
	// 先删再听。真有别的 agent 在跑时 connect 会通——那时新监听者抢文件没
	// 意义也不该抢，直接放弃。
	if c, err := net.DialTimeout("unix", path, 300*time.Millisecond); err == nil {
		_ = c.Close()
		slog.Warn("mirror socket 已被占用（可能有另一个 agent 在跑），本机 mirror 接入不起", "path", path)
		return
	}
	// 只删残留的 socket 文件：路径配错指到普通文件上时不能把它删了
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			slog.Warn("mirror socket 路径上是个非 socket 文件，不动它；本机 mirror 接入不可用", "path", path)
			return
		}
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		slog.Warn("mirror socket 监听失败，本机 mirror 接入不可用", "path", path, "err", err)
		return
	}
	_ = os.Chmod(path, 0o600)
	slog.Info("mirror socket 已监听", "path", path)
	uid := os.Geteuid()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// 文件权限之外再核一次对端身份：Listen 到 Chmod 之间有个窗口，
			// 目录也可能不是 0700（审计日志先建的目录是 0755）。连进来的
			// 就等于拿到本用户的 shell，只放同一个用户（root 跑时只放 root）。
			if peer, ok := peerUID(c); ok && peer != uid {
				slog.Warn("拒绝别的用户连 mirror socket", "peer_uid", peer)
				_ = c.Close()
				continue
			}
			go serveMirrorConn(c, m, p)
		}
	}()
}

var mirrorLocalSeq atomic.Int64

// serveMirrorConn 处理一条本机连接：首行是操作，ls/kill 一答即走，attach
// 进入双向流直到脱离/断连/镜像退出。
func serveMirrorConn(c net.Conn, m *mirrorManager, p *presence) {
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

	switch first.Op {
	case "ls":
		_ = enc.Encode(mirrorSockMsg{OK: true, Mirrors: m.list()})
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
