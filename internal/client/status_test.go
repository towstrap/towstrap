//go:build !windows

package client

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// status op 应答：进程信息 + 连接账本原样回来。
func TestStatusOp(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	st := newConnState("box", "wss://srv")
	st.dialing()
	st.connected()

	cli, srv := net.Pipe()
	defer cli.Close()
	go serveMirrorConn(srv, m, nil, st, false)

	enc := json.NewEncoder(cli)
	dec := json.NewDecoder(cli)
	if err := enc.Encode(mirrorSockMsg{Op: "status"}); err != nil {
		t.Fatal(err)
	}
	var resp mirrorSockMsg
	if err := dec.Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Status == nil {
		t.Fatalf("应答不对: %#v", resp)
	}
	if resp.Status.ID != "box" || resp.Status.Server != "wss://srv" {
		t.Fatalf("id/server 不对: %#v", resp.Status)
	}
	if !resp.Status.Connected || resp.Status.Dials != 1 {
		t.Fatalf("连接状态不对: %#v", resp.Status)
	}
	if resp.Status.PID <= 0 || resp.Status.Version == "" {
		t.Fatalf("pid/ver 缺失: %#v", resp.Status)
	}
}

// 受限连接（root 查别人起的 agent）：只放行 status，ls/attach 一律拒。
func TestStatusOpRestricted(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	st := newConnState("box", "wss://srv")

	cli, srv := net.Pipe()
	defer cli.Close()
	go serveMirrorConn(srv, m, nil, st, true)
	enc := json.NewEncoder(cli)
	dec := json.NewDecoder(cli)

	if err := enc.Encode(mirrorSockMsg{Op: "status"}); err != nil {
		t.Fatal(err)
	}
	var resp mirrorSockMsg
	if err := dec.Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Status == nil {
		t.Fatal("受限连接的 status 应该放行")
	}
	// 连接只允许首行一个请求——status 答完就关
	if err := dec.Decode(&resp); err == nil {
		t.Fatal("status 应答后连接应已关闭")
	}

	cli2, srv2 := net.Pipe()
	defer cli2.Close()
	go serveMirrorConn(srv2, m, nil, st, true)
	enc2 := json.NewEncoder(cli2)
	dec2 := json.NewDecoder(cli2)
	if err := enc2.Encode(mirrorSockMsg{Op: "ls"}); err != nil {
		t.Fatal(err)
	}
	var resp2 mirrorSockMsg
	if err := dec2.Decode(&resp2); err != nil {
		t.Fatal(err)
	}
	if resp2.Err == "" {
		t.Fatal("受限连接的 ls 应被拒")
	}
}

// 断线账本：connected→disconnected 后 Connected 翻 false、LastErr 留痕。
func TestConnStateLifecycle(t *testing.T) {
	st := newConnState("box", "wss://srv")
	st.dialing()
	st.connected()
	st.disconnected(errDropped)
	s := st.snapshot()
	if s.Connected || s.LastErr == "" || s.Dials != 1 {
		t.Fatalf("%#v", s)
	}
	if time.Since(s.LastErrAt) > time.Minute {
		t.Fatal("LastErrAt 应该刚记上")
	}
}

// QueryStatus 走真实 unix socket：serveMirrorSock 监听 + 客户端查询整条链。
func TestQueryStatusRealSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "m.sock")
	t.Setenv("TOWSTRAP_MIRROR_SOCK", sock)

	p := newPresence(Config{AuditLog: filepath.Join(dir, "audit.log")})
	st := newConnState("box", "wss://srv")
	st.dialing()
	st.connected()
	serveMirrorSock(newMirrorManager("/bin/sh"), p, st)

	info, errReply, err := QueryStatus(sock)
	if err != nil || errReply != "" || info == nil {
		t.Fatalf("info=%v errReply=%q err=%v", info, errReply, err)
	}
	if !info.Connected || info.ID != "box" {
		t.Fatalf("%#v", info)
	}

	// socket 不存在 = 传输层错误（agent 没在跑的形态）
	info, errReply, err = QueryStatus(filepath.Join(dir, "gone.sock"))
	if err == nil || info != nil || errReply != "" {
		t.Fatalf("不存在的 socket 应返回传输错误: info=%v errReply=%q err=%v", info, errReply, err)
	}
}
