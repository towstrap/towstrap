//go:build !windows

package client

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Unix 上本机接入走 unix socket mirror.sock。towstrap mirror 子命令（以及
// 任何登上这台机器的 shell——直连 sshd、控制台、towstrap SSH 都算）连上
// 它就能列/接入/新建/终结镜像，不依赖 agent 跟服务器的连接。线缆格式见
// mirrorsock.go。
//
// 安全边界：socket 文件 0600 + 目录 0700，只有跑 agent 的那个用户能连——
// 和「能在本机给这个用户开 shell」等价，不扩大权限面。

// DefaultMirrorSockPath socket 默认位置：审计日志同目录（root 装法
// /var/lib/towstrap/mirror.sock，普通用户 ~/.towstrap/mirror.sock）。
// 审计路径推导不出（HOME 未设置）时返回空串——不落 cwd 相对路径。
func DefaultMirrorSockPath() string {
	if d := DefaultAuditPath(); d != "" {
		return filepath.Join(filepath.Dir(d), "mirror.sock")
	}
	return ""
}

// defaultMirrorDialTargets unix 只有一个候选：socket 路径。
func defaultMirrorDialTargets() []string {
	if p := DefaultMirrorSockPath(); p != "" {
		return []string{p}
	}
	return nil
}

// dialMirror unix 拨号就是 unix socket。
func dialMirror(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", path, timeout)
}

// serveMirrorSock 起本机 socket 监听；起不来只告警不致命（远端接入不受影响）。
// 监听贯穿 agent 整个进程生命，跟连接循环无关。
func serveMirrorSock(m *mirrorManager, p *presence, st *connState) {
	path := os.Getenv("TOWSTRAP_MIRROR_SOCK")
	if path == "" {
		path = DefaultMirrorSockPath()
	}
	if path == "" {
		slog.Warn("mirror socket 路径推导不出（HOME 未设置），本机 mirror 接入不可用")
		return
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
			// 例外：uid 0 连别的用户的 socket 标记为受限——只能跑 status
			// 这类只读查询，开 shell 的操作仍要同一用户。
			restricted := false
			if peer, ok := peerUID(c); ok && peer != uid {
				if peer != 0 {
					slog.Warn("拒绝别的用户连 mirror socket", "peer_uid", peer)
					_ = c.Close()
					continue
				}
				restricted = true
			}
			go serveMirrorConn(c, m, p, st, restricted)
		}
	}()
}
