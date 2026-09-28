//go:build windows

package client

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Windows 没有 unix socket：本机接入走命名管道，名字按 agent 进程的
// owner SID 编码——\\.\pipe\towstrap-mirror-S-1-5-18 是 SYSTEM 服务那台，
// 普通用户跑的 agent 是 \\.\pipe\towstrap-mirror-S-1-5-21-...。线缆格式
// （NDJSON）和 unix socket 完全一样，见 mirrorsock.go。
//
// 安全边界等价于 unix 的 socket 0600：「连上=拿到 agent 身份的 shell」。
// 管道 ACL 只放三种人——owner 本人、SYSTEM、管理员（BA）：
//   - agent 以服务（SYSTEM）跑时，本机接入要管理员终端，或从 towstrap SSH
//     会话里接（那条 shell 本来就是 SYSTEM 子进程）
//   - agent 以普通用户跑时，该用户和 SYSTEM/管理员都能接
// 客户端侧再核一次服务端身份：管道名是全局命名空间，别的进程可以先抢注
// 同名管道骗接入方的按键——连上后查管道服务端进程的 token user，
// 和名字里的 SID 对不上就拒连。

// ownUserSID 当前进程的 token user SID（agent 监听管道名和 ACL 都用它）。
func ownUserSID() (string, error) {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// DefaultMirrorSockPath Windows 的「socket 路径」就是本进程 owner 的
// 管道名——agent 监听用它；推导不出 SID 时返回空串。
func DefaultMirrorSockPath() string {
	sid, err := ownUserSID()
	if err != nil {
		return ""
	}
	return mirrorPipePrefix + sid
}

// defaultMirrorDialTargets 客户端候选：先自己 owner 的管道（普通用户跑的
// agent），再 SYSTEM 那台（服务跑的 agent）。SYSTEM 候选只能在 SYSTEM
// 或管理员上下文里连得上——ACL 会挡掉普通用户，那时报错引导开管理员终端。
func defaultMirrorDialTargets() []string {
	sid, err := ownUserSID()
	if err != nil {
		return nil
	}
	return mirrorPipeTargets(sid)
}

// serveMirrorSock 起命名管道监听；起不来只告警不致命（远端接入不受影响）。
func serveMirrorSock(m *mirrorManager, p *presence, st *connState) {
	path := os.Getenv("TOWSTRAP_MIRROR_SOCK")
	if path == "" {
		path = DefaultMirrorSockPath()
	}
	if path == "" {
		slog.Warn("mirror 管道名推导不出（取不到进程 SID），本机 mirror 接入不可用")
		return
	}
	// SDDL：D:P = DACL 禁用继承；GA = 全部权限。SY=SYSTEM、BA=内置管理员、
	// 最后是 owner 自己的 SID（服务场景就是 SY，重复无害）。
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if sid := pipeSID(path); sid != "" && sid != systemSID {
		sddl += fmt.Sprintf("(A;;GA;;;%s)", sid)
	}
	ln, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		// 名字被占多半是另一个 agent 实例在跑（单实例锁按 server+id 区分，
		// 不同身份的 agent 可以共存），也可能被人抢注——都降级成不可用。
		slog.Warn("mirror 管道监听失败，本机 mirror 接入不可用", "path", path, "err", err)
		return
	}
	slog.Info("mirror 管道已监听", "path", path)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// 权限边界在管道 ACL 上（kernel 强制）：restricted 恒 false。
			go serveMirrorConn(c, m, p, st, false)
		}
	}()
}

// dialMirror 拨命名管道并核对服务端身份：GetNamedPipeServerProcessId 拿
// 服务端 PID → 打开它的 token 取 user SID → 和管道名里的 owner SID 比对。
// SID 不一致 = 名字被抢占，拒连。管道名不是默认形态时跳过核对。
func dialMirror(path string, timeout time.Duration) (net.Conn, error) {
	c, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return nil, err
	}
	if want := pipeSID(path); want != "" {
		if err := verifyPipeOwner(c, want); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	return c, nil
}

// win32File 是 winio 连接的具体类型：Fd() 给出管道句柄，
// GetNamedPipeServerProcessId 靠它拿对端 PID。
func verifyPipeOwner(c net.Conn, wantSID string) error {
	fd, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return nil // 不认识的连接类型：拿到句柄的通道没有就不核（不该发生）
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &pid); err != nil {
		return fmt.Errorf("取不到管道服务端 PID：%w", err)
	}
	sid, err := processUserSID(pid)
	if err != nil {
		return fmt.Errorf("查管道服务端身份失败：%w", err)
	}
	if sid != wantSID {
		return fmt.Errorf("管道服务端身份不符（实际 %s，应是 %s）——管道名可能被抢占", sid, wantSID)
	}
	return nil
}

// processUserSID 取一个进程 token 的 user SID。
func processUserSID(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}
