package client

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID 取 unix socket 对端的 uid（LOCAL_PEERCRED）。ok=false 表示这个平台
// 查不了；查的过程出错返回 -1（调用方按不匹配拒掉）。
func peerUID(c net.Conn) (int, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, true
	}
	sc, err := uc.SyscallConn()
	if err != nil {
		return -1, true
	}
	uid := -1
	_ = sc.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED); err == nil {
			uid = int(cred.Uid)
		}
	})
	return uid, true
}
