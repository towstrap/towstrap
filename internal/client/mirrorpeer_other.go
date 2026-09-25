//go:build !linux && !darwin && !windows

package client

import "net"

// peerUID 其他 unix 平台不查对端身份，只靠 socket 文件 0600 把关。
func peerUID(net.Conn) (int, bool) { return 0, false }
