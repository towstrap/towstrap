//go:build windows

package client

import "log/slog"

// Windows 没有 unix socket：本机 mirror 子命令不可用。接入镜像终端只走这条
// socket，所以 Windows 上镜像终端整体不可用。后续可以用命名管道补。
func serveMirrorSock(_ *mirrorManager, _ *presence) {
	slog.Info("Windows 暂不支持本机 mirror socket，镜像终端不可用")
}
