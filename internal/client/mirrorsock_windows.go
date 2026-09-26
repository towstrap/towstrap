//go:build windows

package client

import (
	"log/slog"
	"path/filepath"
)

// Windows 没有 unix socket：本机 mirror 子命令不可用。接入镜像终端只走这条
// socket，所以 Windows 上镜像终端整体不可用。后续可以用命名管道补。
func serveMirrorSock(_ *mirrorManager, _ *presence, _ *connState) {
	slog.Info("Windows 暂不支持本机 mirror socket，镜像终端不可用")
}

// DefaultMirrorSockPath Windows 上只用于 status 的探测路径展示。
func DefaultMirrorSockPath() string {
	return filepath.Join(filepath.Dir(DefaultAuditPath()), "mirror.sock")
}

func QueryStatus(string) (*StatusInfo, string, error) {
	return nil, "", ErrNoLocalSock
}
