//go:build windows

package main

import (
	"fmt"
	"os"
)

// Windows 暂无本机 mirror socket（见 internal/client/mirrorsock_windows.go），
// 接入镜像终端的唯一通道就是它——所以 Windows 上没有镜像终端。
func runMirror(_ []string) int {
	fmt.Fprintln(os.Stderr, "Windows 暂不支持镜像终端（没有本机 mirror socket）")
	return 1
}
