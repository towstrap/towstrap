//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// chownLikeDir 把刚写的文件改到配置目录属主名下。装服务时 /etc/towstrap
// 被 chown 给了服务账号（linux towstrap / darwin _towstrap），而 register
// 是以 root 跑的——新文件落 root 名下 0600，服务账号根本读不了。目录还
// 是 root 所有时（没装过专用账号的部署）不动。
func chownLikeDir(path string) {
	if os.Geteuid() != 0 {
		return
	}
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return
	}
	_ = os.Chown(path, int(st.Uid), int(st.Gid))
}
