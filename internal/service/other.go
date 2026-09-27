//go:build !linux && !darwin && !windows

package service

import (
	"fmt"
	"runtime"
)

func install(Opts) (string, error)   { return "", errNoService() }
func uninstall(Opts) (string, error) { return "", errNoService() }
func status(Opts) string             { return fmt.Sprintf("%s 不支持服务管理", runtime.GOOS) }
func errNoService() error {
	return fmt.Errorf("%s 没有实现服务注册——用 nohup/tmux 顶着或跑 install 脚本", runtime.GOOS)
}
