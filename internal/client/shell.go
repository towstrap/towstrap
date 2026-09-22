package client

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// defaultShell 挑 agent 的默认 shell：先看 SHELL；Windows 上没有 SHELL，
// 退回 COMSPEC（一般指向 cmd.exe），再没有就用 cmd.exe。
func defaultShell() string {
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	if runtime.GOOS == "windows" {
		if s := os.Getenv("COMSPEC"); s != "" {
			return s
		}
		return "cmd.exe"
	}
	return "/bin/bash"
}

// shellCmd 拼「shell 参数 命令」：unix shell 的 -c、cmd.exe 的 /c、
// powershell/pwsh 的 -Command，按 shell 文件名判断（用户在 Windows 上
// 配 git-bash 的 bash 时仍然走 -c）。
func shellCmd(shell, command string) *exec.Cmd {
	flag := "-c"
	base := shell
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	switch base = strings.ToLower(base); {
	case base == "cmd" || base == "cmd.exe":
		flag = "/c"
	case strings.HasPrefix(base, "powershell") || strings.HasPrefix(base, "pwsh"):
		flag = "-Command"
	}
	return exec.Command(shell, flag, command)
}
