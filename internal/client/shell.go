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

// shellFlag 挑「执行一段命令」的旗标：unix shell 的 -c、cmd.exe 的 /c、
// powershell/pwsh 的 -Command，按 shell 文件名判断（用户在 Windows 上
// 配 git-bash 的 bash 时仍然走 -c）。
func shellFlag(shell string) string {
	base := shell
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	switch strings.ToLower(base) {
	case "cmd", "cmd.exe":
		return "/c"
	default:
		if strings.HasPrefix(base, "powershell") || strings.HasPrefix(base, "pwsh") {
			return "-Command"
		}
		return "-c"
	}
}

// shellCmd 拼「shell 参数 命令」的 exec.Cmd。
func shellCmd(shell, command string) *exec.Cmd {
	return exec.Command(shell, shellFlag(shell), command)
}
