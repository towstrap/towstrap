//go:build !windows

package client

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/creack/pty"
)

// ptyFile PTY 会话句柄（unix）：file 是伪终端主端，cmd 是挂在从端上的子进程。
type ptyFile struct {
	file *os.File
	cmd  *exec.Cmd
}

// startPty 起 PTY 会话：command 非空走「shell -c 命令」，空是交互 shell。
// 交互 shell 用 argv[0] 加「-」前缀变登录 shell（sshd 同款做法，比 -l 旗标
// 更通用——dash/sh 没有 -l）：用户的 .zprofile/.bash_profile 才加载，
// CLICOLOR、LS 配色、PATH 这些才不会缺。
func startPty(shell, command string, cols, rows uint32) (*ptyFile, error) {
	var cmd *exec.Cmd
	if command != "" {
		cmd = shellCmd(shell, command)
	} else {
		cmd = exec.Command(shell)
		cmd.Args[0] = "-" + filepath.Base(shell)
	}
	cmd.Env = childEnv()
	f, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	if cols > 0 && rows > 0 {
		_ = pty.Setsize(f, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	}
	return &ptyFile{file: f, cmd: cmd}, nil
}

func (p *ptyFile) Read(b []byte) (int, error)  { return p.file.Read(b) }
func (p *ptyFile) Write(b []byte) (int, error) { return p.file.Write(b) }

func (p *ptyFile) Close() error {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

// Wait 回收子进程并返回退出码；Close 先杀进程时再调用只是收尸。
func (p *ptyFile) Wait() int {
	return exitCode(p.cmd.Wait())
}

func (p *ptyFile) resize(cols, rows uint32) error {
	return pty.Setsize(p.file, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
}
