//go:build !windows

package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
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
func startPty(shell, command, cwd string, cols, rows uint32) (*ptyFile, error) {
	return startPtyEnv(shell, command, cwd, cols, rows, nil)
}

// startPtyEnv 同上，extraEnv 追加进子进程环境（childEnv 过滤掉继承冲突项，
// 追加值生效）。镜像用它打 TOWSTRAP_MIRROR 标记——镜像里的 shell rc
// 钩子凭它知道「已经在镜像里」不再套娃接入。
func startPtyEnv(shell, command, cwd string, cols, rows uint32, extraEnv []string) (*ptyFile, error) {
	var cmd *exec.Cmd
	if command != "" {
		cmd = shellCmd(shell, command)
	} else {
		cmd = exec.Command(shell)
		cmd.Args[0] = "-" + filepath.Base(shell)
	}
	cmd.Env = append(childEnv(), extraEnv...)
	if cwd != "" {
		cmd.Dir = expandHome(cwd)
	}
	f, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	p := &ptyFile{file: f, cmd: cmd}
	if cols > 0 && rows > 0 {
		_ = p.resize(cols, rows)
	}
	return p, nil
}

// control 在主端 fd 上做 ioctl。不能用 f.Fd()：它会把 fd 切成阻塞模式，
// 之后 Close 再也打断不了阻塞在 Read 里的泵——杀进程时后台任务还攥着
// 从端的话，读端就永远卡住（pty.Setsize 内部走的正是 Fd()）。
func (p *ptyFile) control(fn func(fd int) error) error {
	sc, err := p.file.SyscallConn()
	if err != nil {
		return err
	}
	var ierr error
	if err := sc.Control(func(fd uintptr) { ierr = fn(int(fd)) }); err != nil {
		return err
	}
	return ierr
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
	return p.control(func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(rows), Col: uint16(cols)})
	})
}

// redraw 让终端前台进程组重画：尺寸没变时内核不发 SIGWINCH，这里补发一个
// （全屏程序收到都会整屏重画）。拿不到前台进程组就退而发给主进程。
func (p *ptyFile) redraw() {
	if p == nil || p.file == nil {
		return
	}
	var pgrp int
	err := p.control(func(fd int) error {
		var e error
		pgrp, e = unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		return e
	})
	if err == nil && pgrp > 0 {
		_ = syscall.Kill(-pgrp, syscall.SIGWINCH)
		return
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(syscall.SIGWINCH)
	}
}
