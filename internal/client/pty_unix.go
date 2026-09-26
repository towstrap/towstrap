//go:build !windows

package client

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// ptyFile PTY 会话句柄（unix）：file 是伪终端主端，cmd 是挂在从端上的子进程。
type ptyFile struct {
	file *os.File
	cmd  *exec.Cmd
	dead atomic.Bool // Close 后泵的 poll 循环靠它退出
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
	// 主端 fd 设成非阻塞：Read 走 poll+非阻塞读，不然 Linux 上 Close 打不断
	// 阻塞在 read(2) 里的泵（内核的等待挂在 tty 上，关 fd 不叫醒它）。
	_ = unix.SetNonblock(int(f.Fd()), true)
	p := &ptyFile{file: f, cmd: cmd}
	if cols > 0 && rows > 0 {
		_ = p.resize(cols, rows)
	}
	return p, nil
}

// control 在主端 fd 上做 ioctl：走 SyscallConn 拿原始 fd（顺便一提，
// startPty 里已经主动 Fd()+非阻塞了，这里只是统一入口）。
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

// Read 主端读：poll 等数据（100ms 颗粒），有数据走非阻塞 unix.Read。
// Close 只置 dead——泵在下一轮 poll 超时内（≤100ms）自行退出，不依赖
// Linux 上不成立的「close 打断阻塞 read」。
func (p *ptyFile) Read(b []byte) (int, error) {
	fd := int32(p.file.Fd())
	for {
		if p.dead.Load() {
			return 0, io.EOF
		}
		fds := []unix.PollFd{{Fd: fd, Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		n, err := unix.Poll(fds, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue // 超时：回开头再查 dead
		}
		re := fds[0].Revents
		if re&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return 0, io.EOF
		}
		// POLLIN 或 HUP：HUP 时常伴着最后一段残数据，先读一把再说。
		if p.dead.Load() {
			return 0, io.EOF
		}
		m, rerr := unix.Read(int(fd), b)
		if m > 0 {
			return m, nil
		}
		if rerr == unix.EAGAIN {
			if re&unix.POLLIN != 0 {
				continue // 数据被别人抢了，再 poll
			}
			return 0, io.EOF // HUP 且已经读干
		}
		return 0, rerr // EIO/EBADF 等：主端到头
	}
}

func (p *ptyFile) Write(b []byte) (int, error) { return p.file.Write(b) }

func (p *ptyFile) Close() error {
	p.dead.Store(true)
	if p.cmd != nil && p.cmd.Process != nil {
		// PTY 子进程是 setsid 的会话首领（sid=pid）：关终端按会话杀——
		// 交互 shell 的作业控制会给每个 job 单独开进程组，只杀首领或
		// 首领所在的组都盖不住 `sleep 300 &` 这类后台 job；setsid 自己
		// 脱离出去的守护进程是用户有意留的，不追。
		killSession(p.cmd.Process.Pid)
		_ = p.cmd.Process.Kill()
	}
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

// killSession 杀 sid=pid 的整个会话：先按首领自己的进程组杀，再扫同
// 会话其他进程组的成员补杀。枚举在杀之前做——首领死后其组员的 sid
// 不变（孤儿进程组仍记这个 sid）。
func killSession(pid int) {
	targets := sessionPids(pid)
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	for _, t := range targets {
		if t != pid {
			_ = syscall.Kill(t, syscall.SIGKILL)
		}
	}
}

// sessionPids 枚举会话里的所有进程：Linux 扫 /proc；别的 Unix 用
// pgrep -s（macOS/BSD 都带）。扫不到就返回空——killSession 里按组
// 杀首领那一发还在，行为不比以前差。
func sessionPids(sid int) []int {
	if runtime.GOOS == "linux" {
		return sessionPidsProc(sid)
	}
	out, err := exec.Command("pgrep", "-s", strconv.Itoa(sid)).Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Fields(string(out)) {
		if p, err := strconv.Atoi(line); err == nil {
			pids = append(pids, p)
		}
	}
	return pids
}

// sessionPidsProc 扫 /proc/<pid>/stat 找同 sid 的进程。stat 的 comm 字段
// 带括号空格，按最后一个 ')' 切；剩下字段里 state ppid pgrp session 依次排。
func sessionPidsProc(sid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	sidStr := strconv.Itoa(sid)
	var pids []int
	for _, e := range entries {
		name := e.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		b, err := os.ReadFile("/proc/" + name + "/stat")
		if err != nil {
			continue // 进程说没就没，忽略
		}
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(b[i+1:]))
		// f[0]=state f[1]=ppid f[2]=pgrp f[3]=session
		if len(f) > 3 && f[3] == sidStr {
			if p, err := strconv.Atoi(name); err == nil {
				pids = append(pids, p)
			}
		}
	}
	return pids
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
