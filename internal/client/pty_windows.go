//go:build windows

package client

import (
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ptyFile PTY 会话句柄（windows ConPTY）：in 写进控制台、out 读控制台输出，
// hpc 是伪控制台句柄，proc/thread 是子进程。子进程退出不会自动让 out 读
// 到 EOF——waiter 先等进程退出拿退出码，再关 pseudoconsole，读端才收尾。
type ptyFile struct {
	in      *os.File
	out     *os.File
	hpc     windows.Handle
	proc    windows.Handle
	thread  windows.Handle
	done    chan struct{} // 子进程已退出（退出码可读）即关闭
	code    int32         // 仅在 done 关闭后有效
	conOnce sync.Once     // pseudoconsole 只关一次
	hOnce   sync.Once     // 进程/线程句柄只关一次
}

// startPty 起 ConPTY 会话：建两条管道 → CreatePseudoConsole → 用
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 把子进程挂上去。
func startPty(shell, command string, cols, rows uint32) (*ptyFile, error) {
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	var inRd, inWr, outRd, outWr windows.Handle
	if err := windows.CreatePipe(&inRd, &inWr, nil, 0); err != nil {
		return nil, err
	}
	if err := windows.CreatePipe(&outRd, &outWr, nil, 0); err != nil {
		windows.CloseHandle(inRd)
		windows.CloseHandle(inWr)
		return nil, err
	}
	var hpc windows.Handle
	if err := windows.CreatePseudoConsole(windows.Coord{X: int16(cols), Y: int16(rows)}, inRd, outWr, 0, &hpc); err != nil {
		windows.CloseHandle(inRd)
		windows.CloseHandle(inWr)
		windows.CloseHandle(outRd)
		windows.CloseHandle(outWr)
		return nil, err
	}
	// 控制台那一端已归 pseudoconsole，我们只留「写输入」「读输出」两端
	windows.CloseHandle(inRd)
	windows.CloseHandle(outWr)

	in := os.NewFile(uintptr(inWr), "conpty-in")
	out := os.NewFile(uintptr(outRd), "conpty-out")
	fail := func(err error) (*ptyFile, error) {
		windows.ClosePseudoConsole(hpc)
		_ = in.Close()
		_ = out.Close()
		return nil, err
	}

	al, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return fail(err)
	}
	defer al.Delete()
	if err := al.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		unsafe.Pointer(&hpc), unsafe.Sizeof(hpc)); err != nil {
		return fail(err)
	}
	si := new(windows.StartupInfoEx)
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(*si))
	si.ProcThreadAttributeList = al.List()

	cmdline, err := windows.UTF16PtrFromString(winCmdLine(shell, command))
	if err != nil {
		return fail(err)
	}
	envp, err := envBlock(childEnv())
	if err != nil {
		return fail(err)
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, cmdline, nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		envp, nil, (*windows.StartupInfo)(unsafe.Pointer(si)), &pi); err != nil {
		return fail(err)
	}

	p := &ptyFile{in: in, out: out, hpc: hpc, proc: pi.Process, thread: pi.Thread,
		done: make(chan struct{})}
	go func() {
		_, _ = windows.WaitForSingleObject(p.proc, windows.INFINITE)
		var code uint32
		_ = windows.GetExitCodeProcess(p.proc, &code)
		atomic.StoreInt32(&p.code, int32(code))
		close(p.done)
		p.closeConsole()
	}()
	return p, nil
}

func (p *ptyFile) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *ptyFile) Write(b []byte) (int, error) { return p.in.Write(b) }

// Close 服务端收掉会话：还活着就 Terminate，pseudoconsole 和两条管道都关。
// 进程/线程句柄留给 Wait 收尾，避免 WaitForSingleObject 等到已关句柄上。
func (p *ptyFile) Close() error {
	select {
	case <-p.done:
	default:
		_ = windows.TerminateProcess(p.proc, 1)
	}
	// 先关管道再关控制台：ClosePseudoConsole 会等输出冲刷，读端已关
	// 的情况下不至于卡住
	_ = p.in.Close()
	_ = p.out.Close()
	p.closeConsole()
	return nil
}

// Wait 等子进程退出（自然退出或被 Close 杀掉都会醒），返回退出码并
// 释放进程/线程句柄。
func (p *ptyFile) Wait() int {
	<-p.done
	p.hOnce.Do(func() {
		windows.CloseHandle(p.proc)
		windows.CloseHandle(p.thread)
	})
	return int(atomic.LoadInt32(&p.code))
}

func (p *ptyFile) closeConsole() {
	p.conOnce.Do(func() { windows.ClosePseudoConsole(p.hpc) })
}

func (p *ptyFile) resize(cols, rows uint32) error {
	return windows.ResizePseudoConsole(p.hpc,
		windows.Coord{X: int16(cols), Y: int16(rows)})
}

// winCmdLine 拼 CreateProcess 的命令行：程序名加引号，后面跟执行旗标
// 和命令正文。
func winCmdLine(shell, command string) string {
	q := `"` + strings.ReplaceAll(shell, `"`, "") + `"`
	if command == "" {
		return q
	}
	return q + " " + shellFlag(shell) + " " + command
}

// envBlock 把 KEY=VAL 列表编成 CreateProcess 要的 UTF-16 双 NUL
// 结尾环境块；CREATE_UNICODE_ENVIRONMENT 要求按变量名排序。
func envBlock(env []string) (*uint16, error) {
	sorted := append([]string(nil), env...)
	sort.Slice(sorted, func(i, j int) bool {
		return strings.ToUpper(envKey(sorted[i])) < strings.ToUpper(envKey(sorted[j]))
	})
	var b strings.Builder
	for _, kv := range sorted {
		b.WriteString(kv)
		b.WriteByte(0)
	}
	b.WriteByte(0)
	u16, err := windows.UTF16FromString(b.String())
	if err != nil {
		return nil, err
	}
	return &u16[0], nil
}

func envKey(kv string) string {
	if i := strings.IndexByte(kv, '='); i >= 0 {
		return kv[:i]
	}
	return kv
}
