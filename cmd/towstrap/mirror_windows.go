//go:build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/proto"
)

// mirror 客户端的 Windows 侧钩子：信号兜底（只有 Ctrl-C/Ctrl-Break 能到），
// 尺寸变化轮询（没有 SIGWINCH），PowerShell profile 钩子写入。
// 协议和搬运循环在 mirror.go（无平台标记）。

// guardSignals Windows 能收到的只有 os.Interrupt（Ctrl-C/Ctrl-Break）；
// 关窗/会话断开是直接杀进程，没有通知机会——raw 模式残留只能由新开的
// 控制台自愈（模式是控制台级的，控制台跟着进程死）。
func guardSignals(restore func()) func() {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		restore()
		os.Exit(1)
	}()
	return func() { signal.Stop(sigCh) }
}

// watchResize 没有 SIGWINCH：轮询控制台缓冲区尺寸，变了才发（默认 500ms，
// 拉窗口最多滞后半秒）。GetConsoleScreenBufferInfo 拿到的 Window 矩形
// 就是可见尺寸，和 ssh/ConPTY 会话语义一致。
func watchResize(send func(mirrorMsg) error) func() {
	done := make(chan struct{})
	go func() {
		tk := time.NewTicker(500 * time.Millisecond)
		defer tk.Stop()
		lastW, lastH := -1, -1
		for {
			select {
			case <-tk.C:
				w, h, err := termSize()
				if err == nil && w > 0 && h > 0 && (w != lastW || h != lastH) {
					lastW, lastH = w, h
					_ = send(mirrorMsg{Cols: w, Rows: h})
				}
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

// mirrorPsProfileBlock PowerShell profile 钩子：语义同 unix 的 rc 段——
// TOWSTRAP_MIRROR_AUTO 填名字 = 每个交互 shell 自动接入；留空只在有活
// 镜像时提醒。防套娃同样靠 TOWSTRAP_MIRROR 环境标记。
func mirrorPsProfileBlock(auto string) string {
	return fmt.Sprintf(`# >>> towstrap mirror >>>
# 可接力终端。$env:TOWSTRAP_MIRROR_AUTO 填上镜像名 = 每个交互 PowerShell
# 自动接入它（本机窗口和 SSH 登进来看同一个画面）；留空 = 只提醒不接入。
# 手动接入：mirror <名字>；临时跳过：$env:TOWSTRAP_NO_MIRROR=1。
if ($env:TOWSTRAP_MIRROR_AUTO -eq $null) { $env:TOWSTRAP_MIRROR_AUTO = '%s' }
if (-not $env:TOWSTRAP_MIRROR -and -not $env:TOWSTRAP_NO_MIRROR -and (Get-Command towstrap -ErrorAction SilentlyContinue)) {
  if ($env:TOWSTRAP_MIRROR_AUTO -ne '') {
    towstrap mirror $env:TOWSTRAP_MIRROR_AUTO
  } else {
    towstrap mirror ls -q | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host '[towstrap] 有可接力镜像：mirror ls 查看，mirror <名字> 接入' }
  }
}
# <<< towstrap mirror <<<
`, auto)
}

// psProfilePaths 候选 profile 路径：PS7 用 Documents\PowerShell\，
// PS 5.1（系统自带）用 Documents\WindowsPowerShell\。
func psProfilePaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
		filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
	}
}

// mirrorSetup 处理 `mirror setup`：打印 PowerShell profile 钩子，或
// --write 幂等写进找到的第一个 profile。cmd.exe 没有启动文件机制，
// 这里只覆盖 PowerShell——cmd 用户看到指引后手动接即可。
func mirrorSetup(args []string) int {
	auto, write := "", false
	for _, a := range args {
		switch {
		case a == "--write" || a == "-w":
			write = true
		case strings.HasPrefix(a, "--auto="):
			auto = strings.TrimPrefix(a, "--auto=")
		case !strings.HasPrefix(a, "-"):
			auto = a
		default:
			fmt.Fprintf(os.Stderr, "用法: %s setup [自动接入的镜像名] [--write]\n", mirrorProg())
			return 2
		}
	}
	if auto != "" && !proto.ValidName(auto) {
		fmt.Fprintf(os.Stderr, "镜像名字 %q 不合法（字母、数字、点、下划线、短横线，最长 64）\n", auto)
		return 2
	}

	if !write {
		fmt.Printf(`把下面这段加进 PowerShell 启动文件（%s）：
默认只在有镜像活着时提醒一行；把 TOWSTRAP_MIRROR_AUTO 后面填上镜像名
就变成每个交互 PowerShell 自动接入（Ctrl-\ 脱离回普通 shell）。
cmd.exe 没有启动文件，手动跑 mirror <名字> 就行。

也可以直接 %[2]s setup --write 让它替你写。

`, strings.Join(psProfilePaths(), " 或 "), mirrorProg())
		fmt.Print(mirrorPsProfileBlock(auto))
		return 0
	}

	for _, rc := range psProfilePaths() {
		if _, err := os.Stat(filepath.Dir(rc)); err != nil {
			continue
		}
		if b, err := os.ReadFile(rc); err == nil && bytes.Contains(b, []byte(">>> towstrap mirror >>>")) {
			fmt.Printf("%s 里已有 towstrap mirror 段，没重复写\n", rc)
			return 0
		}
		f, err := os.OpenFile(rc, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "打不开 %s: %v\n", rc, err)
			return 1
		}
		if _, err := f.WriteString("\r\n" + mirrorPsProfileBlock(auto)); err != nil {
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "写 %s 失败: %v\n", rc, err)
			return 1
		}
		_ = f.Close()
		fmt.Printf("已写进 %s。新开的 PowerShell 生效；想自动接入把 TOWSTRAP_MIRROR_AUTO 填上镜像名。\n", rc)
		return 0
	}
	fmt.Fprintln(os.Stderr, "没找到 PowerShell profile 目录（Documents\\PowerShell 或 Documents\\WindowsPowerShell）——不带 --write 跑一遍拿文本手动加")
	return 1
}
