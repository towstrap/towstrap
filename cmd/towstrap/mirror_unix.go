//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/towstrap/towstrap/internal/proto"
)

// mirror 客户端的 unix 侧钩子：SIGTERM/HUP 信号保护、SIGWINCH 尺寸变化、
// shell rc 钩子写入。协议和搬运循环在 mirror.go（无平台标记）。

// guardSignals 装信号兜底：被杀（ssh 断了收到 HUP/TERM）时先恢复终端模式
// 再退，不然父终端留在 raw。返回可停用函数。
func guardSignals(restore func()) func() {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigCh
		restore()
		os.Exit(1)
	}()
	return func() { signal.Stop(sigCh) }
}

// watchResize SIGWINCH 驱动：窗口一变就把新尺寸发给镜像（里面的程序收
// SIGWINCH 重绘）。返回停用函数。
func watchResize(send func(mirrorMsg) error) func() {
	winCh := make(chan os.Signal, 4)
	signal.Notify(winCh, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-winCh:
				if w, h, err := termSize(); err == nil && w > 0 && h > 0 {
					_ = send(mirrorMsg{Cols: w, Rows: h})
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(winCh)
		close(done)
	}
}

// mirrorRcBlock 生成写进 shell rc 的钩子：默认只提醒不接入——有活镜像时
// 提示一行（"有镜子可以接"），没有就静默；用户在 TOWSTRAP_MIRROR_AUTO
// 里填上名字才变成自动接入。防套娃靠镜像进程自带的 TOWSTRAP_MIRROR
// 环境标记；TOWSTRAP_NO_MIRROR 是临时逃生门；case $- 挡掉 sshd 下巴 sh
// 连非交互也读 .bashrc 的怪癖（不然 scp/rsync 会被干扰）。
func mirrorRcBlock(auto string) string {
	return fmt.Sprintf(`# >>> towstrap mirror >>>
# 可接力终端。TOWSTRAP_MIRROR_AUTO 填上镜像名 = 每个交互 shell 自动接入它
# （本机窗口和 SSH 登进来看同一个画面，离开机器后远程接力）；留空 = 不自动
# 进，只在有镜像活着时提醒一行。手动接入：mirror <名字>
# 临时跳过：export TOWSTRAP_NO_MIRROR=1；彻底去掉：删掉本段。
TOWSTRAP_MIRROR_AUTO=%s
case $- in
*i*)
  if [ -z "$TOWSTRAP_MIRROR" ] && [ -z "$TMUX" ] && [ -z "$TOWSTRAP_NO_MIRROR" ] && command -v towstrap >/dev/null 2>&1; then
    if [ -n "$TOWSTRAP_MIRROR_AUTO" ]; then
      towstrap mirror "$TOWSTRAP_MIRROR_AUTO"
    elif towstrap mirror ls -q 2>/dev/null; then
      echo "[towstrap] 有可接力镜像：mirror ls 查看，mirror <名字> 接入"
    fi
  fi
  ;;
esac
# <<< towstrap mirror <<<
`, auto)
}

// mirrorRcPath 按 $SHELL 挑 rc 文件；不认识的 shell 返回空串让调用方只打印。
func mirrorRcPath() string {
	base := ""
	if sh := os.Getenv("SHELL"); sh != "" {
		if i := strings.LastIndexByte(sh, '/'); i >= 0 {
			base = sh[i+1:]
		} else {
			base = sh
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch base {
	case "zsh":
		return home + "/.zshrc"
	case "bash":
		return home + "/.bashrc"
	}
	return ""
}

// mirrorSetup 处理 `mirror setup`：打印钩子代码块，或 --write 幂等地追加
// 进对应 rc 文件。带个名字（如 setup work --write）则把自动接入名预填成
// 它；不带名字默认留空（只提醒不接入）。已写入过（见到标记）就不重复加。
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
		fmt.Printf(`把下面这段加进 shell 启动文件（zsh: ~/.zshrc，bash: ~/.bashrc）：
默认只在有镜像活着时提醒一行，不自动接入；想自动接入，把
TOWSTRAP_MIRROR_AUTO= 后面填上镜像名（本机终端和 SSH 登进来的就是
同一个画面，离开机器后远程接力，Ctrl-\ 脱离回普通 shell）。

也可以直接 %[1]s setup --write 让它替你写；%[1]s setup 名字 --write
顺带把自动接入名填上。

`, mirrorProg())
		fmt.Print(mirrorRcBlock(auto))
		return 0
	}

	rc := mirrorRcPath()
	if rc == "" {
		fmt.Fprintf(os.Stderr, "认不出 $SHELL（%q）——不支持自动写入，把下面这段手动加到你的 rc：\n\n%s",
			os.Getenv("SHELL"), mirrorRcBlock(auto))
		return 1
	}
	if b, err := os.ReadFile(rc); err == nil && bytes.Contains(b, []byte(">>> towstrap mirror >>>")) {
		fmt.Printf("%s 里已有 towstrap mirror 段，没重复写（想改自动接入名或去掉，编辑该段即可）\n", rc)
		return 0
	}
	f, err := os.OpenFile(rc, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打不开 %s: %v\n", rc, err)
		return 1
	}
	if _, err := f.WriteString("\n" + mirrorRcBlock(auto)); err != nil {
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "写 %s 失败: %v\n", rc, err)
		return 1
	}
	_ = f.Close()
	if auto == "" {
		fmt.Printf(`已写进 %s。默认只提醒不接入：新终端里有活镜像时会提示一行；
想自动接入，把该段里 TOWSTRAP_MIRROR_AUTO= 后面填上镜像名。
不想用时删掉 # >>> towstrap mirror >>> 那段，或 export TOWSTRAP_NO_MIRROR=1。
`, rc)
	} else {
		fmt.Printf(`已写进 %s（自动接入 %q）。新开的终端窗口、SSH 登进来都会自动
接入；Ctrl-\ 脱离回普通 shell。不想用时删掉 # >>> towstrap mirror >>>
那段，或 export TOWSTRAP_NO_MIRROR=1。
`, rc, auto)
	}
	return 0
}
