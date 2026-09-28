package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/towstrap/towstrap/internal/client"
)

// towstrap mirror：本机接入镜像终端的客户端。连 agent 的本机接入通道
// （unix 是 mirror.sock，Windows 是命名管道——NDJSON 协议相同，见
// internal/client/mirrorsock.go）。安装时会建 mirror → towstrap 的别名
// ——以那个名字调起时 main() 直接进这里，所以日常敲的是
// `mirror ls` / `mirror work`，不用带 agent 字样。
//
//   mirror                 列出所有镜像
//   mirror work            接入 work；不存在就以登录 shell 新建
//   mirror work vim a.go   接入 work；不存在就以该命令新建
//   mirror kill work       终结 work（镜像里的进程被杀）
//
// 接入后按 Ctrl-\ 脱离——镜像里的进程继续跑，下次同名接入接着用。
// 套在 ssh/mosh 里也能用：ssh -t 机器 mirror work。
//
// 本文件是无平台差的部分（协议、参数、搬运循环）；拨号方式、窗口变化
// 通知、信号保护和 shell 钩子按平台分在 mirror_unix.go / mirror_windows.go。

type mirrorMsg struct {
	Op      string             `json:"op,omitempty"`
	Name    string             `json:"name,omitempty"`
	Cmd     string             `json:"cmd,omitempty"`
	Cwd     string             `json:"cwd,omitempty"`
	Cols    int                `json:"cols,omitempty"`
	Rows    int                `json:"rows,omitempty"`
	D       string             `json:"d,omitempty"`
	Code    *int               `json:"code,omitempty"`
	OK      bool               `json:"ok,omitempty"`
	Created bool               `json:"created,omitempty"`
	Err     string             `json:"err,omitempty"`
	Mirrors []clientMirrorInfo `json:"mirrors,omitempty"`
}

// clientMirrorInfo 和 internal/client.mirrorInfo 同形（它是未导出类型，这里镜像）。
type clientMirrorInfo struct {
	Name     string `json:"name"`
	Cmd      string `json:"cmd,omitempty"`
	Cwd      string `json:"cwd,omitempty"`
	Cols     int    `json:"cols"`
	Rows     int    `json:"rows"`
	Attached int    `json:"attached"`
	Exited   bool   `json:"exited,omitempty"`
	Created  string `json:"created"`
	LastIO   string `json:"last_io"`
}

const detachKey = 0x1c // Ctrl-\

// termSize 读终端尺寸：抽成变量，测试好替换；各平台 watchResize 也用它。
var termSize = func() (int, int, error) {
	return term.GetSize(int(os.Stdout.Fd()))
}

func runMirror(args []string) int {
	fs := flag.NewFlagSet(mirrorProg(), flag.ExitOnError)
	sock := fs.String("sock", "", "mirror 通道地址（默认环境变量 TOWSTRAP_MIRROR_SOCK，再默认平台惯例：mirror.sock / 命名管道）")
	_ = fs.Parse(args)
	rest := fs.Args()

	override := *sock
	if override == "" {
		override = os.Getenv("TOWSTRAP_MIRROR_SOCK")
	}
	targets := client.MirrorDialTargets(override)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "mirror 通道地址推导不出（HOME/SID 取不到）——用 --sock 或 TOWSTRAP_MIRROR_SOCK 指定")
		return 1
	}

	op := "ls"
	var name string
	var cmd string
	switch {
	case len(rest) == 0 || rest[0] == "ls" || rest[0] == "list":
		op = "ls"
	case rest[0] == "kill":
		if len(rest) != 2 {
			fmt.Fprintf(os.Stderr, "用法: %s kill <名字>\n", mirrorProg())
			return 2
		}
		op, name = "kill", rest[1]
	case rest[0] == "setup":
		return mirrorSetup(rest[1:])
	case rest[0] == "help" || rest[0] == "-h":
		mirrorUsage()
		return 0
	default:
		op, name = "attach", rest[0]
		if len(rest) > 1 {
			cmd = strings.Join(rest[1:], " ")
		}
	}

	// 已在同名镜像里再接自己是套娃：画面套画面，Ctrl-\ 都不好分辨脱离的是哪层。
	if op == "attach" && os.Getenv("TOWSTRAP_MIRROR") == name {
		fmt.Fprintf(os.Stderr, "已经在镜像 %q 里了，不用再接（想换镜像直接接别的名字；Ctrl-\\ 脱离后再说）\n", name)
		return 1
	}

	c, target, err := dialMirrorAny(targets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "连不上 mirror 通道：%v（agent 没在跑？或被删了）\n", err)
		return 1
	}
	_ = target
	defer c.Close()
	dec := json.NewDecoder(c)
	enc := json.NewEncoder(c)

	switch op {
	case "ls":
		if err := enc.Encode(mirrorMsg{Op: "ls"}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		var m mirrorMsg
		if err := dec.Decode(&m); err != nil {
			fmt.Fprintln(os.Stderr, "读应答失败:", err)
			return 1
		}
		if m.Err != "" {
			fmt.Fprintln(os.Stderr, m.Err)
			return 1
		}
		// ls -q 是存在性探针（rc 钩子/脚本用）：有活镜像退出 0，没有退出 1，
		// 什么都不打印。
		for _, a := range rest[1:] {
			if a == "-q" || a == "--quiet" {
				for _, t := range m.Mirrors {
					if !t.Exited {
						return 0
					}
				}
				return 1
			}
		}
		printMirrorList(m.Mirrors)
		return 0
	case "kill":
		if err := enc.Encode(mirrorMsg{Op: "kill", Name: name}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		var m mirrorMsg
		if err := dec.Decode(&m); err != nil {
			fmt.Fprintln(os.Stderr, "读应答失败:", err)
			return 1
		}
		if m.Err != "" {
			fmt.Fprintln(os.Stderr, m.Err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "镜像 %s 已终结\n", name)
		return 0
	}

	// attach：拿终端尺寸 → 发接入请求 → 等 ok/err
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintln(os.Stderr, "mirror attach 需要真实终端（ssh 记得加 -t；脚本里用不了）")
		return 1
	}
	cols, rows, err := termSize()
	if err != nil || cols == 0 || rows == 0 {
		cols, rows = 80, 24
	}
	// 带上当前目录：新建镜像时 shell 落在我敲命令的目录，而不是 agent
	// 进程的启动目录；镜像已存在则该字段被忽略（不打扰已有会话）。
	cwd, _ := os.Getwd()
	if err := enc.Encode(mirrorMsg{Op: "attach", Name: name, Cmd: cmd, Cwd: cwd, Cols: cols, Rows: rows}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var first mirrorMsg
	if err := dec.Decode(&first); err != nil {
		fmt.Fprintln(os.Stderr, "读应答失败:", err)
		return 1
	}
	if first.Err != "" {
		fmt.Fprintln(os.Stderr, first.Err)
		return 1
	}
	if !first.OK {
		fmt.Fprintln(os.Stderr, "接入失败")
		return 1
	}
	if first.Created {
		fmt.Fprintf(os.Stderr, "[towstrap] 已新建镜像 %q\n", name)
	} else {
		fmt.Fprintf(os.Stderr, "[towstrap] 已接入镜像 %q（命令被忽略则属正常——镜像里跑的还是原来那个）\n", name)
	}
	fmt.Fprintf(os.Stderr, "[towstrap] 脱离：Ctrl-\\ 或行首 ~.（进程继续跑）；镜像内程序退出即结束\n")

	old, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "切终端原始模式失败:", err)
		return 1
	}
	restore := func() { _ = term.Restore(int(os.Stdin.Fd()), old) }
	defer restore()

	// 被杀（ssh 断了收到 HUP/TERM）时也要恢复终端模式，不然父终端留 raw。
	// Windows 上信号几乎没有，guardSignals 是近乎空操作——那边靠控制台
	// 生命周期收尾。
	defer guardSignals(restore)()

	// 窗口变化和按键两个协程都往同一条连接写：send 加锁，一行一行不串。
	var encMu sync.Mutex
	send := func(m mirrorMsg) error {
		encMu.Lock()
		defer encMu.Unlock()
		return enc.Encode(m)
	}

	// 窗口变化 → 通知镜像改尺寸（里面的程序收 SIGWINCH/resize 重绘）。
	// unix 是 SIGWINCH 驱动，Windows 没有信号——轮询对比。
	stopResize := watchResize(send)
	defer stopResize()

	var alt client.AltScreen
	code, end, rerr := relayMirror(dec, send, os.Stdin, os.Stdout, &alt)
	// 远端程序设的鼠标上报、备用屏幕、隐藏光标这些模式得撤掉，不然脱离后
	// 本地终端一动鼠标就吐乱码、停在一块空屏上。
	_, _ = os.Stdout.WriteString(client.TermReset(alt.On()))
	restore()
	switch end {
	case relayDetached:
		fmt.Fprintf(os.Stderr, "\r\n[towstrap] 已脱离 %q，镜像继续跑（再接: %s %s）\n", name, mirrorProg(), name)
		return 0
	case relayExited:
		fmt.Fprintf(os.Stderr, "\r\n[towstrap] 镜像 %q 已退出（exit=%d）\n", name, code)
		return code
	default:
		// 连接断了 / 被 agent 踢掉：镜像多半还活着，别说成「已退出」
		fmt.Fprintf(os.Stderr, "\r\n[towstrap] 和镜像 %q 的连接断开：%v（镜像可能仍在运行，%s ls 看看，%s %s 重新接入）\n",
			name, rerr, mirrorProg(), mirrorProg(), name)
		return 1
	}
}

// dialMirrorAny 按候选清单逐个拨：第一个连通的赢，全灭报最后一个错。
// Windows 上候选有「自己的」和「SYSTEM 服务」两条管道；unix 永远一条。
func dialMirrorAny(targets []string) (net.Conn, string, error) {
	var lastErr error
	for _, path := range targets {
		c, err := client.DialMirror(path)
		if err == nil {
			return c, path, nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

type relayEnd int

const (
	relayExited   relayEnd = iota // 收到退出码：镜像里的程序结束了
	relayDetached                 // 本端按了 Ctrl-\
	relayLost                     // 连接断开或 agent 回了错误
)

// relayMirror 接入后的双向搬运：in 的按键送进镜像，镜像的输出写到 out 并
// 喂给 alt 跟踪备用屏幕。两种脱离：Ctrl-\（0x1c，任何位置）和 ssh 惯例的
// 行首 ~.——后者是兜底的：Ctrl-\ 的字节可能被外层终端或 ConPTY 吃掉送不
// 到，~. 是纯可打印字符谁也拦不住（~~ 在行首表示字面 ~，同 ssh）。
// 返回退出码（relayExited 时有意义）、结束方式和断开原因。
func relayMirror(dec *json.Decoder, send func(mirrorMsg) error, in io.Reader, out io.Writer, alt *client.AltScreen) (int, relayEnd, error) {
	detached := make(chan struct{})
	go func() {
		detach := func() {
			// 先标记再发：服务端收到 detach 就断连，读循环看到断开时
			// 这边一定已经是「脱离」状态
			close(detached)
			_ = send(mirrorMsg{Op: "detach"})
		}
		buf := make([]byte, 4096)
		run := make([]byte, 0, 4096) // 攒一攒一起发，少打几行
		lineStart := true            // 行首：开局或上一个字节是回车/换行
		tilde := false               // 行首 ~ 已见，等下一字节判 ~.
		for {
			n, rerr := in.Read(buf)
			for _, c := range buf[:n] {
				if tilde {
					tilde = false
					if c == '.' { // ~.：脱离，~ 和 . 都不进镜像
						if len(run) > 0 && send(mirrorMsg{D: base64.StdEncoding.EncodeToString(run)}) != nil {
							return
						}
						detach()
						return
					}
					if c == '~' { // ~~：行首发一个字面 ~
						run = append(run, '~')
						lineStart = false
						continue
					}
					run = append(run, '~') // 挂起的 ~ 落回，按普通字节处理 c
				}
				if c == detachKey {
					if len(run) > 0 && send(mirrorMsg{D: base64.StdEncoding.EncodeToString(run)}) != nil {
						return
					}
					detach()
					return
				}
				if lineStart && c == '~' {
					tilde = true
					continue
				}
				lineStart = c == '\r' || c == '\n'
				run = append(run, c)
			}
			if len(run) > 0 {
				if send(mirrorMsg{D: base64.StdEncoding.EncodeToString(run)}) != nil {
					return
				}
				run = run[:0]
			}
			if rerr != nil {
				if tilde { // 输入收尾时挂起的 ~ 补发出去
					_ = send(mirrorMsg{D: base64.StdEncoding.EncodeToString([]byte{'~'})})
				}
				return
			}
		}
	}()
	for {
		var m mirrorMsg
		if err := dec.Decode(&m); err != nil {
			select {
			case <-detached:
				return 0, relayDetached, nil
			default:
			}
			if err == io.EOF {
				err = errors.New("agent 关闭了连接")
			}
			return 0, relayLost, err
		}
		switch {
		case m.Code != nil:
			return *m.Code, relayExited, nil
		case m.Err != "":
			return 1, relayLost, errors.New(m.Err)
		case m.D != "":
			if b, err := base64.StdEncoding.DecodeString(m.D); err == nil {
				alt.Feed(b)
				_, _ = out.Write(b)
			}
		}
	}
}

func printMirrorList(list []clientMirrorInfo) {
	if len(list) == 0 {
		fmt.Printf("（没有镜像终端——用 %s <名字> [命令] 开一个）\n", mirrorProg())
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "名字\t尺寸\t接入数\t最近活动\t目录\t命令")
	for _, t := range list {
		cmd := t.Cmd
		if cmd == "" {
			cmd = "(登录 shell)"
		}
		last := t.LastIO
		if ts, err := time.Parse(time.RFC3339, t.LastIO); err == nil {
			last = time.Since(ts).Round(time.Second).String() + "前"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%dx%d\t%d\t%s\t%s\t%s\n", t.Name, t.Cols, t.Rows, t.Attached, last, t.Cwd, cmd)
	}
	_ = tw.Flush()
}

func mirrorUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s — 本机的「可接力」终端

  %[1]s                  列出所有镜像
  %[1]s ls -q            探针：有活镜像退出 0，否则 1（脚本/rc 钩子用）
  %[1]s <名字> [命令]    接入该镜像；不存在就新建（无命令 = 登录 shell）
  %[1]s kill <名字>      终结该镜像（杀掉里面的进程）
  %[1]s setup [名字]     打印/写入 shell 启动文件的「可接力」钩子
                       --write 写进 rc/profile；带名字则自动接入它，不带只提醒

接入后按 Ctrl-\ 或行首 ~.（ssh 同款逃逸）脱离，进程继续跑；之后从
本机或 SSH 上来（直连 sshd 或经 towstrap 都行）再跑同样命令就能接回。
Windows 上 Ctrl-\ 可能被终端/管道吃掉，吃不掉的是 ~.。

  --sock 地址   覆盖通道地址（unix 默认 mirror.sock；Windows 默认
                \\.\pipe\towstrap-mirror-<owner>；环境变量
                TOWSTRAP_MIRROR_SOCK 也行）
`, mirrorProg())
}
