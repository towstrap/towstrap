//go:build !windows

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/towstrap/towstrap/internal/client"
	"github.com/towstrap/towstrap/internal/proto"
)

// towstrap mirror：本机接入镜像终端的客户端。连 agent 的 mirror.sock，
// NDJSON 协议（见 internal/client/mirrorsock_unix.go）。install.sh 会把
// towstrap 软链成 mirror——以那个名字调起时 main() 直接进这里，
// 所以日常敲的是 `mirror ls` / `mirror work`，不用带 agent 字样。
//
//   mirror                 列出所有镜像
//   mirror work            接入 work；不存在就以登录 shell 新建
//   mirror work vim a.go   接入 work；不存在就以该命令新建
//   mirror kill work       终结 work（镜像里的进程被杀）
//
// 接入后按 Ctrl-\ 脱离——镜像里的进程继续跑，下次同名接入接着用。
// 套在 ssh/mosh 里也能用：ssh -t 机器 mirror work。

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

func runMirror(args []string) int {
	fs := flag.NewFlagSet(mirrorProg(), flag.ExitOnError)
	sock := fs.String("sock", "", "mirror socket 路径（默认环境变量 TOWSTRAP_MIRROR_SOCK，再默认审计日志同目录的 mirror.sock）")
	_ = fs.Parse(args)
	rest := fs.Args()

	path := *sock
	if path == "" {
		path = os.Getenv("TOWSTRAP_MIRROR_SOCK")
	}
	if path == "" {
		path = client.DefaultMirrorSockPath()
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

	c, err := net.DialTimeout("unix", path, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "连不上 mirror socket %s：%v（agent 没在跑？或被删了）\n", path, err)
		return 1
	}
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
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
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
	fmt.Fprintf(os.Stderr, "[towstrap] Ctrl-\\ 脱离（进程继续跑）；镜像内程序退出即结束\n")

	old, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "切终端原始模式失败:", err)
		return 1
	}
	restore := func() { _ = term.Restore(int(os.Stdin.Fd()), old) }
	defer restore()

	// 被杀（ssh 断了收到 HUP/TERM）时也要恢复终端模式，不然父终端留 raw。
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		restore()
		os.Exit(1)
	}()

	// 窗口变化和按键两个协程都往同一条连接写：send 加锁，一行一行不串。
	var encMu sync.Mutex
	send := func(m mirrorMsg) error {
		encMu.Lock()
		defer encMu.Unlock()
		return enc.Encode(m)
	}

	// 窗口变化 → 通知镜像改尺寸（里面的程序收 SIGWINCH 重绘）
	winCh := make(chan os.Signal, 4)
	signal.Notify(winCh, syscall.SIGWINCH)
	defer signal.Stop(winCh)
	go func() {
		for range winCh {
			if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 && h > 0 {
				_ = send(mirrorMsg{Cols: w, Rows: h})
			}
		}
	}()

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

type relayEnd int

const (
	relayExited   relayEnd = iota // 收到退出码：镜像里的程序结束了
	relayDetached                 // 本端按了 Ctrl-\
	relayLost                     // 连接断开或 agent 回了错误
)

// relayMirror 接入后的双向搬运：in 的按键送进镜像（扫到 Ctrl-\ 就脱离，
// 它前面同一批的按键照样送出），镜像的输出写到 out 并喂给 alt 跟踪备用
// 屏幕。返回退出码（relayExited 时有意义）、结束方式和断开原因。
func relayMirror(dec *json.Decoder, send func(mirrorMsg) error, in io.Reader, out io.Writer, alt *client.AltScreen) (int, relayEnd, error) {
	detached := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := in.Read(buf)
			if i := bytes.IndexByte(buf[:n], detachKey); i >= 0 {
				if i > 0 {
					_ = send(mirrorMsg{D: base64.StdEncoding.EncodeToString(buf[:i])})
				}
				// 先标记再发：服务端收到 detach 就断连，读循环看到断开时
				// 这边一定已经是「脱离」状态
				close(detached)
				_ = send(mirrorMsg{Op: "detach"})
				return
			}
			if n > 0 {
				if send(mirrorMsg{D: base64.StdEncoding.EncodeToString(buf[:n])}) != nil {
					return
				}
			}
			if err != nil {
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
                       --write 写进 rc；带名字则自动接入它，不带只提醒

接入后按 Ctrl-\ 脱离，进程继续跑；之后从本机或 SSH 上来（直连 sshd
或经 towstrap 都行）再跑同样命令就能接回。
（mirror 是 towstrap 的软链别名；install.sh 装好就有，
 没有的话完整写法是 towstrap mirror）

  --sock 路径   覆盖 socket 位置（默认 ~/.towstrap/mirror.sock 或
                /var/lib/towstrap/mirror.sock，环境变量 TOWSTRAP_MIRROR_SOCK 也行）
`, mirrorProg())
}
