package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/client"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/version"
)

// towstrap status：这台机器上的 agent 跑没跑、连没连上服务器、上次为什么断。
// 三档退出码给脚本用：0 = 在跑且已连上；3 = 在跑但当前没连上（重连中）；
// 1 = 没在跑或查不到。
//
// 数据分三层，越往后越是兜底：
//  1. 本机接入通道（mirror.sock/命名管道）的 status 操作——agent 进程活着
//     才会应答（权威实时态）
//  2. 进程表探测——通道挂了/老版本没 status 时证明进程还在
//  3. 服务管理器与配置文件——没在跑时回答「怎么起」
func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", "", "agent.yaml 路径（默认按安装位置探测）")
	sock := fs.String("sock", "", "mirror 通道地址（默认环境变量/平台约定：mirror.sock 或命名管道）")
	agentToken := fs.String("agent-token", "", "覆盖凭据来源（默认和 agent 同款优先级）")
	tokenFile := fs.String("agent-token-file", "", "覆盖 token 文件路径")
	showToken := fs.Bool("show-token", false, "显示完整 token 值（默认只露头尾）")
	quiet := fs.Bool("q", false, "静默：只给退出码，不打印")
	fs.BoolVar(quiet, "quiet", false, "同 -q")
	_ = fs.Parse(args)

	out := func(format string, a ...any) {
		if !*quiet {
			fmt.Printf(format+"\n", a...)
		}
	}
	out("towstrap %s", version.String())

	// —— 实时态：问本机查询通道（unix socket / Windows 命名管道） ——
	sockPath := *sock
	if sockPath == "" {
		sockPath = os.Getenv("TOWSTRAP_MIRROR_SOCK")
	}
	running, connected := false, false
	var info *client.StatusInfo
	var errReply string
	targets := client.MirrorDialTargets(sockPath)
	// 逐个候选拨：传输层失败换下一个；通了（拿到 status 或协议层拒答都
	// 算应答）就停。Windows 上通常两条候选：自己 SID 的管道 + SYSTEM 服务的。
	for _, t := range targets {
		var err error
		info, errReply, err = client.QueryStatus(t)
		if err == nil || errReply != "" {
			break
		}
	}
	switch {
	case len(targets) == 0:
		out("进程：本机查询通道探测路径推导不出（HOME/SID 取不到；--sock 指定）")
	case info != nil:
		running, connected = true, info.Connected
		out("进程：运行中（pid %d，启动于 %s 前）", info.PID, shortDur(time.Since(info.StartedAt)))
		out("机器：%s    服务器：%s", info.ID, info.Server)
		if info.Connected {
			out("连接：已连上（%s 前握手成功；启动以来共拨号 %d 次）",
				shortDur(time.Since(info.ConnectedAt)), info.Dials)
		} else {
			out("连接：未连接（拨号 %d 次，还在重连）", info.Dials)
			if info.LastErr != "" {
				out("上次断开：%s（%s 前）", info.LastErr, shortDur(time.Since(info.LastErrAt)))
			}
		}
		out("远程会话 %d 个 · 镜像终端 %d 个", info.Sessions, info.Mirrors)
	case errReply != "":
		running = true // 通道应答了 = 进程活着，只是不肯/不会报详情
		out("进程：运行中（查询通道有应答，但查询被拒：%s）", errReply)
	}

	// —— 进程兜底探测：通道不应答时用进程表说话 ——
	if !running {
		if pids := findTowstrapPIDs(); len(pids) > 0 {
			running = true
			out("进程：在跑（pid %s）但本机查询通道不应答——监听失败或版本太老",
				strings.Join(pids, ", "))
		} else {
			out("进程：没在跑")
		}
	}

	// —— 服务管理器 ——
	for _, line := range serviceState() {
		out("%s", line)
	}

	// —— 配置与凭据 ——
	cfgPath := *configPath
	if cfgPath == "" {
		cfgPath = config.DefaultAgentPath()
	}
	var cfg config.Agent
	var cfgErr error
	if cfgPath != "" {
		cfg, cfgErr = config.LoadAgent(cfgPath)
	}
	switch {
	case cfgPath == "":
		out("配置：默认位置推导不出（HOME 未设置？）——--config 指定")
	case cfgErr == nil:
		out("配置：%s（server %s）", cfgPath, orDefault(cfg.Server))
	case *configPath != "":
		out("配置：%s 读不了（%v）", cfgPath, cfgErr)
	default:
		out("配置：%s 不存在（没装过或装在别处；--config 指定）", cfgPath)
	}

	// —— 凭据：解析优先级和 agent 一致，报出来的来源就是它实际用的。
	// 值默认遮中段只露头尾；要完整值加 --show-token。
	tok, tokSource, _, tokErr := resolveAgentToken(*agentToken, *tokenFile,
		os.Getenv("TOWSTRAP_AGENT_TOKEN"), cfg.AgentToken, cfg.AgentTokenFile)
	switch {
	case tokErr != nil:
		out("凭据：agent token 缺失——%v", tokErr)
	case *showToken:
		// 完整 token 打印到终端是能直接拿去连服务器的凭据——写一条
		// 审计，事后能查「谁在什么时候亮过 token」。
		auditlog.Open(client.DefaultAuditPath(), 0).Log("SHOW-TOKEN", "source", tokSource)
		out("凭据：agent token %s（来源：%s）", tok, tokSource)
	default:
		out("凭据：agent token %s（来源：%s）", proto.MaskToken(tok), tokSource)
	}
	out("说明：这是 agent 连服务器用的 token（tsa-）。AI 客户端走 MCP 用的是另一套 tsm- token，")
	out("      在服务器上 towstrap-server mcp add 签发——两套凭据互不相干，agent 不需要 tsm-。")

	// —— 收尾：没在跑时给启动指引 ——
	if !running {
		if cfgErr == nil {
			out("启动：towstrap   （会自动用这个配置；或装成服务常驻，见安装说明）")
		} else {
			out("启动：先安装并写入 agent.yaml，或 towstrap --server wss://... --agent-token-file <文件>")
		}
	}
	switch {
	case !running:
		return 1
	case !connected:
		return 3
	}
	return 0
}

func orDefault(s string) string {
	if s == "" {
		return "默认官方"
	}
	return s
}

// shortDur 把时长收成「3 小时」「2 分钟」这种一眼懂的粒度。
func shortDur(d time.Duration) string {
	switch {
	case d < time.Second:
		return "不到 1 秒"
	case d < time.Minute:
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时", int(d.Hours()))
	}
	return fmt.Sprintf("%d 天", int(d.Hours()/24))
}

// findTowstrapPIDs 进程表兜底：socket 挂了时确认 towstrap 进程还在。
// 排除自己——status 命令本身就跑在 towstrap 二进制里。
func findTowstrapPIDs() []string {
	self := strconv.Itoa(os.Getpid())
	var pids []string
	if runtime.GOOS == "windows" {
		b, err := exec.Command("tasklist", "/FI", "IMAGENAME eq towstrap.exe",
			"/FO", "CSV", "/NH").Output()
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(strings.TrimSpace(line), ",")
			if len(f) < 2 {
				continue
			}
			pid := strings.Trim(f[1], `"`)
			if pid != "" && pid != self {
				pids = append(pids, pid)
			}
		}
		return pids
	}
	b, err := exec.Command("pgrep", "-x", "towstrap").Output()
	if err != nil {
		return nil
	}
	for _, pid := range strings.Fields(string(b)) {
		if pid != self {
			pids = append(pids, pid)
		}
	}
	return pids
}

// serviceState 查各平台服务管理器里 towstrap 的安装/运行状态，
// 一行一条事实，查不到就不出那一行。
func serviceState() []string {
	var out []string
	switch runtime.GOOS {
	case "linux":
		// 系统级 + 用户级两格都查：装成哪个取决于当时是不是 root。
		if _, err := exec.LookPath("systemctl"); err == nil {
			out = append(out, systemdState("系统服务", "systemctl")...)
			out = append(out, systemdState("用户服务", "systemctl", "--user")...)
		}
	case "darwin":
		uid := strconv.Itoa(os.Getuid())
		label := "com.towstrap.agent"
		userPlist := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", label+".plist")
		daemonPlist := "/Library/LaunchDaemons/" + label + ".plist"
		if exec.Command("launchctl", "print", "gui/"+uid+"/"+label).Run() == nil {
			out = append(out, "服务：launchd 用户项已加载（gui/"+uid+"/"+label+"）")
		} else if _, err := os.Stat(userPlist); err == nil {
			out = append(out, "服务：LaunchAgent 已写未加载（"+userPlist+
				"）——加载：launchctl bootstrap gui/"+uid+" "+userPlist)
		}
		if exec.Command("launchctl", "print", "system/"+label).Run() == nil {
			out = append(out, "服务：launchd 守护已加载（system/"+label+"）")
		} else if _, err := os.Stat(daemonPlist); err == nil {
			out = append(out, "服务：LaunchDaemon 已写未加载（"+daemonPlist+
				"）——加载：sudo launchctl bootstrap system "+daemonPlist)
		}
	case "windows":
		// SCM 服务（管理员装法）：sc query 拿到 STATE 行就报。计划任务
		// 是非管理员装法的退路，两种形态可能并存过但只能有一个在跑。
		if b, err := exec.Command("sc", "query", "towstrap").Output(); err == nil {
			state := "已注册"
			if bytes.Contains(b, []byte("RUNNING")) {
				state = "在跑"
			} else if bytes.Contains(b, []byte("STOPPED")) {
				state = "已停"
			}
			out = append(out, "服务：Windows 服务 towstrap "+state)
		}
		if exec.Command("schtasks", "/query", "/tn", "towstrap").Run() == nil {
			out = append(out, "服务：计划任务 towstrap 已注册")
		}
	}
	return out
}

// systemdState 一条 systemctl 探测的结果：装没装、启没启用、跑没跑。
func systemdState(name string, args ...string) []string {
	run := func(sub string) bool {
		a := append(append([]string{}, args...), sub, "towstrap")
		return exec.Command(a[0], a[1:]...).Run() == nil
	}
	enabled, active := run("is-enabled"), run("is-active")
	switch {
	case active && enabled:
		return []string{"服务：" + name + " towstrap 已启用且在跑"}
	case active:
		return []string{"服务：" + name + " towstrap 在跑（未启用，重启不自起）"}
	case enabled:
		return []string{"服务：" + name + " towstrap 已启用但当前没跑（systemctl start 拉起）"}
	}
	// 装了但没启用：unit 文件存在但 is-enabled/is-active 都失败
	if run("cat") {
		return []string{"服务：" + name + " towstrap 单元已写，未启用未运行"}
	}
	return nil
}
