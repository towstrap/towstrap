// Package notify 提供系统级提醒：桌面通知 + wall 广播到所有已登录终端。
// 全部 best-effort——发不出去（headless 机器、没装 notify-send、通知权限没批）
// 也不影响调用方；审计日志才是保底。agent 的会话通知和 towstrap-mcp 的
// 本地批准提醒共用这套。
package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Clean 剥掉能折腾终端的控制字符：ESC、C1 序列起点、回车/退格这类
// 行内覆盖符、Unicode 行分隔符；保住换行和制表——审批通知本来就分行
// 排版。凡是把命令文本这类不可信内容打进终端/对话框的路径都过它，
// 不然一条精心构造的命令名能在别人终端上画出假提示。
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029:
			return -1
		}
		return r
	}, s)
}

// Desktop 发一条桌面通知（macOS 用 osascript，Linux 用 notify-send）。
func Desktop(title, body string) {
	title, body = Clean(title), Clean(body)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "osascript", "-e",
			fmt.Sprintf("display notification %s with title %s", quoteApple(body), quoteApple(title)))
	case "linux":
		cmd = exec.CommandContext(ctx, "notify-send", "-a", "towstrap", "-u", "critical", "--", title, body)
	default:
		return
	}
	_ = cmd.Run()
}

// Answer 是批准对话框的三选一结果。
type Answer int

const (
	Deny          Answer = iota // 点了拒绝/取消
	Allow                       // 允许这一次
	AllowRemember               // 允许且本会话内相同命令不再问
)

// rememberLabel 是「记住」按钮的文字，macOS/CLI/审计共用同一说法。
const rememberLabel = "允许并不再问"

// Confirm 弹一个真的能点的系统对话框（本地批准用）：拒绝/允许/允许并不再问。
// 返回 answered=false 表示弹不了（没图形界面、没装 zenity、对话框自己超时
// 没人点），调用方退到普通通知。ctx 取消会杀掉对话框进程。
func Confirm(ctx context.Context, title, body string, givingUp time.Duration) (Answer, bool) {
	title, body = Clean(title), Clean(body)
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("osascript"); err != nil {
			return Deny, false
		}
		secs := int(givingUp.Seconds())
		if secs <= 0 {
			secs = 300
		}
		out, err := exec.CommandContext(ctx, "osascript", "-e",
			fmt.Sprintf(`display dialog %s with title %s buttons {"拒绝","允许",%s} `+
				`default button "允许" cancel button "拒绝" giving up after %d`,
				quoteApple(body), quoteApple(title), quoteApple(rememberLabel), secs)).Output()
		if err != nil {
			if ctx.Err() != nil {
				return Deny, false // 调用方先结束了（别处已批准/超时），不算答复
			}
			// 弹不出来的失败绝不能当成「拒绝」，只认明确的取消动作
			var ee *exec.ExitError
			if errors.As(err, &ee) && bytes.Contains(ee.Stderr, []byte("User canceled")) {
				return Deny, true // cancel button → osascript 报 -128
			}
			return Deny, false
		}
		s := string(out)
		if strings.Contains(s, "gave up:true") {
			return Deny, false // 对话框自己超时没人点——别替用户表态
		}
		if strings.Contains(s, "button returned:"+rememberLabel) {
			return AllowRemember, true
		}
		return Allow, true
	case "linux":
		// 没图形会话时 zenity 会以 exit 1 报错（和「点了取消」同码），
		// 必须先确认有 DISPLAY/WAYLAND，否则「弹不了」会被误当拒绝。
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return Deny, false
		}
		if _, err := exec.LookPath("zenity"); err != nil {
			return Deny, false
		}
		args := []string{"--question",
			"--title=" + title, "--text=" + body,
			"--ok-label=允许", "--cancel-label=拒绝",
			"--extra-button=" + rememberLabel,
			fmt.Sprintf("--timeout=%d", int(givingUp.Seconds()))}
		out, err := exec.CommandContext(ctx, "zenity", args...).Output()
		if err != nil {
			var ee *exec.ExitError
			// 老 zenity 没有 --extra-button（报 Unknown option）——退成两钮再问一次
			if errors.As(err, &ee) && bytes.Contains(ee.Stderr, []byte("extra-button")) {
				args = []string{"--question",
					"--title=" + title, "--text=" + body,
					"--ok-label=允许", "--cancel-label=拒绝",
					fmt.Sprintf("--timeout=%d", int(givingUp.Seconds()))}
				out, err = exec.CommandContext(ctx, "zenity", args...).Output()
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return Deny, false
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 1 {
				return Deny, true // zenity exit 1 = 点了取消；5 = 超时没人点
			}
			return Deny, false
		}
		// 点了 --extra-button：zenity 把按钮文字打到 stdout、exit 0；
		// 点 ok 也是 exit 0 但 stdout 为空。
		if strings.TrimSpace(string(out)) == rememberLabel {
			return AllowRemember, true
		}
		return Allow, true
	default:
		return Deny, false
	}
}

// Wall 用 wall(1) 广播：headless 多用户机器上桌面通知到不了，
// 登录着的终端总能看到。
func Wall(msg string) {
	msg = Clean(msg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wall")
	cmd.Stdin = strings.NewReader(msg + "\n")
	_ = cmd.Run()
}

// quoteApple 转成 AppleScript 字符串字面量（转义反斜杠和双引号；换行转成
// \n 转义序列，AppleScript 解释成换行——直接放裸换行进源码也能跑，
// 但转义形式更稳）。
func quoteApple(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}
