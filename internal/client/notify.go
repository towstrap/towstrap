package client

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// systemNotify 把会话事件广而告之：桌面通知 + wall 广播到所有已登录终端。
// 全部 best-effort——发不出去（headless 机器、没装 notify-send、通知权限没批）
// 也不影响会话本身；审计日志才是保底。
func systemNotify(title, body string) {
	notifyDesktop(title, body)
	wallBroadcast(title + "：" + body)
}

func notifyDesktop(title, body string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "osascript", "-e",
			fmt.Sprintf("display notification %s with title %s", quoteApple(body), quoteApple(title)))
	case "linux":
		cmd = exec.CommandContext(ctx, "notify-send", "-a", "ws2ssh", "-u", "critical", "--", title, body)
	default:
		return
	}
	_ = cmd.Run()
}

// wallBroadcast 用 wall(1) 广播：headless 多用户机器上桌面通知到不了，
// 登录着的终端总能看到。
func wallBroadcast(msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wall")
	cmd.Stdin = strings.NewReader(msg + "\n")
	_ = cmd.Run()
}

// quoteApple 转成 AppleScript 字符串字面量（转义反斜杠和双引号）。
func quoteApple(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
