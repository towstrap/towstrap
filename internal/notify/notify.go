// Package notify 提供系统级提醒：桌面通知 + wall 广播到所有已登录终端。
// 全部 best-effort——发不出去（headless 机器、没装 notify-send、通知权限没批）
// 也不影响调用方；审计日志才是保底。agent 的会话通知和 ws2ssh-mcp 的
// 本地批准提醒共用这套。
package notify

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Desktop 发一条桌面通知（macOS 用 osascript，Linux 用 notify-send）。
func Desktop(title, body string) {
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

// Wall 用 wall(1) 广播：headless 多用户机器上桌面通知到不了，
// 登录着的终端总能看到。
func Wall(msg string) {
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
