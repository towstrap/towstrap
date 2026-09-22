package client

import "github.com/towstrap/towstrap/internal/notify"

// systemNotify 把会话事件广而告之：桌面通知 + wall 广播到所有已登录终端。
func systemNotify(title, body string) {
	notify.Desktop(title, body)
	notify.Wall(title + "：" + body)
}
