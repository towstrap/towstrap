package client

import "github.com/towstrap/towstrap/internal/notify"

// systemNotify 把会话事件广而告之：桌面横幅通知。不往终端里写字节
// （wall 会画花 vim/top 这类 TUI 的屏幕）。
func systemNotify(title, body string) {
	notify.Desktop(title, body)
}
