// Package scripts 把一键安装脚本嵌进 towstrap-server 二进制，
// 服务器在 /install.sh、/install.ps1 上按自己的地址渲染后下发。
package scripts

import (
	"bytes"
	"embed"
)

//go:embed install.sh install.ps1
var FS embed.FS

// marker 是脚本里服务器地址的占位符：下发时被替换成这台服务器的 ws(s)
// 地址；从 GitHub raw 直接拉的脚本里它原样保留，用户必须显式传地址。
const marker = "__TOWSTRAP_DEFAULT_SERVER__"

func mustRead(name string) []byte {
	b, err := FS.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

// render 把脚本里的地址占位符换成 serverURL（wss://...）。
func render(name, serverURL string) []byte {
	return bytes.ReplaceAll(mustRead(name), []byte(marker), []byte(serverURL))
}

// InstallSH 返回 unix 安装脚本，serverURL 填进默认服务器地址。
func InstallSH(serverURL string) []byte { return render("install.sh", serverURL) }

// InstallPS1 返回 Windows 安装脚本。
func InstallPS1(serverURL string) []byte { return render("install.ps1", serverURL) }
