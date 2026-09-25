// Package scripts 把一键安装脚本嵌进 towstrap-server 二进制，
// 服务器在 /install.sh、/install.ps1 上按自己的地址渲染后下发。
package scripts

import (
	"bytes"
	"embed"
	"regexp"
	"strings"

	"github.com/towstrap/towstrap/internal/version"
)

//go:embed install.sh install.ps1
var FS embed.FS

// marker 是脚本里服务器地址的占位符：下发时被替换成这台服务器的 ws(s)
// 地址；从 GitHub raw 直接拉的脚本里它原样保留，脚本运行时回落到官方
// 服务器（wss://towstrap.vast-plan.com），自建才需要显式传地址。
const marker = "__TOWSTRAP_DEFAULT_SERVER__"

// versionMarker 是脚本里默认版本的占位符：下发时被替换成这台服务器的
// release tag（如 v0.3.0）——从哪台服务器拉的脚本就装和它同版本的 agent；
// GitHub raw 拉的脚本里原样保留，运行时回落到 latest。
const versionMarker = "__TOWSTRAP_DEFAULT_VERSION__"

var releaseTagRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// ReleaseTag 把 version.Version 换成 GitHub release tag：干净的 semver
// 加 v 前缀（0.3.0 → v0.3.0）；dev 之类不是版本号的落到 latest。
func ReleaseTag() string {
	v := version.Version
	if i := strings.IndexByte(v, ' '); i >= 0 {
		v = v[:i]
	}
	if !releaseTagRe.MatchString(v) {
		return "latest"
	}
	return "v" + v
}

func mustRead(name string) []byte {
	b, err := FS.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

// render 把脚本里的地址占位符换成 serverURL（wss://...）、版本占位符换成
// 这台服务器的 release tag。
func render(name, serverURL string) []byte {
	b := bytes.ReplaceAll(mustRead(name), []byte(marker), []byte(serverURL))
	return bytes.ReplaceAll(b, []byte(versionMarker), []byte(ReleaseTag()))
}

// InstallSH 返回 unix 安装脚本，serverURL 填进默认服务器地址。
func InstallSH(serverURL string) []byte { return render("install.sh", serverURL) }

// InstallPS1 返回 Windows 安装脚本。
func InstallPS1(serverURL string) []byte { return render("install.ps1", serverURL) }
