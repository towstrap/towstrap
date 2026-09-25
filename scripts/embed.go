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

//go:embed install.sh install.ps1 install-server.sh
var FS embed.FS

// marker 是脚本里服务器地址的占位符：下发时被替换成这台服务器的 ws(s)
// 地址；从 GitHub raw 直接拉的脚本里它原样保留，脚本运行时回落到官方
// 服务器（wss://towstrap.vast-plan.com），自建才需要显式传地址。
const marker = "__TOWSTRAP_DEFAULT_SERVER__"

// versionMarker 是脚本里默认版本的占位符：下发时被替换成这台服务器的
// release tag（如 v0.3.0）——从哪台服务器拉的脚本就装和它同版本的 agent；
// GitHub raw 拉的脚本里原样保留，运行时回落到 latest。
const versionMarker = "__TOWSTRAP_DEFAULT_VERSION__"

// agentConfMarker 是脚本里 agent.yaml 预设片段的占位符：下发时被替换成
// server.yaml 里 agent_defaults: 渲染出的行（没配就是空）；GitHub raw
// 拉的脚本里原样保留，运行时按空处理。
const agentConfMarker = "__TOWSTRAP_AGENT_CONFIG__"

// sshPortMarker 是脚本结尾 SSH 提示里端口号的占位符：下发时替换成这台
// 服务器配置的 SSH 端口；GitHub raw 拉的脚本保留原样，运行时回落默认
// 端口 7822。
const sshPortMarker = "__TOWSTRAP_SSH_PORT__"

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

// render 把脚本里的占位符按这台服务器填好：地址 serverURL（wss://...）、
// 版本 release tag、agent.yaml 预设片段、SSH 端口。
func render(name, serverURL, agentConf, sshPort string) []byte {
	b := bytes.ReplaceAll(mustRead(name), []byte(marker), []byte(serverURL))
	b = bytes.ReplaceAll(b, []byte(versionMarker), []byte(ReleaseTag()))
	b = bytes.ReplaceAll(b, []byte(agentConfMarker), []byte(agentConf))
	return bytes.ReplaceAll(b, []byte(sshPortMarker), []byte(sshPort))
}

// InstallSH 返回 unix 安装脚本。agentConf 是写进 agent.yaml 的预设片段
// （可为空），sshPort 是脚本结尾 SSH 提示里显示的端口。
func InstallSH(serverURL, agentConf, sshPort string) []byte {
	return render("install.sh", serverURL, agentConf, sshPort)
}

// InstallPS1 返回 Windows 安装脚本。
func InstallPS1(serverURL, agentConf, sshPort string) []byte {
	return render("install.ps1", serverURL, agentConf, sshPort)
}

// InstallServerSH 返回服务端安装脚本。它完全自包含（版本默认 latest、
// 地址不需要下发——装的是服务器自己），所以不做任何占位符替换，
// 官方服务器下发的和 GitHub raw 拉的是同一份字节。
func InstallServerSH() []byte {
	return mustRead("install-server.sh")
}
