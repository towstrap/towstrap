// Package service 把 towstrap agent / towstrap-server 注册成系统常驻
// 服务：launchd（macOS）/ systemd（Linux）/ 计划任务（Windows）。
// 等价 install.sh 的服务注册段——给「二进制已就位、当时没走安装脚本」
// 的机器补票：towstrap service install 一条命令变成开机自启/掉线自拉。
//
// 每个平台文件各自实现 install/uninstall/status 三个入口。
package service

// Opts 描述要注册的服务。
type Opts struct {
	Name       string // "agent" / "server"——决定单元名（towstrap / towstrap-server）和 darwin label
	Exe        string // 要跑的二进制绝对路径
	ConfigPath string // --config 传给二进制的配置文件
	// SysUser 是 root 安装时跑服务的账号名：linux 用原名，darwin 自动加
	// "_" 前缀（macOS 系统账号约定）。空 = 服务以 root 跑。
	SysUser string
	// ProtectHome 给 systemd 单元加 ProtectHome=true（server 用——
	// 库文件之外的家目录对服务进程不可见）。
	ProtectHome bool
	// NoStart 只写服务定义不启动：install 脚本在还没拿到 token 时先
	// 注册占位，register 拿到凭据后再拉起（tryStartPendingService）。
	NoStart bool
}

// unitName 是 systemd 单元和计划任务名：agent→towstrap，server→towstrap-server。
func (o Opts) unitName() string {
	if o.Name == "agent" {
		return "towstrap"
	}
	return "towstrap-" + o.Name
}

// label 是 launchd 的服务标识。
func (o Opts) label() string { return "com.towstrap." + o.Name }

func (o Opts) args() []string {
	if o.ConfigPath == "" {
		return nil
	}
	return []string{"--config", o.ConfigPath}
}

// Install 写服务定义并启用启动；已装过等价于重装（重启生效新二进制）。
// 返回一句「做了什么」的说明文本。
func Install(o Opts) (string, error) { return install(o) }

// Uninstall 停用并删掉服务定义（二进制和配置不动）。
func Uninstall(o Opts) (string, error) { return uninstall(o) }

// Status 报告服务现在的状态（一行人能看懂的话）。
func Status(o Opts) string { return status(o) }
