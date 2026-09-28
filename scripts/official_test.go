package scripts

import (
	"strings"
	"testing"

	"github.com/towstrap/towstrap/internal/proto"
)

// 安装脚本里的官方服务器字面值必须和 proto.OfficialServer 一致——脚本是
// 独立文件没法共享 Go 常量，靠这个测试防止两处漂移。
func TestScriptsOfficialServer(t *testing.T) {
	sh := string(mustRead("install.sh"))
	if !strings.Contains(sh, `OFFICIAL_SERVER="`+proto.OfficialServer+`"`) {
		t.Fatal("install.sh 的 OFFICIAL_SERVER 与 proto.OfficialServer 不一致")
	}
	ps := string(mustRead("install.ps1"))
	if !strings.Contains(ps, `$OfficialServer = "`+proto.OfficialServer+`"`) {
		t.Fatal("install.ps1 的 $OfficialServer 与 proto.OfficialServer 不一致")
	}
	// SHA256SUMS 在 GitHub Releases 上是 application/octet-stream：
	// Windows PowerShell 5.1 的 .Content 拿到 byte[]，不显式解 UTF-8
	// 的话后面按行匹配会全落空（报"清单里没有这一行"）。钉住解码。
	if !strings.Contains(ps, `[byte[]]) { [Text.Encoding]::UTF8.GetString(`) {
		t.Fatal("install.ps1 没了 SHA256SUMS 的 byte[]→UTF8 解码")
	}
}

// Windows 常驻靠计划任务，XML 里三个开关是常驻 agent 的命门，少了哪个
// 都会翻车：没有 RestartOnFailure 进程死了没人拉；ExecutionTimeLimit
// 不设回 PT0S 会被默认 3 天强杀；不经 wscript 启动器直接跑 exe 会把
// 控制台窗口钉在用户桌面（关窗口=杀 agent）。钉住这套定义。
func TestInstallPS1TaskDefinition(t *testing.T) {
	ps := string(mustRead("install.ps1"))
	for _, want := range []string{
		"schtasks /create /tn towstrap /xml",
		"<RestartOnFailure>",
		"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
		"wscript.exe</Command>",
		"towstrap-run.vbs",
		"<UserId>",
		"StopExisting",
	} {
		if !strings.Contains(ps, want) {
			t.Errorf("install.ps1 任务定义缺 %q", want)
		}
	}
}
