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

// Windows 常驻委托给 towstrap service install：管理员权限走 SCM 服务，
// 非管理员退回计划任务（XML 定义的细节由 internal/service 和
// taskxml_test 钉住）。脚本侧要钉的是：① 确实调了 service install；
// ② 没 token 时用 --no-start 只注册不启动；③ 升级覆盖前会把已注册
// 的 SCM 服务停掉（不停 Move-Item 撞文件锁）。
func TestInstallPS1TaskDefinition(t *testing.T) {
	ps := string(mustRead("install.ps1"))
	for _, want := range []string{
		"service install --config $agentyaml",
		"service install --config $agentyaml --no-start",
		"sc.exe stop towstrap",
		"sc.exe start towstrap",
		"schtasks /end /tn towstrap",
	} {
		if !strings.Contains(ps, want) {
			t.Errorf("install.ps1 缺 %q", want)
		}
	}
}
