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
}
