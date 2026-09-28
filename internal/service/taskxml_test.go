package service

import (
	"strings"
	"testing"
)

func TestTaskXML(t *testing.T) {
	o := Opts{Name: "agent", Exe: `C:\Users\李雷\TowStrap\towstrap.exe`,
		ConfigPath: `C:\Users\李雷\TowStrap\agent.yaml`}
	vbs := `C:\Users\李雷\.towstrap\towstrap-run.vbs`
	x := taskXML(o, vbs, `DESKTOP-1\李雷`)

	for _, want := range []string{
		"<UserId>DESKTOP-1\\李雷</UserId>",       // 只在本账号登录时触发
		"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", // 永不掐表（默认 3 天强杀）
		"<RestartOnFailure>",                      // 崩溃自拉起
		"<Interval>PT30S</Interval>",
		"<MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>",
		"C:\\Windows\\System32\\wscript.exe", // 动作是 wscript 隐藏启动器
		`towstrap-run.vbs"`,                  // vbs 路径进 Arguments
		"InteractiveToken",                   // 等价 /rl limited
	} {
		if !strings.Contains(x, want) {
			t.Errorf("任务定义缺 %q", want)
		}
	}
	// 直接跑 exe 的路不该出现（会钉一个关不得的控制台窗口）
	if strings.Contains(x, "towstrap.exe") {
		t.Error("任务定义不该直接跑 towstrap.exe")
	}
}

func TestRunVBS(t *testing.T) {
	o := Opts{Name: "agent", Exe: `C:\TowStrap\towstrap.exe`,
		ConfigPath: `C:\TowStrap\agent.yaml`}
	v := runVBS(o, `C:\Users\x\.towstrap\towstrap.log`)

	// 文件里存的是 VBS 字面量（引号翻倍）；解码回运行时 cmdline 再比对。
	var line string
	for _, l := range strings.Split(v, "\n") {
		if strings.HasPrefix(l, "cmdline = ") {
			line = strings.TrimSpace(strings.TrimPrefix(l, "cmdline = "))
		}
	}
	if !strings.HasPrefix(line, "\"") || !strings.HasSuffix(line, "\"") {
		t.Fatalf("cmdline 不是 vbs 字面量：%q", line)
	}
	got := strings.ReplaceAll(line[1:len(line)-1], "\"\"", "\"")
	want := `cmd /c ""C:\TowStrap\towstrap.exe" "--config" "C:\TowStrap\agent.yaml" >> "C:\Users\x\.towstrap\towstrap.log" 2>&1"`
	if got != want {
		t.Fatalf("cmdline 跑出来的命令不对：\n got %s\nwant %s", got, want)
	}
	for _, kw := range []string{"sh.Run(", "True", "WScript.Quit"} {
		if !strings.Contains(v, kw) {
			t.Errorf("启动器缺 %q", kw)
		}
	}
}

func TestVbsStr(t *testing.T) {
	if got := vbsStr(`a"b`); got != `"a""b"` {
		t.Fatalf("vbsStr 转义错了：%q", got)
	}
}
