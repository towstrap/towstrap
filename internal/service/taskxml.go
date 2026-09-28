package service

import (
	"fmt"
	"strings"
)

// Windows 计划任务的两段模板，放在无 build tag 的文件里是为了能在
// 非 Windows 机器上跑单测。install.ps1 里有同逻辑的 PowerShell 副本，
// 改这里时两边要一起改。

// taskXML 渲染 schtasks /create /xml 吃的任务定义：
//   - LogonTrigger 钉住 UserId——只在「这个用户」登录时触发，避免别人
//     登录同一台机器时把 agent 拉成别人身份；
//   - RestartOnFailure——进程异常退出（崩溃/panic）30 秒后自拉起，
//     最多 999 次。普通的 schtasks /create /tr 没有等价开关；
//   - ExecutionTimeLimit PT0S——永不掐表。计划任务默认 3 天强杀，
//     不设的话常驻 agent 跑满 72 小时必被砍；
//   - 动作是 wscript 跑 runVBS 生成的隐藏启动器，而不是直接跑 exe——
//     InteractiveToken 下直接跑控制台程序会把一个 cmd 窗口钉在用户
//     桌面上，用户一关窗口 agent 就没了。
func taskXML(o Opts, vbsPath, runUser string) string {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n")
	b.WriteString("<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n")
	b.WriteString("  <RegistrationInfo><Description>TowStrap " + o.Name + "</Description></RegistrationInfo>\n")
	b.WriteString("  <Triggers>\n    <LogonTrigger>\n      <Enabled>true</Enabled>\n")
	if runUser != "" {
		b.WriteString("      <UserId>" + xmlEsc(runUser) + "</UserId>\n")
	}
	b.WriteString("    </LogonTrigger>\n  </Triggers>\n")
	b.WriteString("  <Principals>\n    <Principal id=\"Author\">\n" +
		"      <LogonType>InteractiveToken</LogonType>\n" +
		"      <RunLevel>LeastPrivilege</RunLevel>\n" +
		"    </Principal>\n  </Principals>\n")
	b.WriteString("  <Settings>\n" +
		"    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>\n" +
		"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n" +
		"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n" +
		"    <AllowHardTerminate>true</AllowHardTerminate>\n" +
		"    <StartWhenAvailable>true</StartWhenAvailable>\n" +
		"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n" +
		"    <AllowStartOnDemand>true</AllowStartOnDemand>\n" +
		"    <Enabled>true</Enabled>\n" +
		"    <Hidden>true</Hidden>\n" +
		"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n" +
		"    <WakeToRun>false</WakeToRun>\n" +
		"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n" +
		"    <Priority>7</Priority>\n" +
		"    <RestartOnFailure>\n      <Interval>PT30S</Interval>\n      <Count>999</Count>\n    </RestartOnFailure>\n" +
		"  </Settings>\n")
	b.WriteString("  <Actions Context=\"Author\">\n    <Exec>\n" +
		"      <Command>C:\\Windows\\System32\\wscript.exe</Command>\n" +
		"      <Arguments>\"" + xmlEsc(vbsPath) + "\"</Arguments>\n" +
		"    </Exec>\n  </Actions>\n</Task>\n")
	return b.String()
}

// runVBS 渲染隐藏启动器：wscript（GUI 程序，本身不产窗口）用窗口样式 0
// 起 cmd 重定向 stdout/stderr 到日志文件，并同步等待把退出码透传回去——
// 这样 agent 崩了任务才算「失败」，RestartOnFailure 才接得上。
// vbs 里路径只可能含双引号不允许的字符（Windows 文件名禁 "），所以直接
// 用 Chr(34) 拼引号不用转义。
func runVBS(o Opts, logPath string) string {
	var cmdline strings.Builder
	cmdline.WriteString("cmd /c \"\"" + o.Exe + "\"")
	for _, a := range o.args() {
		cmdline.WriteString(" \"" + a + "\"")
	}
	cmdline.WriteString(" >> \"" + logPath + "\" 2>&1\"")
	return fmt.Sprintf(`' TowStrap %s 计划任务隐藏启动器：wscript 没有控制台，用窗口样式 0
' 起 cmd 把输出重进日志——直接让任务跑控制台程序会在桌面留一个关不得的窗口。
' 同步等待并把退出码透传回去，agent 崩了 RestartOnFailure 才知道要拉。
q = Chr(34)
cmdline = %s
Set sh = CreateObject("WScript.Shell")
WScript.Quit sh.Run(cmdline, 0, True)
`, o.Name, vbsStr(cmdline.String()))
}

// vbsStr 把任意字符串变成 VBS 双引号字面量（内嵌 " 变 ""）。
func vbsStr(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
}

// xmlEsc 转义 XML 文本/属性里的五个保留字符。
func xmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;",
		"\"", "&quot;", "'", "&apos;")
	return r.Replace(s)
}
