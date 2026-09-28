//go:build windows

package service

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// install 注册常驻。agent 在管理员权限下走真·Windows 服务（SCM）：开机
// 自启不用等谁登录、崩溃由服务恢复策略拉起、不占用户桌面窗口。非管理
// 员装不了服务，退回「登录自起」计划任务（XML 定义，带崩溃自拉起和日
// 志）。towstrap-server 二进制没有 SCM 握手，只能走任务。
func install(o Opts) (string, error) {
	if o.Name == "agent" && isElevated() {
		return installService(o)
	}
	return installTask(o)
}

// isElevated 报告当前进程是不是管理员令牌——SCM 的 create/start/stop 都
// 要这个权限，先查再决定走哪条路，比试 sc 命令再猜错误文本可靠。
func isElevated() bool {
	t, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer t.Close()
	return t.IsElevated()
}

// installService 用 SCM 注册服务：binPath 直接指 exe（服务模式下进程自己
// 走 svc.Run 握手）；failure 配崩溃重启（3s/3s/30s，一天一重置）。幂等：
// 老服务先停掉删掉再建，老计划任务顺手删掉——两套常驻会被单实例锁互顶。
func installService(o Opts) (string, error) {
	name := o.unitName()
	if exec.Command("sc.exe", "query", name).Run() == nil {
		_ = exec.Command("sc.exe", "stop", name).Run()
		waitStopped(name)
		if out, err := exec.Command("sc.exe", "delete", name).CombinedOutput(); err != nil {
			return "", fmt.Errorf("已有同名服务删不掉：%s", strings.TrimSpace(string(out)))
		}
	}
	bin := fmt.Sprintf(`"%s"`, o.Exe)
	for _, a := range o.args() {
		bin += fmt.Sprintf(` "%s"`, a)
	}
	for _, args := range [][]string{
		{"create", name, "binPath=", bin, "start=", "auto", "DisplayName=", "TowStrap agent"},
		{"failure", name, "reset=", "86400", "actions=", "restart/3000/restart/3000/restart/30000"},
		{"description", name, "TowStrap agent：远程接入与终端托管"},
	} {
		if out, err := exec.Command("sc.exe", args...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("sc %s 失败：%s", args[0], strings.TrimSpace(string(out)))
		}
	}
	_ = exec.Command("schtasks", "/end", "/tn", name).Run()
	_ = exec.Command("schtasks", "/delete", "/tn", name, "/f").Run()
	if o.NoStart {
		return fmt.Sprintf("服务 %s 已注册为开机自启（未启动，拿到 token 后会拉起）", name), nil
	}
	if out, err := exec.Command("sc.exe", "start", name).CombinedOutput(); err != nil {
		return "", fmt.Errorf("服务已注册但启动失败：%s", strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("服务 %s 已注册并启动（开机自启、崩溃自动重启，日志 C:\\ProgramData\\TowStrap\\towstrap-svc.log）", name), nil
}

// waitStopped 轮询服务状态到 STOPPED——sc stop 只是发出控制码，立即接
// delete/start 会撞上「服务正在停止」。
func waitStopped(name string) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("sc.exe", "query", name).Output()
		if err != nil || strings.Contains(string(out), "STOPPED") {
			return // 查不到也算停了（可能已被删）
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// installTask 是降级路（非管理员）：XML 计划任务带 RestartOnFailure
// （崩溃 30 秒自拉起）+ ExecutionTimeLimit PT0S（关掉默认 3 天强杀），
// 动作是 wscript 隐藏启动器（直接跑控制台程序会钉一个关不得的桌面窗
// 口），输出重进 ~/.towstrap/towstrap.log。
func installTask(o Opts) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("拿不到用户目录：%w", err)
	}
	dir := filepath.Join(home, ".towstrap")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("建 %s 失败：%w", dir, err)
	}
	vbs := filepath.Join(dir, o.unitName()+"-run.vbs")
	log := filepath.Join(dir, o.unitName()+".log")
	if err := writeUTF16File(vbs, runVBS(o, log)); err != nil {
		return "", fmt.Errorf("写启动器 %s 失败：%w", vbs, err)
	}
	x, err := os.CreateTemp("", "towstrap-task-*.xml")
	if err != nil {
		return "", err
	}
	defer func() { _ = x.Close(); _ = os.Remove(x.Name()) }()
	if _, err := x.Write(utf16le(taskXML(o, vbs, runUser()))); err != nil {
		return "", fmt.Errorf("写任务定义失败：%w", err)
	}
	_ = x.Close()
	if out, err := exec.Command("schtasks", "/create", "/tn", o.unitName(),
		"/xml", x.Name(), "/f").CombinedOutput(); err != nil {
		return "", fmt.Errorf("计划任务注册失败：%w（%s）", err, strings.TrimSpace(string(out)))
	}
	if o.NoStart {
		return fmt.Sprintf("计划任务 %s 已注册为登录自起（未拉起，拿到 token 后会拉起）", o.unitName()), nil
	}
	_ = exec.Command("schtasks", "/run", "/tn", o.unitName()).Run()
	return fmt.Sprintf("计划任务 %s 已注册并拉起（登录自起、崩溃 30 秒自拉起，日志 %s）", o.unitName(), log), nil
}

func uninstall(o Opts) (string, error) {
	name := o.unitName()
	// 服务形态优先查 SCM；没有再看计划任务。
	if exec.Command("sc.exe", "query", name).Run() == nil {
		_ = exec.Command("sc.exe", "stop", name).Run()
		waitStopped(name)
		if out, err := exec.Command("sc.exe", "delete", name).CombinedOutput(); err != nil {
			return "", fmt.Errorf("删除服务失败：%w（%s）", err, strings.TrimSpace(string(out)))
		}
		// SCM 的 stop 正常会让服务进程退；残留（老版本不响应 stop）按镜
		// 像名收一遍——要排除自己：跑这条命令的 CLI 也是同名 exe。
		killOthers(o.Exe)
		return fmt.Sprintf("已删掉服务 %s（二进制和配置没动）", name), nil
	}
	return uninstallTask(o)
}

// killOthers 按镜像名强杀同名 exe 的其他进程，留着自己——跑
// service uninstall/update 的 CLI 本体就是同一个 exe 名，不过滤 PID
// 会把自己杀了，后面的 delete/start 根本执行不到。
func killOthers(exe string) {
	_ = exec.Command("taskkill", "/f", "/im", filepath.Base(exe),
		"/fi", fmt.Sprintf("PID ne %d", os.Getpid())).Run()
}

func uninstallTask(o Opts) (string, error) {
	if exec.Command("schtasks", "/query", "/tn", o.unitName()).Run() != nil {
		return "", fmt.Errorf("没找到服务或计划任务 %s——本来就没装过", o.unitName())
	}
	_ = exec.Command("schtasks", "/end", "/tn", o.unitName()).Run()
	if out, err := exec.Command("schtasks", "/delete", "/tn", o.unitName(), "/f").CombinedOutput(); err != nil {
		return "", fmt.Errorf("删除失败：%w（%s）", err, strings.TrimSpace(string(out)))
	}
	if home, err := os.UserHomeDir(); err == nil {
		_ = os.Remove(filepath.Join(home, ".towstrap", o.unitName()+"-run.vbs"))
	}
	// 任务的动作是 wscript，/end 只收启动器——被它拉起的 agent 本体放
	// 在最后收（taskkill 排除自己，CLI 不会中途暴毙导致 delete 没跑）。
	killOthers(o.Exe)
	return fmt.Sprintf("已删掉计划任务 %s（二进制和配置没动）", o.unitName()), nil
}

func status(o Opts) string {
	name := o.unitName()
	if out, err := exec.Command("sc.exe", "query", name).Output(); err == nil {
		state := "已注册"
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "STATE") || strings.Contains(line, "状态") {
				state = "已注册 " + strings.TrimSpace(line)
			}
		}
		return state + "（Windows 服务）"
	}
	return taskStatus(o)
}

func taskStatus(o Opts) string {
	if exec.Command("schtasks", "/query", "/tn", o.unitName()).Run() != nil {
		return "未安装"
	}
	out, _ := exec.Command("schtasks", "/query", "/tn", o.unitName(), "/fo", "list", "/v").Output()
	var st, last string
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "Status") || strings.HasPrefix(l, "状态") {
			st = l
		}
		if strings.HasPrefix(l, "Last Result") || strings.HasPrefix(l, "上次结果") ||
			strings.HasPrefix(l, "上次运行结果") {
			last = l
		}
	}
	if st == "" {
		return "已注册（计划任务）"
	}
	if last != "" {
		return "已注册 " + st + "（" + last + "，计划任务）"
	}
	return "已注册 " + st + "（计划任务）"
}

// runUser 拿「域\用户名」填 LogonTrigger 的 UserId——只在这台机器的这个
// 账号登录时触发，别人登同一台机不会把 agent 拉成他的身份。
func runUser() string {
	if out, err := exec.Command("whoami").Output(); err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			return s
		}
	}
	if d, u := os.Getenv("USERDOMAIN"), os.Getenv("USERNAME"); d != "" && u != "" {
		return d + `\` + u
	}
	return ""
}

// writeUTF16File 用 UTF-16LE+BOM 写文件：WSH（vbs）和 schtasks /xml 都
// 认这个编码，且能装下中文用户名这类非 ASCII 路径。
func writeUTF16File(path, s string) error {
	return os.WriteFile(path, utf16le(s), 0o600)
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	buf := make([]byte, 2+len(u)*2)
	buf[0], buf[1] = 0xFF, 0xFE
	for i, c := range u {
		binary.LittleEndian.PutUint16(buf[2+i*2:], c)
	}
	return buf
}
