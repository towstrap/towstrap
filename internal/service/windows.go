//go:build windows

package service

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// installSchtasks 注册「登录自起」计划任务。用 XML 而不是 schtasks /tr，
// 因为 /tr 开不了 RestartOnFailure（崩溃自拉起）也关不掉默认 3 天的
// ExecutionTimeLimit——两个对常驻 agent 都是硬伤。动作实际是 wscript
// 跑 ~/.towstrap 下生成的 vbs 隐藏启动器，输出重定向进 towstrap.log，
// agent 崩了至少留得下遗言。
func install(o Opts) (string, error) {
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
	_ = exec.Command("schtasks", "/run", "/tn", o.unitName()).Run()
	return fmt.Sprintf("计划任务 %s 已注册并拉起（登录自起、崩溃 30 秒自拉起，日志 %s）", o.unitName(), log), nil
}

func uninstall(o Opts) (string, error) {
	if exec.Command("schtasks", "/query", "/tn", o.unitName()).Run() != nil {
		return "", fmt.Errorf("没找到计划任务 %s——本来就没装过", o.unitName())
	}
	_ = exec.Command("schtasks", "/end", "/tn", o.unitName()).Run()
	// 任务的动作是 wscript，/end 只收启动器——被它拉起的 agent 本体要
	// 再补一刀（按镜像名杀，Windows 上同一台机基本就这一个实例）。
	_ = exec.Command("taskkill", "/f", "/im", filepath.Base(o.Exe)).Run()
	if out, err := exec.Command("schtasks", "/delete", "/tn", o.unitName(), "/f").CombinedOutput(); err != nil {
		return "", fmt.Errorf("删除失败：%w（%s）", err, strings.TrimSpace(string(out)))
	}
	if home, err := os.UserHomeDir(); err == nil {
		_ = os.Remove(filepath.Join(home, ".towstrap", o.unitName()+"-run.vbs"))
	}
	return fmt.Sprintf("已删掉计划任务 %s（二进制和配置没动）", o.unitName()), nil
}

func status(o Opts) string {
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
		return "已注册"
	}
	if last != "" {
		return "已注册 " + st + "（" + last + "）"
	}
	return "已注册 " + st
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
