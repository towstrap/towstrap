package machineid

import (
	"os"
	"os/exec"
	"strings"
)

// platformID：优先 SMBIOS UUID（Win32_ComputerSystemProduct.UUID，主板固件
// 级，重装 Windows 不变），查不到回落注册表 MachineGuid（装系统时生成）。
func platformID() (string, string, error) {
	if uuid := smbiosUUID(); uuid != "" {
		return uuid, "smbios", nil
	}
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) >= 3 && f[0] == "MachineGuid" {
				return f[len(f)-1], "os", nil
			}
		}
	}
	return "", "", errNoID
}

// smbiosUUID 用 PowerShell 查 SMBIOS UUID。wmictl 老系统上没有 CIM cmdlet
// 的话退 wmic。占位 UUID 直接当没有。
func smbiosUUID() string {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-CimInstance Win32_ComputerSystemProduct).UUID`).Output()
	if err == nil {
		if s := strings.TrimSpace(string(out)); s != "" && !isPlaceholderUUID(s) {
			return s
		}
	}
	out, err = exec.Command("wmic", "csproduct", "get", "uuid").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines[1:] {
			if s := strings.TrimSpace(line); s != "" && !isPlaceholderUUID(s) {
				return s
			}
		}
	}
	return ""
}

type errString string

var errNoID = errString("没有平台机器 ID")

func (e errString) Error() string { return string(e) }

func confDirOS() string {
	// Windows 不写 /etc：统一走 %LOCALAPPDATA%\TowStrap
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		return d + `\TowStrap`
	}
	return ""
}
