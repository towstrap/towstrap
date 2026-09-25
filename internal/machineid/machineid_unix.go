//go:build !windows

package machineid

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// platformID 按系统取稳定的机器 ID，返回 (原始值, 来源类型)。
// 优先主板固件级 ID（重装系统不变），再退回 OS 级 machine-id。
func platformID() (string, string, error) {
	switch runtime.GOOS {
	case "darwin":
		// IOPlatformUUID 是主板固件 UUID，重装系统不变；同一次 ioreg
		// 调用里顺手拿 IOPlatformSerialNumber 一起进哈希，防 UUID 撞车。
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err == nil {
			var uuid, serial string
			for _, line := range strings.Split(string(out), "\n") {
				if v, ok := ioregField(line, "IOPlatformUUID"); ok {
					uuid = v
				}
				if v, ok := ioregField(line, "IOPlatformSerialNumber"); ok {
					serial = v
				}
			}
			if uuid != "" {
				if serial != "" {
					return uuid + "|" + serial, "smbios", nil
				}
				return uuid, "smbios", nil
			}
		}
		// 兜底：内核 hostuuid
		if out, err := exec.Command("sysctl", "-n", "kern.hostuuid").Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s, "os", nil
			}
		}
	case "linux", "freebsd", "openbsd", "netbsd":
		// SMBIOS product_uuid 是主板固件 UUID：重装系统不变，克隆 VM 各有
		// 各的（hypervisor 会重新生成）。多数发行版只有 root 能读（0400）——
		// 读不到就回落 machine-id。
		if b, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" && !isPlaceholderUUID(s) {
				return s, "smbios", nil
			}
		}
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := os.ReadFile(p); err == nil {
				if s := strings.TrimSpace(string(b)); s != "" {
					return s, "os", nil
				}
			}
		}
	}
	return "", "", errNoID
}

// ioregField 解析 ioreg 输出的 `"key" = "value"` 行。
func ioregField(line, key string) (string, bool) {
	i := strings.Index(line, key)
	if i < 0 || !strings.Contains(line[:i+len(key)], `"`) {
		return "", false
	}
	j := strings.LastIndex(line, `"`)
	if j <= i {
		return "", false
	}
	line = line[:j]
	if k := strings.LastIndex(line, `"`); k >= 0 {
		return line[k+1:], true
	}
	return "", false
}

var errNoID = errString("没有平台机器 ID")

type errString string

func (e errString) Error() string { return string(e) }

func confDirOS() string {
	if os.Geteuid() == 0 {
		return "/etc/towstrap"
	}
	return ""
}
