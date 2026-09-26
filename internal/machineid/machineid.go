// Package machineid 取这台机器的稳定指纹，给服务器端注册去重用：
// 同一台机器只许注册一个账号。
//
// 来源按可靠性排序取——主板固件 UUID（重装系统不变，防重复注册最硬）>
// OS 级机器 ID（装系统时生成，重装会变）> 持久化随机 ID 兜底。
// 对外只暴露 SHA256 哈希（Fingerprint），原始 ID 不出本机；哈希里带
// 来源标签，不同来源的原始值互相撞不上。
package machineid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Fingerprint 返回这台机器的稳定指纹（sha256 hex）。带域前缀和来源标签
// 哈希，原始机器 ID 不出本机。
func Fingerprint() string {
	raw, kind, err := sourceID()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte("towstrap-register\n" + kind + "\n" + raw))
	return hex.EncodeToString(sum[:])
}

// Source 返回指纹的来源：smbios（主板固件 UUID，最硬）、os（装系统生成
// 的机器 ID）、random（兜底持久化随机 ID）。诊断/文档用。
func Source() string {
	_, kind, err := sourceID()
	if err != nil {
		return ""
	}
	return kind
}

// sourceID 返回 (原始 ID, 来源类型)。平台层取不到时用持久化随机 ID 兜底。
func sourceID() (string, string, error) {
	if raw, kind, err := platformID(); err == nil && raw != "" {
		return raw, kind, nil
	}
	id, err := persistedID()
	return id, "random", err
}

// Raw 取原始机器 ID（未哈希）。文件持久化兜底保证至少稳定到删配置为止。
func Raw() (string, error) {
	raw, _, err := sourceID()
	return raw, err
}

// ConfDir 返回 towstrap 的配置目录约定：root 进 /etc/towstrap，普通用户
// 进 XDG_CONFIG_HOME 或 ~/.config/towstrap；Windows 用 %LOCALAPPDATA%。
// 和 install.sh 的安装路径一致。
func ConfDir() (string, error) {
	if dir := confDirOS(); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "towstrap"), nil
}

// persistedID 兜底：配置目录里存一个一次生成的随机 ID。
func persistedID() (string, error) {
	dir, err := ConfDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "machine-id")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	// ConfDir 开始认 XDG_CONFIG_HOME 后，设了 XDG 的旧机器上 machine-id
	// 还在 ~/.config/towstrap 下——找不到就先认旧位置的，保住既有指纹。
	if home, err := os.UserHomeDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(home, ".config", "towstrap", "machine-id")); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id, nil
			}
		}
	}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("没有可用的机器 ID 来源: %w", err)
	}
	id := hex.EncodeToString(rnd[:])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// isPlaceholderUUID 滤掉 SMBIOS 里常见的占位/无效 UUID：全 0、全 F、
// 主板厂商没填时的通用默认值（03000200-0400-0500-…）。这些没有区分度，
// 拿去做指纹反而会让不同机器撞车。
func isPlaceholderUUID(s string) bool {
	t := strings.ToLower(strings.ReplaceAll(s, "-", ""))
	if len(t) != 32 {
		return true
	}
	uniform := true
	for _, c := range t[1:] {
		if c != rune(t[0]) {
			uniform = false
			break
		}
	}
	if uniform {
		return true // 全是同一个字符（0000…、ffff…）
	}
	return strings.HasPrefix(t, "0300020004000500000") // 厂商没填时的通用默认
}
