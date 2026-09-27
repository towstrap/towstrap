// genkey 生成一对 minisign 发行签名钥匙（make signkey 调它）：
//
//	minisign.key  未加密私钥文件（0600）——base64 后配成 GitHub secret
//	              MINISIGN_KEY，配完建议删掉本机这份。
//	minisign.pub  公钥文件——提交进仓库；同一份内容填进
//	              internal/selfupdate/minisign.go 的 releasePubKey、
//	              scripts/install.sh / install.ps1 的 MINISIGN_PUB。
//
// 文件格式和 minisign 官方一致（未加密档）：
//
//	私钥 = "Ed"(2) || keynum(8) || seed||pub(64)   的 base64
//	公钥 = "Ed"(2) || keynum(8) || pub(32)         的 base64
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	if _, err := os.Stat("minisign.key"); err == nil {
		fmt.Fprintln(os.Stderr, "minisign.key 已存在——不覆盖现有钥匙。要重生成先手动删掉它。")
		os.Exit(2)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成钥匙失败:", err)
		os.Exit(1)
	}
	var keynum [8]byte
	if _, err := rand.Read(keynum[:]); err != nil {
		fmt.Fprintln(os.Stderr, "生成 keynum 失败:", err)
		os.Exit(1)
	}

	secretRaw := append(append([]byte("Ed"), keynum[:]...), priv...)
	pubRaw := append(append([]byte("Ed"), keynum[:]...), pub...)
	secretFile := "untrusted comment: minisign secret key\n" +
		base64.StdEncoding.EncodeToString(secretRaw) + "\n"
	pubFile := fmt.Sprintf("untrusted comment: minisign public key %s\n",
		strings.ToUpper(hex.EncodeToString(keynum[:]))) +
		base64.StdEncoding.EncodeToString(pubRaw) + "\n"

	if err := os.WriteFile("minisign.key", []byte(secretFile), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "写 minisign.key:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("minisign.pub", []byte(pubFile), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写 minisign.pub:", err)
		os.Exit(1)
	}

	fmt.Println("已生成 minisign 钥匙对：")
	fmt.Println("  minisign.pub —— 提交进仓库")
	fmt.Println("  minisign.key —— 私钥（0600）")
	fmt.Println()
	fmt.Println("三件事：")
	fmt.Println("  1. 公钥那行填进 internal/selfupdate/minisign.go 的 releasePubKey，")
	fmt.Println("     以及 scripts/install.sh / install.ps1 的 MINISIGN_PUB 默认值：")
	fmt.Println("     " + base64.StdEncoding.EncodeToString(pubRaw))
	fmt.Println("  2. 私钥配成 GitHub secret MINISIGN_KEY（base64 整个文件）：")
	fmt.Println("     base64 < minisign.key")
	fmt.Println("  3. 配好后删掉本机的 minisign.key，别把私钥提交进仓库。")
}
