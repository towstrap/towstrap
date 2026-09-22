// totpcmd 打印一个 base32 秘钥当前的 6 位 TOTP 码——给 CLI 调试/测试用。
package main

import (
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/totp"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "用法: totpcmd <base32-secret>")
		os.Exit(2)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(os.Args[1]))
	if err != nil {
		fmt.Fprintln(os.Stderr, "秘钥解码失败:", err)
		os.Exit(2)
	}
	fmt.Println(totp.Code(secret, time.Now()))
}
