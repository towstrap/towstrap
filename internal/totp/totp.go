// Package totp 实现 RFC 6238 时间型一次性密码（TOTP，SHA-1 / 6 位 / 30 秒片），
// 只用标准库。防重放由调用方结合「上次用掉的时间片」完成：同一个码在它
// 有效期内只能被消费一次。
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	digits = 6
	period = 30 // 秒/时间片
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Generate 生成 160 位秘钥和扫码绑定用的 otpauth:// URI（Google Authenticator
// 等验证器通用格式）。
func Generate(issuer, account string) (secret []byte, uri string) {
	secret = make([]byte, 20)
	_, _ = rand.Read(secret)
	uri = fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		issuer, account, b32.EncodeToString(secret), issuer, digits, period)
	return secret, uri
}

// SecretString 返回手动录入验证器用的 base32 串。
func SecretString(secret []byte) string { return b32.EncodeToString(secret) }

// ParseSecret 把 SecretString 的 base32 串解回秘钥字节。
func ParseSecret(s string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.TrimSpace(s)))
}

// Code 算出 t 时刻的 6 位码（导出给测试和绑定确认用）。
func Code(secret []byte, t time.Time) string {
	return hotp(secret, t.Unix()/period)
}

// Verify 校验 codeStr：允许 ±1 个时间片（时钟偏差），但时间片必须比 lastStep
// 新——同一个码不能吃第二次。返回匹配到的时间片，成功时调用方应落库它。
func Verify(secret []byte, codeStr string, lastStep int64, now time.Time) (int64, bool) {
	if len(secret) == 0 || len(codeStr) != digits {
		return 0, false
	}
	cur := now.Unix() / period
	for _, s := range []int64{cur - 1, cur, cur + 1} {
		if s <= lastStep {
			continue
		}
		if hotp(secret, s) == codeStr {
			return s, true
		}
	}
	return 0, false
}

// hotp 是 RFC 4226 的 HMAC-OTP：HMAC-SHA1(秘钥, 时间片计数) 截断取 6 位。
func hotp(secret []byte, counter int64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(b[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, n%uint32(pow10(digits)))
}

func pow10(n int) int {
	p := 1
	for i := 0; i < n; i++ {
		p *= 10
	}
	return p
}
