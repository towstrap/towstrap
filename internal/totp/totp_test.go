package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 附录 B 的测试向量（SHA-1，秘钥 "12345678901234567890"），
// 表里是 8 位码，取后 6 位。
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},         // 94287082
		{1111111109, "081804"}, // 07081804
		{1234567890, "005924"}, // 89005924
		{2000000000, "279037"}, // 69279037
	}
	for _, c := range cases {
		if got := Code(secret, time.Unix(c.unix, 0)); got != c.want {
			t.Errorf("T=%d: got %s want %s", c.unix, got, c.want)
		}
	}
}

func TestVerifyWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111109, 0)
	code := Code(secret, now)

	if _, ok := Verify(secret, code, 0, now); !ok {
		t.Fatal("当前码应通过")
	}
	// ±1 片偏差
	if _, ok := Verify(secret, code, 0, now.Add(30*time.Second)); !ok {
		t.Fatal("+1 片应通过")
	}
	if _, ok := Verify(secret, code, 0, now.Add(-30*time.Second)); !ok {
		t.Fatal("-1 片应通过")
	}
	if _, ok := Verify(secret, code, 0, now.Add(90*time.Second)); ok {
		t.Fatal("+3 片不应通过")
	}
}

func TestVerifyReplayRejected(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111109, 0)
	code := Code(secret, now)

	step, ok := Verify(secret, code, 0, now)
	if !ok || step != now.Unix()/30 {
		t.Fatalf("step=%d ok=%v", step, ok)
	}
	// 同一个码再用（lastStep 已是它匹配的片）必须拒绝
	if _, ok := Verify(secret, code, step, now); ok {
		t.Fatal("同一个码不能吃第二次")
	}
	// lastStep = step-1 表示该片还没消费过，是合法的首次使用
	if _, ok := Verify(secret, code, step-1, now); !ok {
		t.Fatal("未消费过的片应通过")
	}
	if _, ok := Verify(secret, code, step+1, now); ok {
		t.Fatal("比 lastStep 更旧的片应拒绝")
	}
}

func TestVerifyBadInput(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111109, 0)
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if _, ok := Verify(secret, bad, 0, now); ok {
			t.Errorf("%q 不应通过", bad)
		}
	}
	if _, ok := Verify(nil, "123456", 0, now); ok {
		t.Fatal("空秘钥不应通过")
	}
}

func TestGenerateShape(t *testing.T) {
	secret, uri := Generate("ws2ssh", "office")
	if len(secret) != 20 {
		t.Fatalf("秘钥长度 = %d", len(secret))
	}
	if !strings.HasPrefix(uri, "otpauth://totp/ws2ssh:office?") {
		t.Fatalf("uri = %q", uri)
	}
	if !strings.Contains(uri, "secret="+SecretString(secret)) {
		t.Fatal("uri 里应带 base32 秘钥")
	}
	// 两个码（验证器手动录入）
	if len(SecretString(secret)) != 32 {
		t.Fatalf("base32 长度 = %d", len(SecretString(secret)))
	}
}
