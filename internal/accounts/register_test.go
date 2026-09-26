package accounts

import "testing"

// 指纹是十六进制哈希：大小写两种写法必须撞同一行，不然同一台机器
// 换个大写就能再占一个账号。
func TestFingerprintCaseInsensitive(t *testing.T) {
	s := openTest(t)
	fp := "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"

	bound, inserted, err := s.BindFingerprint(fp, "alice")
	if err != nil || !bound || !inserted {
		t.Fatalf("首次绑定: bound=%t inserted=%t err=%v", bound, inserted, err)
	}
	// 小写变体查/绑都要撞上同一行
	if owner, _ := s.FingerprintAccount("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"); owner != "alice" {
		t.Fatalf("小写指纹应查到 alice, got %q", owner)
	}
	if bound, _, err := s.BindFingerprint("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "mallory"); err != nil || bound {
		t.Fatalf("小写变体换账号应被拒: bound=%t err=%v", bound, err)
	}
	// 同账号幂等重试通过（不重复插行也不算占用）
	if bound, inserted, err := s.BindFingerprint(fp, "alice"); err != nil || !bound || inserted {
		t.Fatalf("同账号重绑: bound=%t inserted=%t err=%v", bound, inserted, err)
	}
	// 回滚只能删自己插的行：mallory 没插进去，调 Release 不许误伤 alice 的绑定
	if err := s.ReleaseFingerprint(fp, "mallory"); err != nil {
		t.Fatal(err)
	}
	if owner, _ := s.FingerprintAccount(fp); owner != "alice" {
		t.Fatalf("别人回滚不能删 alice 的绑定, got %q", owner)
	}
	// alice 自己的回滚正常删
	if err := s.ReleaseFingerprint(fp, "alice"); err != nil {
		t.Fatal(err)
	}
	if owner, _ := s.FingerprintAccount(fp); owner != "" {
		t.Fatalf("自己的回滚应删掉绑定, got %q", owner)
	}
}
