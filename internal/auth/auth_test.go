package auth

import "testing"

func TestEqual(t *testing.T) {
	if !Equal("secret", "secret") {
		t.Fatal("相同口令应相等")
	}
	for _, bad := range []string{"", "Secret", "secret "} {
		if Equal("secret", bad) {
			t.Fatalf("%q 不应相等", bad)
		}
	}
	// 两个空串相等是预期行为，调用方负责先检查非空。
	if !Equal("", "") {
		t.Fatal("空串应相等")
	}
}
