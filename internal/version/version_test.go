package version

import "testing"

func TestLessThan(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.1.9", "0.2.0", true},
		{"0.2.0", "0.2.0", false},
		{"0.2.1", "0.2.0", false},
		{"1.0.0", "0.99.99", false},
		{"0.2.0 (abc123)", "0.2.1", true},
		{"0.2.0 (abc123)", "0.2.0", false},
		{"", "0.1.0", true}, // 旧 agent 不上报 → 0.0.0
		{"garbage", "0.0.1", true},
		{"0.2", "0.2.1", true}, // 不满三段按 0.0.0
		{"10.0.0", "9.9.9", false},
	}
	for _, c := range cases {
		if got := LessThan(c.a, c.b); got != c.want {
			t.Errorf("LessThan(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
