package client

import "testing"

// 管道名/SID 规则是无平台差字符串逻辑（在 mirrorsock.go），任何系统都能测。

func TestPipeSID(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{`\\.\pipe\towstrap-mirror-S-1-5-18`, "S-1-5-18"},
		{`\\.\pipe\towstrap-mirror-S-1-5-21-3623811015-3361044348-30300820-1013`, "S-1-5-21-3623811015-3361044348-30300820-1013"},
		{`\\.\pipe\towstrap-mirror-`, ""},              // 空后缀
		{`\\.\pipe\towstrap-mirror-foo`, ""},           // 非 SID 形态
		{`\\.\pipe\custom-name`, ""},                   // 自定义管道名
		{`\\.\pipe\towstrap-mirror-S-1-5-18\evil`, ""}, // 路径穿透字符
		{`\\.\pipe\towstrap-mirror-S-1-5-18 x`, ""},    // 带空格
		{`/tmp/mirror.sock`, ""},                       // unix 路径
		{"", ""},
	} {
		if got := pipeSID(tc.path); got != tc.want {
			t.Errorf("pipeSID(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestMirrorPipeTargets(t *testing.T) {
	// 普通用户：自己优先，SYSTEM 服务兜底
	got := mirrorPipeTargets("S-1-5-21-111-222-333-1001")
	want := []string{
		`\\.\pipe\towstrap-mirror-S-1-5-21-111-222-333-1001`,
		`\\.\pipe\towstrap-mirror-S-1-5-18`,
	}
	if len(got) != len(want) {
		t.Fatalf("targets = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("targets[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// SYSTEM 自己只有一条，不重复
	if got := mirrorPipeTargets("S-1-5-18"); len(got) != 1 || got[0] != `\\.\pipe\towstrap-mirror-S-1-5-18` {
		t.Errorf("system targets = %v", got)
	}
}
