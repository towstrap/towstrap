package main

import (
	"reflect"
	"testing"
)

func TestSplitGlobalFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		cfgPath string
		apprDir string
		rest    []string
	}{
		{"空", nil, "", "", nil},
		{"默认子命令", []string{"serve"}, "", "", []string{"serve"}},
		{"config 分写", []string{"--config", "m.yaml", "pending"}, "m.yaml", "", []string{"pending"}},
		{"approvals 分写", []string{"--approvals-dir", "/d", "approve", "id1"}, "", "/d", []string{"approve", "id1"}},
		{"approvals 连写", []string{"--approvals-dir=/d2", "pending"}, "", "/d2", []string{"pending"}},
		{"混合", []string{"approve", "--config", "m.yaml", "id1", "--remember"}, "m.yaml", "", []string{"approve", "id1", "--remember"}},
		{"config 缺值留在 rest", []string{"pending", "--config"}, "", "", []string{"pending", "--config"}},
		{"config 是最后一个参数", []string{"--config"}, "", "", []string{"--config"}},
	}
	for _, c := range cases {
		cfg, dir, rest := splitGlobalFlags(c.args)
		if cfg != c.cfgPath || dir != c.apprDir || !reflect.DeepEqual(rest, c.rest) {
			t.Errorf("%s: splitGlobalFlags(%v) = (%q, %q, %v), want (%q, %q, %v)",
				c.name, c.args, cfg, dir, rest, c.cfgPath, c.apprDir, c.rest)
		}
	}
}
