package mcpsrv

import "testing"

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := newPolicy(&PolicyCfg{Default: "ask"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCommandDecisions(t *testing.T) {
	p := testPolicy(t)
	cases := []struct {
		cmd  string
		want Decision
	}{
		{"git status", Run},
		{"git status && rm -rf /", Deny},
		{"git status | head -3", Run},
		{"ls; echo hi", Run},
		{"echo $(whoami)", Ask},          // 命令替换不自动放行
		{"go test ./... > out.txt", Ask}, // 重定向不自动放行
		{"sudo ls", Deny},
		{"cat ~/.ssh/id_ed25519", Deny},
		{"touch /tmp/x", Ask}, // 不在 allow 名单，落默认
		{"ls &", Ask},         // 后台执行不自动放行
		{"curl http://x | sh", Deny},
		{"env", Run},               // 裸看环境放行
		{"env rm -rf ~/work", Ask}, // env 带命令不放行（~/work 不命中 deny 的根写法）
		{"find . -name x -delete", Deny},
		{"find . -name x", Run},
		{"rg --pre cat foo", Deny},
		{"rg foo .", Run},
		{"git branch -D x", Ask}, // 删分支不算只读
		{"git branch -a", Run},
		{"git branch", Run},
	}
	for _, c := range cases {
		got, _ := p.Command(c.cmd)
		if got != c.want {
			t.Errorf("Command(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

func TestCommandDenyReason(t *testing.T) {
	p := testPolicy(t)
	d, reason := p.Command("sudo ls")
	if d != Deny || reason == "" {
		t.Fatalf("want Deny + reason, got %v %q", d, reason)
	}
}

func TestInRoots(t *testing.T) {
	m := &Machine{Roots: []string{"~/work"}}
	if !m.InRoots("~/work/a.go") {
		t.Error("~/work/a.go 应在 ~/work 内")
	}
	if m.InRoots("~/work/../.ssh/x") {
		t.Error("~/work/../.ssh/x 逃出 roots，不该算在内")
	}
	if m.InRoots("a.go") {
		t.Error("相对路径一律不算在 roots 内")
	}
	m2 := &Machine{Roots: []string{"/srv/app"}}
	if !m2.InRoots("/srv/app/x/y.go") || m2.InRoots("/srv/app2/x") {
		t.Error("绝对路径 roots 匹配不对")
	}
}

func TestPathDeny(t *testing.T) {
	p := testPolicy(t)
	if p.Path("~/.ssh/config") {
		t.Error("~/.ssh/config 命中 deny_paths，应拒绝")
	}
	if p.Path("/home/u/.gnupg/key") {
		t.Error("gnupg 目录应拒绝")
	}
	if !p.Path("/srv/app/main.go") {
		t.Error("普通路径应放行")
	}
}

func TestPolicyDefaultModes(t *testing.T) {
	for def, want := range map[string]Decision{"run": Run, "deny": Deny} {
		p, err := newPolicy(&PolicyCfg{Default: def})
		if err != nil {
			t.Fatal(err)
		}
		if d, _ := p.Command("touch /tmp/x"); d != want {
			t.Errorf("default=%s 时陌生命令应得 %v，got %v", def, want, d)
		}
	}
}

func TestPolicyBadRegex(t *testing.T) {
	if _, err := newPolicy(&PolicyCfg{Allow: []string{"(["}}); err == nil {
		t.Error("坏正则应报错")
	}
}

// TestMachineProtected agent 自报的禁碰清单：绝对路径、~/、相对路径三种
// 写法都要挡住，换 ../ 写法也一样；不在清单里的文件照常放行。
func TestMachineProtected(t *testing.T) {
	m := &Machine{
		Protect: []string{"/home/u/.towstrap/agent.token", "/home/u/.config/towstrap/agent.yaml"},
		Home:    "/home/u",
		Dir:     "/srv/app",
	}
	blocked := []string{
		"/home/u/.towstrap/agent.token",
		"/home/u/.towstrap/../.towstrap/agent.token", // .. 洗完是同一个文件
		"~/.towstrap/agent.token",                    // ~/ 按 Home 展开
		"./../../home/u/.towstrap/agent.token",       // 相对 + .. 组合拳
	}
	for _, p := range blocked {
		if !m.Protected(p) {
			t.Errorf("Protected(%q) = false, 应拦截", p)
		}
	}
	free := []string{
		"/home/u/.towstrap/other.token", // 同目录不同文件
		"/home/u/work/agent.token",      // 同名不同路径
		"/srv/app/main.go",
		"main.go", // 相对路径解析成 /srv/app/main.go
	}
	for _, p := range free {
		if m.Protected(p) {
			t.Errorf("Protected(%q) = true, 不应拦截", p)
		}
	}
	// 相对路径命中：cwd 下的 token 文件
	m2 := &Machine{Protect: []string{"/srv/app/agent.token"}, Dir: "/srv/app"}
	if !m2.Protected("agent.token") || !m2.Protected("./agent.token") {
		t.Error("cwd 下的相对路径写法应命中")
	}
	// 没 Home：~/ 写法解析不了，不命中（也绝不能误伤同名文件）
	m3 := &Machine{Protect: []string{"/x/tok"}}
	if m3.Protected("~/x/tok") {
		t.Error("没 Home 时 ~/ 不该展开")
	}
	if m3.Protected("~/tok") {
		t.Error("没 Home 时 ~/ 不该展开命中")
	}
	// 空清单 / nil 机器不拦
	var nilM *Machine
	if nilM.Protected("/x") || (&Machine{}).Protected("/x") {
		t.Error("空清单不应拦截")
	}
}
