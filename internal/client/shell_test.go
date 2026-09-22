package client

import "testing"

func TestShellCmdFlag(t *testing.T) {
	cases := []struct {
		shell string
		flag  string
	}{
		{"/bin/bash", "-c"},
		{"/bin/sh", "-c"},
		{"zsh", "-c"},
		{`C:\Windows\System32\cmd.exe`, "/c"},
		{"cmd.exe", "/c"},
		{"CMD.EXE", "/c"},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-Command"},
		{"powershell", "-Command"},
		{"pwsh", "-Command"},
		{"pwsh.exe", "-Command"},
	}
	for _, c := range cases {
		cmd := shellCmd(c.shell, "echo hi")
		if len(cmd.Args) != 3 || cmd.Args[1] != c.flag || cmd.Args[2] != "echo hi" {
			t.Errorf("shellCmd(%q) = %v, 想要 flag %s", c.shell, cmd.Args, c.flag)
		}
	}
}

func TestDefaultShell(t *testing.T) {
	// 不设 SHELL/COMSPEC 时必须有兜底值
	t.Setenv("SHELL", "")
	t.Setenv("COMSPEC", "")
	if s := defaultShell(); s == "" {
		t.Fatal("defaultShell 返回空")
	}
	t.Setenv("SHELL", "/usr/bin/fish")
	if s := defaultShell(); s != "/usr/bin/fish" {
		t.Fatalf("SHELL 环境变量没生效: %q", s)
	}
}
