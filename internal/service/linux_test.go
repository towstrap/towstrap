//go:build linux

package service

import (
	"strings"
	"testing"
)

func TestSystemdUnitUser(t *testing.T) {
	u := systemdUnit(Opts{
		Name:       "agent",
		Exe:        "/home/x/.local/bin/towstrap",
		ConfigPath: "/home/x/.config/towstrap/agent.yaml",
	}, false)
	for _, want := range []string{
		"Description=towstrap agent",
		"ExecStart=/home/x/.local/bin/towstrap --config /home/x/.config/towstrap/agent.yaml",
		"Restart=always",
		"WantedBy=default.target",
	} {
		if !strings.Contains(u, want) {
			t.Fatalf("用户单元缺 %q：\n%s", want, u)
		}
	}
	if strings.Contains(u, "User=") || strings.Contains(u, "ProtectSystem") {
		t.Fatal("用户单元不该有 User=/ProtectSystem")
	}
}

func TestSystemdUnitRoot(t *testing.T) {
	u := systemdUnit(Opts{
		Name:        "server",
		Exe:         "/usr/local/bin/towstrap-server",
		ConfigPath:  "/etc/towstrap/server.yaml",
		SysUser:     "",
		ProtectHome: true,
	}, true)
	for _, want := range []string{
		"Description=towstrap server",
		"NoNewPrivileges=true",
		"ProtectSystem=true",
		"ProtectHome=true",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Fatalf("系统单元缺 %q：\n%s", want, u)
		}
	}
	if strings.Contains(u, "User=") {
		t.Fatal("server 不设 SysUser 时不该有 User=")
	}
}

func TestSystemdUnitSysUser(t *testing.T) {
	u := systemdUnit(Opts{Name: "agent", Exe: "/x/towstrap", SysUser: "towstrap"}, true)
	if !strings.Contains(u, "User=towstrap\nGroup=towstrap") {
		t.Fatalf("系统单元缺 User/Group：\n%s", u)
	}
}
