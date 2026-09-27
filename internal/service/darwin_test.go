//go:build darwin

package service

import (
	"strings"
	"testing"
)

func TestPlistXMLUser(t *testing.T) {
	xml := plistXML(Opts{
		Name:       "agent",
		Exe:        "/usr/local/bin/towstrap",
		ConfigPath: "/Users/x/.config/towstrap/agent.yaml",
	}, "/tmp/x.log", false)
	for _, want := range []string{
		"com.towstrap.agent",
		"/usr/local/bin/towstrap",
		"/Users/x/.config/towstrap/agent.yaml",
		"RunAtLoad", "KeepAlive", "NumberOfFiles",
		"/tmp/x.log",
	} {
		if !strings.Contains(xml, want) {
			t.Fatalf("plist 缺 %q：\n%s", want, xml)
		}
	}
	// 用户项不带进程数上限和 UserName
	if strings.Contains(xml, "NumberOfProcesses") || strings.Contains(xml, "UserName") {
		t.Fatal("用户级 plist 不该有 NumberOfProcesses/UserName")
	}
}

func TestPlistXMLRootDaemon(t *testing.T) {
	xml := plistXML(Opts{
		Name:    "agent",
		Exe:     "/usr/local/bin/towstrap",
		SysUser: "_towstrap",
	}, "/var/log/t.log", true)
	for _, want := range []string{
		"UserName</key><string>_towstrap",
		"GroupName</key><string>_towstrap",
		"NumberOfProcesses",
	} {
		if !strings.Contains(xml, want) {
			t.Fatalf("root plist 缺 %q：\n%s", want, xml)
		}
	}
}

func TestNames(t *testing.T) {
	if (Opts{Name: "agent"}).unitName() != "towstrap" {
		t.Fatal("agent 单元名应为 towstrap")
	}
	if (Opts{Name: "server"}).unitName() != "towstrap-server" {
		t.Fatal("server 单元名应为 towstrap-server")
	}
	if (Opts{Name: "agent"}).label() != "com.towstrap.agent" {
		t.Fatal("agent label 应为 com.towstrap.agent")
	}
}
