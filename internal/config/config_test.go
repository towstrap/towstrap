package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "conf.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadServerSection(t *testing.T) {
	path := write(t, `
server:
  http: "127.0.0.1:9000"
  ssh: "127.0.0.1:2200"
  host_key: /tmp/k
  users_db: /tmp/users.db
  users_key: /tmp/users.key
  admin_token: adm
  public_url: wss://ssh.example.com:443
  allow_ips: [10.0.0.0/8]
`)
	s, err := LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.HTTP != "127.0.0.1:9000" || s.SSH != "127.0.0.1:2200" || s.HostKey != "/tmp/k" {
		t.Fatalf("%#v", s)
	}
	if s.UsersDB != "/tmp/users.db" || s.UsersKey != "/tmp/users.key" || s.AdminToken != "adm" || s.PublicURL != "wss://ssh.example.com:443" {
		t.Fatalf("%#v", s)
	}
	if len(s.AllowIPs) != 1 {
		t.Fatalf("%#v", s)
	}

	m := MergeServer(s, map[string]string{"ssh": "127.0.0.1:2222"})
	if m.SSH != "127.0.0.1:2222" || m.HTTP != "127.0.0.1:9000" {
		t.Fatalf("命令行应覆盖文件: %#v", m)
	}
}

func TestMergeServerDefaults(t *testing.T) {
	m := MergeServer(Server{}, nil)
	if m.HTTP != ":8080" || m.SSH != ":2222" || m.HostKey != "/etc/ws2ssh/ssh_host_key" {
		t.Fatalf("%#v", m)
	}
	if m.UsersDB != "/etc/ws2ssh/users.db" {
		t.Fatalf("账号库默认路径: %#v", m)
	}
}

func TestLoadAgentSectionAndFlat(t *testing.T) {
	path := write(t, `
agent:
  server: wss://1.2.3.4:443
  agent_token: w2s-abc
  insecure: true
`)
	a, err := LoadAgent(path)
	if err != nil {
		t.Fatal(err)
	}
	if a.Server != "wss://1.2.3.4:443" || a.AgentToken != "w2s-abc" || !a.Insecure {
		t.Fatalf("%#v", a)
	}

	flat := write(t, "server: wss://5.6.7.8:443\nagent_token: w2s-flat\n")
	a2, err := LoadAgent(flat)
	if err != nil {
		t.Fatal(err)
	}
	if a2.Server != "wss://5.6.7.8:443" || a2.AgentToken != "w2s-flat" || a2.Insecure {
		t.Fatalf("%#v", a2)
	}

	m := MergeAgent(a2, map[string]string{"agent-token": "w2s-new", "insecure": "true"})
	if m.AgentToken != "w2s-new" || !m.Insecure || m.Server != a2.Server {
		t.Fatalf("%#v", m)
	}
}

func TestMergeServerLimits(t *testing.T) {
	out := MergeServer(Server{}, map[string]string{})
	if out.MaxSessions != 16 || out.MaxConns != 4096 || out.MaxConnsPerIP != 64 {
		t.Fatalf("连接上限默认值: %+v", out)
	}
	if out.SSHMaxTimeout != "24h" || out.SSHIdleTimeout != "" {
		t.Fatalf("SSH 超时默认值: %+v", out)
	}

	out = MergeServer(Server{}, map[string]string{"max-sessions": "4", "max-conns-per-ip": "2", "ssh-max-timeout": "1h"})
	if out.MaxSessions != 4 || out.MaxConnsPerIP != 2 || out.SSHMaxTimeout != "1h" {
		t.Fatalf("旗标应覆盖默认值: %+v", out)
	}

	out = MergeServer(Server{MaxSessions: 8, MaxConns: 100, SSHIdleTimeout: "10m"}, map[string]string{})
	if out.MaxSessions != 8 || out.MaxConns != 100 || out.SSHIdleTimeout != "10m" {
		t.Fatalf("配置文件应生效: %+v", out)
	}

	// yaml 里的 0 视为「没写」，保持默认（显式禁用走旗标 --max-sessions 0）
	out = MergeServer(Server{}, map[string]string{"max-sessions": "0"})
	if out.MaxSessions != 0 {
		t.Fatalf("旗标显式给 0 应关掉上限: %+v", out)
	}
}
