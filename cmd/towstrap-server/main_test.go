package main

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"towstrap/internal/accounts"
	"towstrap/internal/totp"
)

// mcpEndpointURL 的 public_url 是 ws/wss scheme，打印给 MCP 客户端前
// 要换成 http/https；其他形式原样保留。
func TestMCPEndpointURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"wss://ssh.example.com:443", "https://ssh.example.com:443/mcp"},
		{"ws://127.0.0.1:8080", "http://127.0.0.1:8080/mcp"},
		{"https://ssh.example.com", "https://ssh.example.com/mcp"},
		{"wss://host/", "https://host/mcp"}, // 尾部斜杠去掉再拼
		{"", "https://<服务器>:<HTTP端口>/mcp"},  // 没配 public_url 留占位
	}
	for _, c := range cases {
		if got := mcpEndpointURL(c.in, ""); got != c.want {
			t.Errorf("mcpEndpointURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSkillInstallHint(t *testing.T) {
	base := "https://ssh.example.com:8080"
	hint := skillInstallHint(base)
	for _, want := range []string{
		"~/.claude/skills/towstrap/SKILL.md",
		"~/.cursor/skills/towstrap/SKILL.md",
		"~/.agents/skills/towstrap/SKILL.md",
		"towstrap-mcp connect",
		base + "/skill",
		"-k",
	} {
		if !strings.Contains(hint, want) {
			t.Errorf("skillInstallHint 缺 %q:\n%s", want, hint)
		}
	}
}

// TestConfirmOwner 账号本人确认：密码必过；绑了 TOTP 还要验证码；
// --admin 不读输入直接放行。
func TestConfirmOwner(t *testing.T) {
	newStore := func(t *testing.T) *accounts.Store {
		t.Helper()
		s, err := accounts.Open(filepath.Join(t.TempDir(), "users.db"), "")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// 绑 TOTP 的账号：lastStep 记成上一片，当前片的码才有效
	enroll := func(t *testing.T, s *accounts.Store, user string) []byte {
		t.Helper()
		secret, _ := totp.Generate("towstrap", user)
		if err := s.EnrollTOTP(user, secret, time.Now().Unix()/30-1); err != nil {
			t.Fatal(err)
		}
		return secret
	}

	t.Run("密码错", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Add("alice", "right-password", nil, "", nil); err != nil {
			t.Fatal(err)
		}
		err := confirmOwner(s, "alice", strings.NewReader("wrong-password\n"), io.Discard, false)
		if err == nil || !strings.Contains(err.Error(), "密码") {
			t.Fatalf("密码错应报「密码不对或账号已停用」: %v", err)
		}
	})

	t.Run("账号不存在", func(t *testing.T) {
		s := newStore(t)
		err := confirmOwner(s, "ghost", strings.NewReader("pw\n"), io.Discard, false)
		if err == nil {
			t.Fatal("不存在的账号应确认失败")
		}
	})

	t.Run("密码对无TOTP", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Add("alice", "right-password", nil, "", nil); err != nil {
			t.Fatal(err)
		}
		if err := confirmOwner(s, "alice", strings.NewReader("right-password\n"), io.Discard, false); err != nil {
			t.Fatalf("正确密码应通过: %v", err)
		}
	})

	t.Run("密码对加TOTP对", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Add("alice", "right-password", nil, "", nil); err != nil {
			t.Fatal(err)
		}
		secret := enroll(t, s, "alice")
		in := strings.NewReader("right-password\n" + totp.Code(secret, time.Now()) + "\n")
		if err := confirmOwner(s, "alice", in, io.Discard, false); err != nil {
			t.Fatalf("密码+验证码应通过: %v", err)
		}
	})

	t.Run("密码对加TOTP错", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Add("alice", "right-password", nil, "", nil); err != nil {
			t.Fatal(err)
		}
		secret := enroll(t, s, "alice")
		bad := totp.Code(secret, time.Now())
		bad = string(map[bool]byte{true: '1', false: '0'}[bad[0] == '0']) + bad[1:]
		err := confirmOwner(s, "alice", strings.NewReader("right-password\n"+bad+"\n"), io.Discard, false)
		if err == nil || !strings.Contains(err.Error(), "验证码") {
			t.Fatalf("错误验证码应报「验证码不对」: %v", err)
		}
	})

	t.Run("admin不读输入", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Add("alice", "right-password", nil, "", nil); err != nil {
			t.Fatal(err)
		}
		// 输入是「读了就报错」的 reader：admin 分支不能碰它
		err := confirmOwner(s, "alice", failReader{}, io.Discard, true)
		if err != nil {
			t.Fatalf("admin 应直接放行: %v", err)
		}
	})
}

// failReader 任何读取都报错，用来断言 admin 分支没有读输入。
type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("不应读输入") }
