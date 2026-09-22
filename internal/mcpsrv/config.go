// Package mcpsrv 是 towstrap-mcp 的内核：把 towstrap 的被控机包装成 MCP 工具
// （跑命令、读写文件），外加策略过滤和人工批准环节。MCP 的 stdio 通道只走
// 协议数据，本包所有日志一律写 stderr。
package mcpsrv

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 对应 mcp.yaml 的全部内容。
type Config struct {
	Server       string              `yaml:"server"`      // towstrap 服务器的 SSH 入口 host:port
	Key          string              `yaml:"key"`         // 登录私钥路径（无口令）
	KnownHosts   string              `yaml:"known_hosts"` // HostKey 设了就不用
	HostKey      string              `yaml:"host_key"`    // 钉死的服务器主机密钥指纹 SHA256:...
	Machines     map[string]*Machine `yaml:"machines"`    // 键 = towstrap 账号名 = SSH 用户名
	Policy       PolicyCfg           `yaml:"policy"`
	Limits       LimitsCfg           `yaml:"limits"`
	ApprovalsDir string              `yaml:"approvals_dir"` // 本地批准回退的待批目录

	// 下面三个字段不走 yaml，由调用方按运行模式填。
	// ApproveCmd 是错误文案和 instructions 里提示的批准命令：stdio 模式是
	// "towstrap-mcp approve"，服务器内嵌模式是在服务器上跑的
	// "towstrap-server mcp approve"。
	ApproveCmd string `yaml:"-"`
	// LocalNotify 控制本地批准回退要不要弹桌面通知：stdio 模式弹（进程跑在
	// 用户的电脑上），服务器模式不弹（服务器大概率没桌面）。
	LocalNotify bool `yaml:"-"`
	// Audit 是审计回调：策略拒绝、批准进出、批准结果各记一条。nil 时用
	// slog 写 stderr；服务器模式换成服务器自己的审计器。
	Audit func(event string, kv ...string) `yaml:"-"`
}

// Machine 一台被控机。Roots 里的目录 write_file 自动放行。
type Machine struct {
	Description string   `yaml:"description"`
	Roots       []string `yaml:"roots"`
	// Protect 是 agent 握手时自报的禁碰文件（token 文件、agent 配置——
	// 绝对路径）；Home/Dir 是 agent 侧家目录和工作目录，用来把输入的
	// ~/ 和相对路径解析成绝对形式。由服务器内嵌模式在 agent 在线时填，
	// 不走 yaml；stdio 模式拿不到这些信息，留空即不生效。
	Protect []string `yaml:"-"`
	Home    string   `yaml:"-"`
	Dir     string   `yaml:"-"`
}

// PolicyCfg 策略配置；名单不写就用 policy.go 里的内置默认。
type PolicyCfg struct {
	Default    string        `yaml:"default"` // run | ask | deny
	Allow      []string      `yaml:"allow"`
	Deny       []string      `yaml:"deny"`
	DenyPaths  []string      `yaml:"deny_paths"`
	AskTimeout time.Duration `yaml:"ask_timeout"`
}

// LimitsCfg 执行和文件的大小/时长上限。
type LimitsCfg struct {
	Timeout     time.Duration `yaml:"timeout"`      // run_command 默认超时
	MaxTimeout  time.Duration `yaml:"max_timeout"`  // timeout_seconds 上限
	MaxOutput   int           `yaml:"max_output"`   // stdout/stderr 各自上限（字节）
	MaxFile     int           `yaml:"max_file"`     // read_file/write_file 上限（字节）
	SessionIdle time.Duration `yaml:"session_idle"` // 常驻 shell 空闲多久回收，默认 30m
	MaxSessions int           `yaml:"max_sessions"` // 每个 MCP 客户端会话最多几个常驻 shell，默认 8
}

// DefaultPath 是 towstrap-mcp 没给 --config 时读的配置路径。
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "towstrap", "mcp.yaml")
}

// DefaultApprovalsDir 是 approvals_dir 的缺省值，也是批准子命令在
// 找不到配置时用的目录。
func DefaultApprovalsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "towstrap", "approvals")
}

// LoadConfig 读 mcp.yaml，展开 ~、补缺省、做校验。
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}
	cfg.Server = strings.TrimSpace(cfg.Server)
	cfg.Key = expandTilde(cfg.Key)
	cfg.KnownHosts = expandTilde(cfg.KnownHosts)
	cfg.ApprovalsDir = expandTilde(cfg.ApprovalsDir)
	cfg.ApplyDefaults()
	if cfg.ApprovalsDir == "" {
		cfg.ApprovalsDir = DefaultApprovalsDir()
	}
	if cfg.ApproveCmd == "" {
		cfg.ApproveCmd = "towstrap-mcp approve"
	}
	cfg.LocalNotify = true
	if err := cfg.validateSSH(); err != nil {
		return nil, fmt.Errorf("配置 %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置 %s: %w", path, err)
	}
	return &cfg, nil
}

// ApplyDefaults 填策略/限额的缺省值（ApprovalsDir 不在此列——stdio 和
// 服务器内嵌模式的默认目录不一样，各自填）。服务器内嵌模式用它而不是
// LoadConfig：那份配置是 server.yaml 的 mcp: 小节组出来的。
func (c *Config) ApplyDefaults() {
	if c.Policy.Default == "" {
		c.Policy.Default = "ask"
	}
	if c.Policy.AskTimeout == 0 {
		c.Policy.AskTimeout = 5 * time.Minute
	}
	if c.Limits.Timeout == 0 {
		c.Limits.Timeout = 120 * time.Second
	}
	if c.Limits.MaxTimeout == 0 {
		c.Limits.MaxTimeout = time.Hour
	}
	if c.Limits.MaxOutput == 0 {
		c.Limits.MaxOutput = 65536
	}
	if c.Limits.MaxFile == 0 {
		c.Limits.MaxFile = 1 << 20
	}
	if c.Limits.SessionIdle == 0 {
		c.Limits.SessionIdle = 30 * time.Minute
	}
	if c.Limits.MaxSessions == 0 {
		c.Limits.MaxSessions = 8
	}
}

// validateSSH 是 stdio 模式专属的校验：SSH 入口、私钥、至少一台机器
// （内嵌模式下机器集合来自 MCP 客户端凭据，不在配置里要求）。
func (c *Config) validateSSH() error {
	if c.Server == "" {
		return fmt.Errorf("server 必填（towstrap 服务器的 SSH 入口 host:port）")
	}
	if c.Key == "" {
		return fmt.Errorf("key 必填（登录用的无口令私钥）")
	}
	if len(c.Machines) == 0 {
		return fmt.Errorf("machines 至少要配一台（键是 towstrap 账号名）")
	}
	return nil
}

// Validate 是策略和限额的通用校验，两种模式都跑（导出给服务器内嵌模式
// 用，它没有 SSH 入口那套必填项）。
func (c *Config) Validate() error {
	switch c.Policy.Default {
	case "run", "ask", "deny":
	default:
		return fmt.Errorf("policy.default 只能是 run/ask/deny，现在是 %q", c.Policy.Default)
	}
	if c.Policy.AskTimeout <= 0 || c.Limits.Timeout <= 0 || c.Limits.MaxTimeout <= 0 {
		return fmt.Errorf("超时配置必须大于 0")
	}
	if c.Limits.Timeout > c.Limits.MaxTimeout {
		return fmt.Errorf("limits.timeout 不能大于 limits.max_timeout")
	}
	if c.Limits.MaxOutput < 1024 || c.Limits.MaxFile < 1 {
		return fmt.Errorf("limits.max_output 至少 1024、max_file 至少 1")
	}
	if c.Limits.SessionIdle <= 0 || c.Limits.MaxSessions <= 0 {
		return fmt.Errorf("limits.session_idle 和 max_sessions 必须大于 0")
	}
	if _, err := newPolicy(&c.Policy); err != nil {
		return err
	}
	return nil
}

// expandTilde 把开头的 ~ 换成家目录。只处理 "~/..." 和单独的 "~"，
// "~user" 形式不支持（本机用不到）。
func expandTilde(p string) string {
	if p == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}
