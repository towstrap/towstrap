package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/towstrap/towstrap/internal/mcpsrv"
)

type Server struct {
	HTTP       string   `yaml:"http"`
	SSH        string   `yaml:"ssh"`
	HostKey    string   `yaml:"host_key"`
	TLS        bool     `yaml:"tls"`
	Cert       string   `yaml:"cert"`
	Key        string   `yaml:"key"`
	UsersDB    string   `yaml:"users_db"`  // 账号 SQLite 库（towstrap user 改的就是它）
	UsersKey   string   `yaml:"users_key"` // token 加密密钥；不写用 users.db 同名的 .key
	AdminToken string   `yaml:"admin_token"`
	PublicURL  string   `yaml:"public_url"` // 用于生成 agent 安装命令，例如 wss://ssh.example.com:443
	AllowIPs   []string `yaml:"allow_ips"`  // 全局：谁能连 SSH；账号还可以再设自己的白名单
	// IdleVerify 是绑了 TOTP 的账号的空闲重验阈值（如 30m；0 关闭）。
	IdleVerify string `yaml:"idle_verify"`
	// 资源与连接上限。0 = 不限。
	MaxSessions    int    `yaml:"max_sessions"`     // 每台机器（每账号）并发 SSH 会话上限
	MaxConns       int    `yaml:"max_conns"`        // SSH/HTTP 各自并发连接总上限
	MaxConnsPerIP  int    `yaml:"max_conns_per_ip"` // SSH 每来源 IP 并发连接上限
	SSHIdleTimeout string `yaml:"ssh_idle_timeout"` // SSH 空闲超时（如 30m；0 关闭）
	SSHMaxTimeout  string `yaml:"ssh_max_timeout"`  // SSH 连接绝对寿命（如 24h；0 不限）
	// AuditLog 是服务器侧审计日志（认证成败、agent 上下线、会话开关），16MB 轮转。
	AuditLog string `yaml:"audit_log"`
	// MinAgentVersion：agent 自报版本低于此值拒绝接入（版本淘汰用；空 = 不限）
	MinAgentVersion string `yaml:"min_agent_version"`

	// MCP 是服务器内嵌 MCP（HTTP /mcp）的开关和策略；nil = 不开。
	MCP *MCP `yaml:"mcp"`
}

// MCP 是 server.yaml 里 mcp: 小节：服务器内嵌 MCP（Streamable HTTP）的
// 开关和策略。开启后客户端凭 towstrap-server mcp 子命令签发的 Bearer token
// 访问，能碰哪些机器由凭据里的 machines 决定，不是这里。
type MCP struct {
	Enabled        bool                       `yaml:"enabled"`
	Path           string                     `yaml:"path"`             // 默认 /mcp
	AllowPlainHTTP bool                       `yaml:"allow_plain_http"` // 明文 HTTP + 非回环监听时必须显式 true
	ApprovalsDir   string                     `yaml:"approvals_dir"`
	Machines       map[string]*mcpsrv.Machine `yaml:"machines"` // 每台机器的说明和 write_file 放行目录；键 = 账号名
	Policy         mcpsrv.PolicyCfg           `yaml:"policy"`
	Limits         mcpsrv.LimitsCfg           `yaml:"limits"`
}

type Agent struct {
	Server         string `yaml:"server"`
	AgentToken     string `yaml:"agent_token"`      // 直写 token（方便但建议改用文件/环境变量）
	AgentTokenFile string `yaml:"agent_token_file"` // 从 0600 文件读 token，比写进配置文件安全
	Shell          string `yaml:"shell"`
	Insecure       bool   `yaml:"insecure"`
	Quiet          bool   `yaml:"quiet"`     // 关掉会话开始/结束的通知（审计日志照写）
	AuditLog       string `yaml:"audit_log"` // 审计日志路径；空 = agent 自己的默认位置
}

type file struct {
	ServerNode      yaml.Node `yaml:"server"`
	AgentNode       yaml.Node `yaml:"agent"`
	HTTP            string    `yaml:"http"`
	SSH             string    `yaml:"ssh"`
	HostKey         string    `yaml:"host_key"`
	TLS             bool      `yaml:"tls"`
	Cert            string    `yaml:"cert"`
	Key             string    `yaml:"key"`
	UsersDB         string    `yaml:"users_db"`
	UsersKey        string    `yaml:"users_key"`
	AdminToken      string    `yaml:"admin_token"`
	PublicURL       string    `yaml:"public_url"`
	AgentToken      string    `yaml:"agent_token"`
	AgentTokenFile  string    `yaml:"agent_token_file"`
	Insecure        bool      `yaml:"insecure"`
	Shell           string    `yaml:"shell"`
	AllowIPs        []string  `yaml:"allow_ips"`
	IdleVerify      string    `yaml:"idle_verify"`
	MaxSessions     int       `yaml:"max_sessions"`
	MaxConns        int       `yaml:"max_conns"`
	MaxConnsPerIP   int       `yaml:"max_conns_per_ip"`
	SSHIdleTimeout  string    `yaml:"ssh_idle_timeout"`
	SSHMaxTimeout   string    `yaml:"ssh_max_timeout"`
	AuditLog        string    `yaml:"audit_log"`
	MinAgentVersion string    `yaml:"min_agent_version"`
	MCP             *MCP      `yaml:"mcp"`
}

func loadFile(path string) (file, error) {
	var f file
	raw, err := os.ReadFile(path)
	if err != nil {
		return f, fmt.Errorf("读配置 %s: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return f, fmt.Errorf("解析配置 %s: %w", path, err)
	}
	return f, nil
}

// LoadServer 读服务端配置。支持 `server:` 小节，或直接平铺写各字段。
func LoadServer(path string) (Server, error) {
	f, err := loadFile(path)
	if err != nil {
		return Server{}, err
	}
	if f.ServerNode.Kind == yaml.MappingNode {
		var s Server
		if err := f.ServerNode.Decode(&s); err != nil {
			return Server{}, fmt.Errorf("解析 server: %w", err)
		}
		return s, nil
	}
	return Server{
		HTTP:            f.HTTP,
		SSH:             f.SSH,
		HostKey:         f.HostKey,
		TLS:             f.TLS,
		Cert:            f.Cert,
		Key:             f.Key,
		UsersDB:         f.UsersDB,
		UsersKey:        f.UsersKey,
		AdminToken:      f.AdminToken,
		PublicURL:       f.PublicURL,
		AllowIPs:        f.AllowIPs,
		IdleVerify:      f.IdleVerify,
		MaxSessions:     f.MaxSessions,
		MaxConns:        f.MaxConns,
		MaxConnsPerIP:   f.MaxConnsPerIP,
		SSHIdleTimeout:  f.SSHIdleTimeout,
		SSHMaxTimeout:   f.SSHMaxTimeout,
		AuditLog:        f.AuditLog,
		MinAgentVersion: f.MinAgentVersion,
		MCP:             f.MCP,
	}, nil
}

// LoadAgent 读 agent 配置。支持 `agent:` 小节，或平铺；
// 平铺时 `server` 写服务器地址，例如 `server: wss://1.2.3.4:443`。
func LoadAgent(path string) (Agent, error) {
	f, err := loadFile(path)
	if err != nil {
		return Agent{}, err
	}
	if f.AgentNode.Kind == yaml.MappingNode {
		var a Agent
		if err := f.AgentNode.Decode(&a); err != nil {
			return Agent{}, fmt.Errorf("解析 agent: %w", err)
		}
		return a, nil
	}
	serverURL := ""
	if f.ServerNode.Kind == yaml.ScalarNode {
		serverURL = f.ServerNode.Value
	}
	return Agent{
		Server:         serverURL,
		AgentToken:     f.AgentToken,
		AgentTokenFile: f.AgentTokenFile,
		Shell:          f.Shell,
		Insecure:       f.Insecure,
	}, nil
}

// MergeServer 合并配置文件和命令行（命令行写过的项覆盖文件），并给出默认值。
func MergeServer(file Server, set map[string]string) Server {
	out := Server{
		HTTP:          ":8080",
		SSH:           ":2222",
		UsersDB:       "/etc/towstrap/users.db",
		AdminToken:    file.AdminToken,
		PublicURL:     file.PublicURL,
		TLS:           file.TLS,
		Cert:          file.Cert,
		Key:           file.Key,
		AllowIPs:      append([]string{}, file.AllowIPs...),
		IdleVerify:    "30m",
		MaxSessions:   16,
		MaxConns:      4096,
		MaxConnsPerIP: 64,
		SSHMaxTimeout: "24h",
	}
	if file.IdleVerify != "" {
		out.IdleVerify = file.IdleVerify
	}
	if file.MaxSessions != 0 {
		out.MaxSessions = file.MaxSessions
	}
	if file.MaxConns != 0 {
		out.MaxConns = file.MaxConns
	}
	if file.MaxConnsPerIP != 0 {
		out.MaxConnsPerIP = file.MaxConnsPerIP
	}
	if file.SSHIdleTimeout != "" {
		out.SSHIdleTimeout = file.SSHIdleTimeout
	}
	if file.SSHMaxTimeout != "" {
		out.SSHMaxTimeout = file.SSHMaxTimeout
	}
	if file.HTTP != "" {
		out.HTTP = file.HTTP
	}
	if file.SSH != "" {
		out.SSH = file.SSH
	}
	if file.HostKey != "" {
		out.HostKey = file.HostKey
	}
	if file.UsersDB != "" {
		out.UsersDB = file.UsersDB
	}
	if file.UsersKey != "" {
		out.UsersKey = file.UsersKey
	}
	if v, ok := set["http"]; ok {
		out.HTTP = v
	}
	if v, ok := set["ssh"]; ok {
		out.SSH = v
	}
	if v, ok := set["host-key"]; ok {
		out.HostKey = v
	}
	if v, ok := set["users-db"]; ok {
		out.UsersDB = v
	}
	if v, ok := set["users-key"]; ok {
		out.UsersKey = v
	}
	if v, ok := set["admin-token"]; ok {
		out.AdminToken = v
	}
	if v, ok := set["public-url"]; ok {
		out.PublicURL = v
	}
	if v, ok := set["cert"]; ok {
		out.Cert = v
	}
	if v, ok := set["key"]; ok {
		out.Key = v
	}
	if v, ok := set["tls"]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			out.TLS = b
		}
	}
	if v, ok := set["idle-verify"]; ok {
		out.IdleVerify = v
	}
	if v, ok := set["max-sessions"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			out.MaxSessions = n
		}
	}
	if v, ok := set["max-conns"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			out.MaxConns = n
		}
	}
	if v, ok := set["max-conns-per-ip"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			out.MaxConnsPerIP = n
		}
	}
	if v, ok := set["ssh-idle-timeout"]; ok {
		out.SSHIdleTimeout = v
	}
	if v, ok := set["ssh-max-timeout"]; ok {
		out.SSHMaxTimeout = v
	}
	if v, ok := set["audit-log"]; ok {
		out.AuditLog = v
	}
	if v, ok := set["min-agent-version"]; ok {
		out.MinAgentVersion = v
	}
	// mcp: 小节没有对应命令行旗标，yaml 里写了就透传。
	out.MCP = file.MCP
	// 主机密钥默认跟着 users.db 走（同目录），不写死当前目录——服务常从
	// 别的工作目录启动，密钥落哪得可预期。
	if out.HostKey == "" {
		out.HostKey = filepath.Join(filepath.Dir(out.UsersDB), "ssh_host_key")
	}
	return out
}

func MergeAgent(file Agent, set map[string]string) Agent {
	out := file
	if v, ok := set["server"]; ok {
		out.Server = v
	}
	if v, ok := set["agent-token"]; ok {
		out.AgentToken = v
	}
	if v, ok := set["agent-token-file"]; ok {
		out.AgentTokenFile = v
	}
	if v, ok := set["shell"]; ok {
		out.Shell = v
	}
	if v, ok := set["insecure"]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			out.Insecure = b
		}
	}
	if v, ok := set["quiet"]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			out.Quiet = b
		}
	}
	if v, ok := set["audit-log"]; ok {
		out.AuditLog = v
	}
	return out
}

// AgentInstallHint 生成把 agent 装到目标机上的提示文案。publicURL 为空时
// 用占位符并提醒把地址换成实际的。CLI 和 SSH 自助管理命令共用。
func AgentInstallHint(publicURL, token string) string {
	url := publicURL
	if url == "" {
		url = "wss://<服务器>:<端口>"
	}
	s := fmt.Sprintf("在那台机器上执行 agent 安装命令：\n  towstrap-agent --server %s --agent-token %s", url, token)
	if publicURL == "" {
		s += "\n（服务器没配 public_url，请把上面的地址换成实际地址）"
	}
	return s
}
