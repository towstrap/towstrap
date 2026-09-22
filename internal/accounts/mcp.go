package accounts

// MCP 客户端凭据：服务器内嵌 MCP（/mcp）的 Bearer token 认证用。
// 一个 MCPClient = 一个「能用 MCP 的客户端」（比如用户笔记本上的
// Claude Code），machines 决定它能碰哪些账号对应的机器。

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"ws2ssh/internal/proto"
)

// MCPClient 一个 MCP 客户端凭据。Machines 是它能看到的 ws2ssh 账号名
// 列表，["*"] 表示全部。
type MCPClient struct {
	Name      string    `json:"name"`
	Token     string    `json:"token"` // 解密回显用；库里只存加密值
	Machines  []string  `json:"machines"`
	AllowIPs  []string  `json:"allow_ips,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Grants 报告这个客户端能不能碰名为 machine 的账号。
func (c MCPClient) Grants(machine string) bool {
	for _, m := range c.Machines {
		if m == "*" || m == machine {
			return true
		}
	}
	return false
}

func (s *Store) encMCPToken(tok string) ([]byte, error) {
	return s.key.seal("mcptoken", []byte(tok))
}

func (s *Store) decMCPToken(blob []byte) (string, error) {
	pt, err := s.key.open("mcptoken", blob)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func newMCPToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "w2m-" + base64.RawURLEncoding.EncodeToString(b)
}

// validMachines 校验 machines 列表：非空，每项是 "*" 或合法账号名。
// 空列表意味着「什么都不能看」——不批这种客户端（fail-closed）。
func validMachines(machines []string) error {
	if len(machines) == 0 {
		return fmt.Errorf("至少要给一台机器（--machine 账号名，'*' = 全部）")
	}
	for _, m := range machines {
		if m != "*" && !proto.ValidName(m) {
			return fmt.Errorf("机器名 %q 不合法（应为 ws2ssh 账号名或 '*'）", m)
		}
	}
	return nil
}

func scanMCPClient(s *Store, name string, tokenEnc []byte, machines, allowIPs string, disabled int, createdAt string) (MCPClient, error) {
	var c MCPClient
	c.Name = name
	if tok, err := s.decMCPToken(tokenEnc); err == nil {
		c.Token = tok
	}
	_ = json.Unmarshal([]byte(machines), &c.Machines)
	_ = json.Unmarshal([]byte(allowIPs), &c.AllowIPs)
	c.Disabled = disabled != 0
	c.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return c, nil
}

const mcpCols = `name, token_enc, machines, allow_ips, disabled, created_at`

// MCPAdd 新建 MCP 客户端，返回记录和明文 token（token 只在这一刻可见，
// 之后库里只剩加密值；要看只能由管理员用 mcp token 子命令回显）。
func (s *Store) MCPAdd(name string, machines, allowIPs []string) (MCPClient, string, error) {
	if !proto.ValidName(name) {
		return MCPClient{}, "", fmt.Errorf("名字 %q 不合法，只能用字母、数字、点、下划线和短横线", name)
	}
	if err := validMachines(machines); err != nil {
		return MCPClient{}, "", err
	}
	if err := validateAllowIPs(allowIPs); err != nil {
		return MCPClient{}, "", err
	}
	token := newMCPToken()
	enc, err := s.encMCPToken(token)
	if err != nil {
		return MCPClient{}, "", err
	}
	mb, _ := json.Marshal(machines)
	ab, _ := json.Marshal(allowIPs)
	_, err = s.db.Exec(`INSERT INTO mcp_clients (name, token_enc, machines, allow_ips, disabled, created_at)
		VALUES (?, ?, ?, ?, 0, ?)`, name, enc, string(mb), string(ab), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return MCPClient{}, "", fmt.Errorf("%w: %s", ErrExists, name)
	}
	c, _ := s.MCPGet(name)
	return c, token, nil
}

// MCPGet 按名字取客户端记录。
func (s *Store) MCPGet(name string) (MCPClient, bool) {
	var (
		tokenEnc           []byte
		machines, allowIPs string
		disabled           int
		createdAt          string
	)
	err := s.db.QueryRow(`SELECT `+mcpCols+` FROM mcp_clients WHERE name = ?`, name).
		Scan(&name, &tokenEnc, &machines, &allowIPs, &disabled, &createdAt)
	if err != nil {
		return MCPClient{}, false
	}
	c, err := scanMCPClient(s, name, tokenEnc, machines, allowIPs, disabled, createdAt)
	if err != nil {
		return MCPClient{}, false
	}
	return c, true
}

// MCPList 列出全部 MCP 客户端，按名字排序。
func (s *Store) MCPList() []MCPClient {
	rows, err := s.db.Query(`SELECT ` + mcpCols + ` FROM mcp_clients ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []MCPClient
	for rows.Next() {
		var (
			name               string
			tokenEnc           []byte
			machines, allowIPs string
			disabled           int
			createdAt          string
		)
		if err := rows.Scan(&name, &tokenEnc, &machines, &allowIPs, &disabled, &createdAt); err != nil {
			continue
		}
		if c, err := scanMCPClient(s, name, tokenEnc, machines, allowIPs, disabled, createdAt); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// MCPSet 改客户端的机器集合/白名单/停用状态；nil 的字段不动。
func (s *Store) MCPSet(name string, machines *[]string, allowIPs *[]string, disabled *bool) error {
	if _, ok := s.MCPGet(name); !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if machines != nil {
		if err := validMachines(*machines); err != nil {
			return err
		}
		mb, _ := json.Marshal(*machines)
		if _, err := s.db.Exec(`UPDATE mcp_clients SET machines = ? WHERE name = ?`, string(mb), name); err != nil {
			return err
		}
	}
	if allowIPs != nil {
		if err := validateAllowIPs(*allowIPs); err != nil {
			return err
		}
		ab, _ := json.Marshal(*allowIPs)
		if _, err := s.db.Exec(`UPDATE mcp_clients SET allow_ips = ? WHERE name = ?`, string(ab), name); err != nil {
			return err
		}
	}
	if disabled != nil {
		res, err := s.db.Exec(`UPDATE mcp_clients SET disabled = ? WHERE name = ?`, boolToInt(*disabled), name)
		if err != nil {
			return err
		}
		return requireAffected(res, name)
	}
	return nil
}

// MCPRemove 删掉一个客户端（token 随之作废）。
func (s *Store) MCPRemove(name string) error {
	res, err := s.db.Exec(`DELETE FROM mcp_clients WHERE name = ?`, name)
	if err != nil {
		return err
	}
	return requireAffected(res, name)
}

// MCPRegenToken 换一个新 token，旧 token 立刻作废。
func (s *Store) MCPRegenToken(name string) (string, error) {
	if _, ok := s.MCPGet(name); !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	token := newMCPToken()
	enc, err := s.encMCPToken(token)
	if err != nil {
		return "", err
	}
	res, err := s.db.Exec(`UPDATE mcp_clients SET token_enc = ? WHERE name = ?`, enc, name)
	if err != nil {
		return "", err
	}
	if err := requireAffected(res, name); err != nil {
		return "", err
	}
	return token, nil
}

// MCPClientByToken 用 Bearer token 查客户端；token 无效或客户端停用时
// ok 为 false。
func (s *Store) MCPClientByToken(token string) (MCPClient, bool) {
	enc, err := s.encMCPToken(token)
	if err != nil {
		return MCPClient{}, false
	}
	var (
		name               string
		tokenEnc           []byte
		machines, allowIPs string
		disabled           int
		createdAt          string
	)
	err = s.db.QueryRow(`SELECT `+mcpCols+` FROM mcp_clients WHERE token_enc = ?`, enc).
		Scan(&name, &tokenEnc, &machines, &allowIPs, &disabled, &createdAt)
	if err != nil {
		return MCPClient{}, false
	}
	if disabled != 0 {
		return MCPClient{}, false
	}
	c, err := scanMCPClient(s, name, tokenEnc, machines, allowIPs, disabled, createdAt)
	if err != nil {
		return MCPClient{}, false
	}
	return c, true
}
