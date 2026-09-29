package accounts

// MCP 客户端凭据：服务器内嵌 MCP（/mcp）的 Bearer token 认证用。
// 一个 MCPClient = 一个「能用 MCP 的客户端」（比如用户笔记本上的
// Claude Code），machines 决定它能碰哪些账号对应的机器。

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/proto"
)

// MCPClient 一个 MCP 客户端凭据。Machines 是它能看到的 towstrap 账号名
// 列表，["*"] 表示全部。Owner 是「谁有权在 @mcp 里管理它」——账号本人
// 自签时等于该账号，管理员签发的留空（只有管理员 CLI 管得了）。
type MCPClient struct {
	Name      string    `json:"name"`
	Owner     string    `json:"owner,omitempty"`
	Token     string    `json:"token"` // 解密回显用；库里只存加密值
	Machines  []string  `json:"machines"`
	AllowIPs  []string  `json:"allow_ips,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Grants 报告这个客户端能不能碰名为 machine 的目标。machines 条目支持
// "*"（全部）、"alice" / "alice+*"（账号下全部机器）和 "alice+office"
// （指定一台）。
func (c MCPClient) Grants(machine string) bool {
	targetUser, targetMachine := SplitMachineID(machine)
	for _, m := range c.Machines {
		if m == "*" || m == machine {
			return true
		}
		specUser, specMachine := SplitMachineID(m)
		if specUser != targetUser {
			continue
		}
		if specMachine == "" || specMachine == "*" {
			return true
		}
		// spec 是单台机器时按拆好的两段比：demo+local 的规则同样
		// 命中 demo/local 这种别名写法。
		if targetMachine != "" && specMachine == targetMachine {
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
	return "tsm-" + base64.RawURLEncoding.EncodeToString(b)
}

// validMachines 校验 machines 列表：非空，每项是四种写法之一：
//
//	"*"            全部账号的全部机器
//	"alice"        alice 账号的全部机器
//	"alice+*"      同上（显式通配）
//	"alice+office" 指定一台机器
//
// 空列表意味着「什么都不能看」——不批这种客户端（fail-closed）。
func validMachines(machines []string) error {
	if len(machines) == 0 {
		return fmt.Errorf("至少要给一台机器（--machine 账号[+机器名]，'*' = 全部）")
	}
	for _, m := range machines {
		if m == "*" {
			continue
		}
		u, mn := SplitMachineID(m)
		switch {
		case u == "." || u == ".." || !proto.ValidName(u):
			return fmt.Errorf("机器 %q 的账号部分不合法（应为 towstrap 账号名或 '*'）", m)
		case mn == "." || mn == ".." || (mn != "" && mn != "*" && !proto.ValidName(mn)):
			return fmt.Errorf("机器 %q 的机器名部分不合法", m)
		}
	}
	return nil
}

func scanMCPClient(s *Store, name, owner string, tokenEnc []byte, machines, allowIPs string, disabled int, createdAt string) (MCPClient, error) {
	var c MCPClient
	c.Name = name
	c.Owner = owner
	if tok, err := s.decMCPToken(tokenEnc); err == nil {
		c.Token = tok
	}
	_ = json.Unmarshal([]byte(machines), &c.Machines)
	_ = json.Unmarshal([]byte(allowIPs), &c.AllowIPs)
	c.Disabled = disabled != 0
	c.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return c, nil
}

const mcpCols = `name, owner, token_enc, machines, allow_ips, disabled, created_at`

// MCPAdd 新建 MCP 客户端，返回记录和明文 token（token 只在这一刻可见，
// 之后库里只剩加密值；要看只能由管理员用 mcp token 子命令回显）。
// owner 是归属账号：@mcp 自助签发时传当前登录账号，管理员 CLI 传 ""。
func (s *Store) MCPAdd(name, owner string, machines, allowIPs []string) (MCPClient, string, error) {
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
	_, err = s.db.Exec(`INSERT INTO mcp_clients (name, owner, token_enc, machines, allow_ips, disabled, created_at)
		VALUES (?, ?, ?, ?, ?, 0, ?)`, name, owner, enc, string(mb), string(ab), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return MCPClient{}, "", fmt.Errorf("%w: %s", ErrExists, name)
	}
	c, _ := s.MCPGet(name)
	return c, token, nil
}

// MCPGet 按名字取客户端记录。
func (s *Store) MCPGet(name string) (MCPClient, bool) {
	return s.mcpGet(`WHERE name = ?`, name)
}

// MCPOwnedGet 取「属于 owner 且名为 name」的客户端。@mcp 自助面一律走这里：
// 归属由 owner 列判定，不靠名字前缀猜——账号名允许点号，前缀不是无歧义的
// 名字空间（账号 alice.bob 的 laptop 会被账号 alice 拼成同一个库内名字）。
// owner 空值一律按「不存在」处理：owner=” 是管理员签发的正常行，没这层
// 挡板，谁把空 owner 传进来就等于摸到了管理员名下全部客户端。
func (s *Store) MCPOwnedGet(owner, name string) (MCPClient, bool) {
	if owner == "" {
		return MCPClient{}, false
	}
	return s.mcpGet(`WHERE owner = ? AND name = ?`, owner, name)
}

func (s *Store) mcpGet(where string, args ...any) (MCPClient, bool) {
	var (
		name, owner        string
		tokenEnc           []byte
		machines, allowIPs string
		disabled           int
		createdAt          string
	)
	err := s.db.QueryRow(`SELECT `+mcpCols+` FROM mcp_clients `+where, args...).
		Scan(&name, &owner, &tokenEnc, &machines, &allowIPs, &disabled, &createdAt)
	if err != nil {
		return MCPClient{}, false
	}
	c, err := scanMCPClient(s, name, owner, tokenEnc, machines, allowIPs, disabled, createdAt)
	if err != nil {
		return MCPClient{}, false
	}
	return c, true
}

// MCPList 列出全部 MCP 客户端，按名字排序。
func (s *Store) MCPList() []MCPClient {
	return s.mcpList(`SELECT ` + mcpCols + ` FROM mcp_clients ORDER BY name`)
}

// MCPOwnedList 只列属于 owner 的客户端。@mcp list 走这里：按 owner 列
// 过滤，不按名字前缀——前缀会把别人账号名里带点的（如 alice.bob.*）也算进来。
func (s *Store) MCPOwnedList(owner string) []MCPClient {
	if owner == "" {
		return nil // owner='' 是管理员签发：见 MCPOwnedGet 的说明
	}
	return s.mcpList(`SELECT `+mcpCols+` FROM mcp_clients WHERE owner = ? ORDER BY name`, owner)
}

func (s *Store) mcpList(query string, args ...any) []MCPClient {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []MCPClient
	for rows.Next() {
		var (
			name, owner        string
			tokenEnc           []byte
			machines, allowIPs string
			disabled           int
			createdAt          string
		)
		if err := rows.Scan(&name, &owner, &tokenEnc, &machines, &allowIPs, &disabled, &createdAt); err != nil {
			continue
		}
		if c, err := scanMCPClient(s, name, owner, tokenEnc, machines, allowIPs, disabled, createdAt); err == nil {
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
	return s.mcpSet(name, []any{name}, machines, allowIPs, disabled)
}

// MCPOwnedSet 只改属于 owner 的客户端。@mcp set 走这里：改 machines 等于
// 改这把 token 能碰哪些机器，归属判错就是越权放大。
func (s *Store) MCPOwnedSet(owner, name string, machines *[]string, allowIPs *[]string, disabled *bool) error {
	if _, ok := s.MCPOwnedGet(owner, name); !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return s.mcpSet(name, []any{owner, name}, machines, allowIPs, disabled)
}

// mcpSet 的共同实现：where/args 是同库两种归属条件（按名字 / 按 owner+名字），
// label 只用于报错文案。存在性由调用方先查好。
func (s *Store) mcpSet(label string, keys []any, machines *[]string, allowIPs *[]string, disabled *bool) error {
	upd := func(col string, val any) error {
		_, err := s.db.Exec(`UPDATE mcp_clients SET `+col+` = ? WHERE `+mcpKeyWhere(len(keys)), append([]any{val}, keys...)...)
		return err
	}
	if machines != nil {
		if err := validMachines(*machines); err != nil {
			return err
		}
		mb, _ := json.Marshal(*machines)
		if err := upd("machines", string(mb)); err != nil {
			return err
		}
	}
	if allowIPs != nil {
		if err := validateAllowIPs(*allowIPs); err != nil {
			return err
		}
		ab, _ := json.Marshal(*allowIPs)
		if err := upd("allow_ips", string(ab)); err != nil {
			return err
		}
	}
	if disabled != nil {
		res, err := s.db.Exec(`UPDATE mcp_clients SET disabled = ? WHERE `+mcpKeyWhere(len(keys)),
			append([]any{boolToInt(*disabled)}, keys...)...)
		if err != nil {
			return err
		}
		return requireAffected(res, label)
	}
	return nil
}

// mcpKeyWhere 按 key 个数给出归属条件：1 个是库内全名，2 个是 owner+全名。
func mcpKeyWhere(n int) string {
	if n == 2 {
		return `owner = ? AND name = ?`
	}
	return `name = ?`
}

// MCPRemove 删掉一个客户端（token 随之作废）。
func (s *Store) MCPRemove(name string) error {
	res, err := s.db.Exec(`DELETE FROM mcp_clients WHERE name = ?`, name)
	if err != nil {
		return err
	}
	return requireAffected(res, name)
}

// MCPOwnedRemove 只删属于 owner 的客户端。@mcp remove 走这里。
func (s *Store) MCPOwnedRemove(owner, name string) error {
	if owner == "" {
		return fmt.Errorf("%w: %s", ErrNotFound, name) // 见 MCPOwnedGet
	}
	res, err := s.db.Exec(`DELETE FROM mcp_clients WHERE owner = ? AND name = ?`, owner, name)
	if err != nil {
		return err
	}
	return requireAffected(res, name)
}

// MCPSetOwner 移交/收回客户端归属。owner 非空 = 移交给该账号：账号必须
// 真实存在，同时把名字收敛成「账号.短名」规范形——@mcp 自助面按全名+
// owner 双条件寻址，只改 owner 不改名，用户照样够不到这条凭据。短名取
// 名字第一个点之后的部分（无点就用全名）。owner 为空 = 收回管理员名下，
// 只清归属、不动名字（带点的名字管理员照旧按原名操作）。
// 返回最终名字（移交时可能已改过），供调用方回显。
func (s *Store) MCPSetOwner(name, owner string) (string, error) {
	if _, ok := s.MCPGet(name); !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	newName := name
	if owner != "" {
		var exists int
		if err := s.db.QueryRow(`SELECT 1 FROM users WHERE username = ?`, owner).Scan(&exists); err != nil {
			return "", fmt.Errorf("账号 %q 不存在", owner)
		}
		short := name
		if i := strings.IndexByte(name, '.'); i >= 0 {
			short = name[i+1:]
		}
		if short == "" {
			return "", fmt.Errorf("%q 拆不出短名，没法收敛成「账号.短名」交给自助面", name)
		}
		newName = owner + "." + short
	}
	// name 列全局唯一——新名被占时 UPDATE 撞约束，正好当冲突检查用。
	res, err := s.db.Exec(`UPDATE mcp_clients SET owner = ?, name = ? WHERE name = ?`, owner, newName, name)
	if err != nil {
		return "", fmt.Errorf("移交 %q 给 %q 失败（多半是改后名字已被占用）: %w", name, owner, err)
	}
	if err := requireAffected(res, name); err != nil {
		return "", err
	}
	return newName, nil
}

// MCPRegenToken 换一个新 token，旧 token 立刻作废。
func (s *Store) MCPRegenToken(name string) (string, error) {
	if _, ok := s.MCPGet(name); !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return s.mcpRegen(name, `WHERE name = ?`, name)
}

// MCPOwnedRegenToken 只给属于 owner 的客户端换 token。@mcp token --regen
// 走这里：换发会把新明文 token 打印给操作者，归属判错等于凭据外送。
func (s *Store) MCPOwnedRegenToken(owner, name string) (string, error) {
	if _, ok := s.MCPOwnedGet(owner, name); !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return s.mcpRegen(name, `WHERE owner = ? AND name = ?`, owner, name)
}

// mcpRegen 换 token 的共同实现：label 只用于报错文案，where/args 是同库
// 里两种归属条件（按名字 / 按 owner+名字）。
func (s *Store) mcpRegen(label, where string, args ...any) (string, error) {
	token := newMCPToken()
	enc, err := s.encMCPToken(token)
	if err != nil {
		return "", err
	}
	res, err := s.db.Exec(`UPDATE mcp_clients SET token_enc = ? `+where, append([]any{enc}, args...)...)
	if err != nil {
		return "", err
	}
	if err := requireAffected(res, label); err != nil {
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
		name, owner        string
		tokenEnc           []byte
		machines, allowIPs string
		disabled           int
		createdAt          string
	)
	err = s.db.QueryRow(`SELECT `+mcpCols+` FROM mcp_clients WHERE token_enc = ?`, enc).
		Scan(&name, &owner, &tokenEnc, &machines, &allowIPs, &disabled, &createdAt)
	if err != nil {
		return MCPClient{}, false
	}
	if disabled != 0 {
		return MCPClient{}, false
	}
	c, err := scanMCPClient(s, name, owner, tokenEnc, machines, allowIPs, disabled, createdAt)
	if err != nil {
		return MCPClient{}, false
	}
	return c, true
}
