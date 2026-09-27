package accounts

// 账号 CRUD：增删改、密码、白名单、改名、令牌重置。查询侧留在 accounts.go。

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/proto"
)

// ---- 账号操作 ----

// Add 新建账号，并自动建一台名为 default 的机器（agentAllowIPs 落到它
// 身上），返回的 Account.Machines[0] 带明文 token。contact 是可选的
// 追溯备注。多机器用 AddMachine。
func (s *Store) Add(username, password string, allowIPs []string, contact string, agentAllowIPs []string) (Account, error) {
	if !proto.ValidName(username) {
		return Account{}, fmt.Errorf("%w: 用户名 %q 不合法，只能用字母、数字、点、下划线和短横线", ErrBadInput, username)
	}
	if err := validPassword(password); err != nil {
		return Account{}, err
	}
	if err := validateAllowIPs(allowIPs); err != nil {
		return Account{}, err
	}
	if err := validateAllowIPs(agentAllowIPs); err != nil {
		return Account{}, fmt.Errorf("agent 来源白名单: %w", err)
	}
	hash, err := hashPassword(password)
	if err != nil {
		return Account{}, err
	}
	tok, err := s.newUniqueToken()
	if err != nil {
		return Account{}, err
	}
	ips, _ := json.Marshal(allowIPs)
	agentIPs, _ := json.Marshal(agentAllowIPs)
	tEnc, err := s.encToken(tok)
	if err != nil {
		return Account{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(
		`INSERT INTO users (username, password_hash, contact, allow_ips, disabled, created_at)
		 VALUES (?, ?, ?, ?, 0, ?)`,
		username, hash, cleanText(contact), string(ips), now,
	)
	if err != nil {
		if isUniqueErr(err) {
			return Account{}, fmt.Errorf("%w: %s", ErrExists, username)
		}
		return Account{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO machines (username, name, token_enc, agent_allow_ips, agent_last_ip, created_at)
		 VALUES (?, ?, ?, ?, '', ?)`,
		username, DefaultMachine, tEnc, string(agentIPs), now); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	return Account{
		Username: username,
		Contact:  contact,
		AllowIPs: append([]string{}, allowIPs...),
		Machines: []Machine{{
			Username:      username,
			Name:          DefaultMachine,
			Token:         tok,
			AgentAllowIPs: append([]string{}, agentAllowIPs...),
			CreatedAt:     time.Now(),
		}},
		CreatedAt: time.Now(),
	}, nil
}

// Remove 删除账号，连带删掉它名下全部机器；那些机器的 agent 会因 token
// 失效被巡检断开。
func (s *Store) Remove(username string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM machines WHERE username = ?`, username); err != nil {
		return err
	}
	// 账号没了，它占的机器指纹一并释放，那台机器以后还能再注册
	if _, err := tx.Exec(`DELETE FROM register_fps WHERE username = ?`, username); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM users WHERE username = ?`, username)
	if err != nil {
		return err
	}
	if err := requireAffected(res, username); err != nil {
		return err
	}
	return tx.Commit()
}

// SetPassword 改 SSH 密码（重新 bcrypt，带新的随机盐）。
func (s *Store) SetPassword(username, password string) error {
	if err := validPassword(password); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE username = ?`, hash, username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// SetAllow 设置这个账号的 IP 白名单；传空表示不限。
func (s *Store) SetAllow(username string, ips []string) error {
	if err := validateAllowIPs(ips); err != nil {
		return err
	}
	blob, _ := json.Marshal(ips)
	res, err := s.db.Exec(`UPDATE users SET allow_ips = ? WHERE username = ?`, string(blob), username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// SetDisabled 启用/停用账号；停用后 SSH 和 agent 都进不来。
func (s *Store) SetDisabled(username string, disabled bool) error {
	res, err := s.db.Exec(`UPDATE users SET disabled = ? WHERE username = ?`, boolToInt(disabled), username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// SetContact 设置追溯备注（负责人/联系方式），不参与任何认证。控制字符在
// 写入时清掉：这串字会原样打印到终端（user list），不能让它带终端转义序列。
func (s *Store) SetContact(username, contact string) error {
	res, err := s.db.Exec(`UPDATE users SET contact = ? WHERE username = ?`, cleanText(contact), username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// SetAgentAllow 兼容包装：只作用于账号恰有一台机器的情况（CLI 老用法）；
// 多台机器请用 SetMachineAgentAllow 指定哪台。
func (s *Store) SetAgentAllow(username string, ips []string) error {
	m, err := s.soleMachine(username)
	if err != nil {
		return err
	}
	return s.SetMachineAgentAllow(username, m.Name, ips)
}

// soleMachine 取账号唯一的机器；0 台或不止一台都报错（调用方文案自行翻译）。
func (s *Store) soleMachine(username string) (Machine, error) {
	ms := s.Machines(username)
	switch len(ms) {
	case 0:
		return Machine{}, fmt.Errorf("%w: %s 没有机器", ErrNotFound, username)
	case 1:
		return ms[0], nil
	default:
		return Machine{}, fmt.Errorf("账号 %s 有多台机器，请用 machine 子命令指定（如 %s+%s）", username, username, ms[0].Name)
	}
}

// addrHost 取地址里的主机部分（去端口）；取不出就原样返回。
func addrHost(addr net.Addr) string {
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

// cleanText 去掉控制字符（换行、终端转义等），保留正常文本。
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// Rename 改用户名；agent 不用动（它靠 token 认，不靠名字）。账号下的
// machines.username 同事务联动。
func (s *Store) Rename(oldName, newName string) error {
	if !proto.ValidName(newName) {
		return fmt.Errorf("%w: 用户名 %q 不合法，只能用字母、数字、点、下划线和短横线", ErrBadInput, newName)
	}
	var one int
	if err := s.db.QueryRow(`SELECT 1 FROM users WHERE username = ?`, newName).Scan(&one); err == nil {
		return fmt.Errorf("%w: %s", ErrExists, newName)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE users SET username = ? WHERE username = ?`, newName, oldName)
	if err != nil {
		// 并发下可能恰好有人抢注了新名，UNIQUE 报错也归为重名。
		if isUniqueErr(err) {
			return fmt.Errorf("%w: %s", ErrExists, newName)
		}
		return err
	}
	if err := requireAffected(res, oldName); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE machines SET username = ? WHERE username = ?`, newName, oldName); err != nil {
		return err
	}
	return tx.Commit()
}

// RegenToken 兼容包装：换账号唯一那台机器的 token；多台机器请用
// RegenMachineToken 指定哪台。
func (s *Store) RegenToken(username string) (string, error) {
	m, err := s.soleMachine(username)
	if err != nil {
		return "", err
	}
	return s.RegenMachineToken(username, m.Name)
}

// Get 返回账号副本（含机器列表）。
