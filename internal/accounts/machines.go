package accounts

// 机器（agent）是账号下的独立实体：一个账号（人/凭据）可以挂多台机器，
// 每台机器有自己的 token 和 agent 来源白名单，可单独撤权。机器的完整
// 标识是「账号+机器名」（如 alice+office）——「+」不在 proto.ValidName
// 字符集里，第一个 + 一定是分隔符。

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"ws2ssh/internal/allow"
	"ws2ssh/internal/proto"
)

// DefaultMachine 是账号默认机器的名字：user add 自动建一台，老库迁移
// 也把原 token 归到这台名下。
const DefaultMachine = "default"

// Machine 一台被控机。Token 是这台机器的 agent 连接令牌（库里加密存）。
type Machine struct {
	Username      string    `json:"username"`
	Name          string    `json:"name"`
	Token         string    `json:"token"`
	AgentAllowIPs []string  `json:"agent_allow_ips,omitempty"`
	AgentLastIP   string    `json:"agent_last_ip,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// ID 是机器的完整标识：账号+机器名。
func (m Machine) ID() string { return m.Username + "+" + m.Name }

// SplitMachineID 把 "alice+office" 拆成 ("alice","office")；没有 + 时
// machine 为空（表示「整个账号」而不是某一台）。
func SplitMachineID(id string) (username, machine string) {
	for i := 0; i < len(id); i++ {
		if id[i] == '+' {
			return id[:i], id[i+1:]
		}
	}
	return id, ""
}

const machineCols = `username, name, token_enc, agent_allow_ips, agent_last_ip, created_at`

func scanMachine(s *Store, r rowScanner) (Machine, error) {
	var (
		username, name string
		tEnc           []byte
		allowBlob      string
		lastIP         string
		createdAt      string
	)
	if err := r.Scan(&username, &name, &tEnc, &allowBlob, &lastIP, &createdAt); err != nil {
		return Machine{}, err
	}
	tok, err := s.decToken(tEnc)
	if err != nil {
		return Machine{}, err
	}
	var ips []string
	_ = json.Unmarshal([]byte(allowBlob), &ips)
	created, _ := time.Parse(time.RFC3339, createdAt)
	return Machine{
		Username:      username,
		Name:          name,
		Token:         tok,
		AgentAllowIPs: ips,
		AgentLastIP:   lastIP,
		CreatedAt:     created,
	}, nil
}

// newUniqueToken 生成不与现有机器重复的 token。
func (s *Store) newUniqueToken() (string, error) {
	for i := 0; i < 10; i++ {
		tok := randomToken()
		enc, err := s.encToken(tok)
		if err != nil {
			return "", err
		}
		var one int
		err = s.db.QueryRow(`SELECT 1 FROM machines WHERE token_enc = ?`, enc).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return tok, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("生成唯一 token 失败")
}

// AddMachine 在账号下加一台机器，返回带明文 token 的记录（token 只在
// 这一刻可见，之后库里只剩加密值）。账号不存在报 ErrNotFound，同名
// 机器报 ErrExists。
func (s *Store) AddMachine(username, name string, agentAllowIPs []string) (Machine, error) {
	if !proto.ValidName(name) {
		return Machine{}, fmt.Errorf("机器名 %q 不合法，只能用字母、数字、点、下划线和短横线", name)
	}
	if err := validateAllowIPs(agentAllowIPs); err != nil {
		return Machine{}, fmt.Errorf("agent 来源白名单: %w", err)
	}
	var one int
	if err := s.db.QueryRow(`SELECT 1 FROM users WHERE username = ?`, username).Scan(&one); err != nil {
		return Machine{}, fmt.Errorf("%w: %s", ErrNotFound, username)
	}
	tok, err := s.newUniqueToken()
	if err != nil {
		return Machine{}, err
	}
	enc, err := s.encToken(tok)
	if err != nil {
		return Machine{}, err
	}
	ips, _ := json.Marshal(agentAllowIPs)
	_, err = s.db.Exec(
		`INSERT INTO machines (username, name, token_enc, agent_allow_ips, agent_last_ip, created_at)
		 VALUES (?, ?, ?, ?, '', ?)`,
		username, name, enc, string(ips), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return Machine{}, fmt.Errorf("%w: %s+%s", ErrExists, username, name)
	}
	return Machine{
		Username:      username,
		Name:          name,
		Token:         tok,
		AgentAllowIPs: append([]string{}, agentAllowIPs...),
		CreatedAt:     time.Now(),
	}, nil
}

// RemoveMachine 删掉一台机器（token 随之作废，连着的 agent 会被巡检断开）。
func (s *Store) RemoveMachine(username, name string) error {
	res, err := s.db.Exec(`DELETE FROM machines WHERE username = ? AND name = ?`, username, name)
	if err != nil {
		return err
	}
	return requireAffected(res, username+"+"+name)
}

// Machines 列出账号下全部机器，按机器名排序。
func (s *Store) Machines(username string) []Machine {
	rows, err := s.db.Query(`SELECT `+machineCols+` FROM machines WHERE username = ? ORDER BY name`, username)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Machine
	for rows.Next() {
		if m, err := scanMachine(s, rows); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// machinesByUser 一次查全表按账号归并（List 用，别为每个账号查一次）。
func (s *Store) machinesByUser() map[string][]Machine {
	rows, err := s.db.Query(`SELECT ` + machineCols + ` FROM machines ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[string][]Machine{}
	for rows.Next() {
		if m, err := scanMachine(s, rows); err == nil {
			out[m.Username] = append(out[m.Username], m)
		}
	}
	return out
}

// GetMachine 取一台机器。
func (s *Store) GetMachine(username, name string) (Machine, bool) {
	m, err := scanMachine(s, s.db.QueryRow(
		`SELECT `+machineCols+` FROM machines WHERE username = ? AND name = ?`, username, name))
	if err != nil {
		return Machine{}, false
	}
	return m, true
}

// MachineByToken 用 agent token 查机器；token 无效、机器不存在或所属
// 账号停用时 ok 为 false。
func (s *Store) MachineByToken(token string) (Machine, bool) {
	enc, err := s.encToken(token)
	if err != nil {
		return Machine{}, false
	}
	m, err := scanMachine(s, s.db.QueryRow(
		`SELECT `+machineCols+` FROM machines WHERE token_enc = ?`, enc))
	if err != nil {
		return Machine{}, false
	}
	var disabled int
	err = s.db.QueryRow(`SELECT disabled FROM users WHERE username = ?`, m.Username).Scan(&disabled)
	if err != nil || disabled != 0 {
		return Machine{}, false
	}
	return m, true
}

// RegenMachineToken 换一台机器的 token，旧 token 立刻作废。
func (s *Store) RegenMachineToken(username, name string) (string, error) {
	tok, err := s.newUniqueToken()
	if err != nil {
		return "", err
	}
	enc, err := s.encToken(tok)
	if err != nil {
		return "", err
	}
	res, err := s.db.Exec(`UPDATE machines SET token_enc = ? WHERE username = ? AND name = ?`,
		enc, username, name)
	if err != nil {
		return "", err
	}
	if err := requireAffected(res, username+"+"+name); err != nil {
		return "", err
	}
	return tok, nil
}

// SetMachineToken 把一台机器的 token 换成指定值（换发流程里 agent 已确认
// 写进文件后落库）。token 撞了 UNIQUE 约束照常报错——那台 agent 的文件
// 已经改了，调用方要按「需人工处理」告警。
func (s *Store) SetMachineToken(username, name, token string) error {
	enc, err := s.encToken(token)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE machines SET token_enc = ? WHERE username = ? AND name = ?`,
		enc, username, name)
	if err != nil {
		return err
	}
	return requireAffected(res, username+"+"+name)
}

// SetMachineAgentAllow 设置一台机器的 agent 来源白名单；传空表示不限。
func (s *Store) SetMachineAgentAllow(username, name string, ips []string) error {
	if err := validateAllowIPs(ips); err != nil {
		return fmt.Errorf("agent 来源白名单: %w", err)
	}
	blob, _ := json.Marshal(ips)
	res, err := s.db.Exec(`UPDATE machines SET agent_allow_ips = ? WHERE username = ? AND name = ?`,
		string(blob), username, name)
	if err != nil {
		return err
	}
	return requireAffected(res, username+"+"+name)
}

// CheckAgentIP 在 agent 连接时校验这台机器的来源：设了白名单就硬校验；
// 没设放行但把这次的来源记成 agent_last_ip（拒绝的不记），并返回上次
// 来源——调用方用它识别「换了地方连」。
func (s *Store) CheckAgentIP(username, name string, remote net.Addr) (prev string, err error) {
	var allowBlob, prevIP string
	err = s.db.QueryRow(
		`SELECT agent_allow_ips, agent_last_ip FROM machines WHERE username = ? AND name = ?`,
		username, name).Scan(&allowBlob, &prevIP)
	if err != nil {
		return "", fmt.Errorf("%w: %s+%s", ErrNotFound, username, name)
	}
	var items []string
	_ = json.Unmarshal([]byte(allowBlob), &items)
	if len(items) > 0 {
		list, perr := allow.Parse(items)
		if perr != nil {
			return "", fmt.Errorf("机器 %s+%s 的 agent 来源白名单配置无效: %w", username, name, perr)
		}
		if !list.AllowsAddr(remote) {
			return prevIP, fmt.Errorf("来源 %s 不在机器 %s+%s 的 agent 来源白名单里",
				addrHost(remote), username, name)
		}
	}
	ip := addrHost(remote)
	if ip != prevIP {
		if _, uerr := s.db.Exec(`UPDATE machines SET agent_last_ip = ? WHERE username = ? AND name = ?`,
			ip, username, name); uerr != nil {
			return prevIP, uerr
		}
	}
	return prevIP, nil
}

// MachineBrief 是不解密 token 的机器摘要：/status 这种高频路径用。
type MachineBrief struct {
	ID       string // username+name
	Username string
	Name     string
	Disabled bool // 所属账号是否停用
}

// ListMachinesBasic 列出全部机器（含所属账号停用状态），按 ID 排序。
func (s *Store) ListMachinesBasic() []MachineBrief {
	rows, err := s.db.Query(
		`SELECT m.username, m.name, u.disabled FROM machines m
		 JOIN users u ON u.username = m.username ORDER BY m.username, m.name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []MachineBrief
	for rows.Next() {
		var b MachineBrief
		var disabled int
		if err := rows.Scan(&b.Username, &b.Name, &disabled); err != nil {
			continue
		}
		b.ID = b.Username + "+" + b.Name
		b.Disabled = disabled != 0
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
