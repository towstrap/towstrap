package accounts

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	gossh "golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"

	"ws2ssh/internal/allow"
	"ws2ssh/internal/proto"
	"ws2ssh/internal/totp"
)

var (
	ErrNotFound = errors.New("账号不存在")
	ErrExists   = errors.New("账号已存在")
)

// Account 一个账号对应一台要被访问的机器：
// 外人用 Username/Password 走 SSH 登录，那台机器上的 agent 用 Token 连服务器。
// 数据库里 Username 明文存放（注册查重、登录查询都按它来），Token 和 TOTP
// 秘钥是 AES-GCM 加密存的，Password 是 bcrypt（自带随机盐）。
// Contact 是运维备注（负责人邮箱/工单号），只做追溯，不参与认证。
type Account struct {
	Username      string    `json:"username"`
	Password      string    `json:"-"`                         // bcrypt 哈希，只进不出
	Token         string    `json:"token"`                     // agent 连接令牌，全局唯一
	Contact       string    `json:"contact,omitempty"`         // 追溯用备注：负责人/联系方式
	TOTPEnabled   bool      `json:"totp_enabled,omitempty"`    // 绑了 TOTP 验证器就要二因素登录
	AgentAllowIPs []string  `json:"agent_allow_ips,omitempty"` // agent 连接的来源白名单；空 = 不限
	AllowIPs      []string  `json:"allow_ips,omitempty"`       // 谁能 SSH 登录这个账号；空 = 不限
	SSHKeys       []string  `json:"ssh_keys,omitempty"`        // SSH 公钥登录用的钥匙（authorized_keys 格式），给自动化用
	Disabled      bool      `json:"disabled,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Store 是账号 SQLite 库。CLI（ws2ssh user）和服务器进程各自 Open 同一个库，
// WAL 模式下并发读写由 SQLite 负责，改完不用重启服务器。
type Store struct {
	db     *sql.DB
	key    *secretKey
	dbPath string
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	username        TEXT    NOT NULL UNIQUE,
	password_hash   TEXT    NOT NULL,
	token_enc       BLOB    NOT NULL UNIQUE,
	contact         TEXT    NOT NULL DEFAULT '',
	totp_secret_enc BLOB,
	totp_last_step  INTEGER NOT NULL DEFAULT 0,
	agent_allow_ips TEXT    NOT NULL DEFAULT '',
	agent_last_ip   TEXT    NOT NULL DEFAULT '',
	allow_ips       TEXT    NOT NULL DEFAULT '',
	ssh_pubkeys     TEXT    NOT NULL DEFAULT '',
	disabled        INTEGER NOT NULL DEFAULT 0,
	created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_token ON users(token_enc);

-- mcp_clients 是服务器内嵌 MCP（/mcp）的客户端凭据表：名字 + token +
-- 可见机器集合 + 来源白名单。token 和 agent token 一样确定性加密存放
--（seal 可索引），库里不留明文。
CREATE TABLE IF NOT EXISTS mcp_clients (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT    NOT NULL UNIQUE,
	token_enc  BLOB    NOT NULL UNIQUE,
	machines   TEXT    NOT NULL DEFAULT '', -- JSON 数组；["*"] = 全部机器
	allow_ips  TEXT    NOT NULL DEFAULT '',
	disabled   INTEGER NOT NULL DEFAULT 0,
	created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mcp_token ON mcp_clients(token_enc);
`

// DefaultKeyPath 由数据库路径推出密钥文件路径：users.db -> users.key。
func DefaultKeyPath(dbPath string) string {
	return strings.TrimSuffix(dbPath, ".db") + ".key"
}

// Open 打开（必要时创建）账号库和密钥文件。keyPath 为空时用 DefaultKeyPath。
func Open(dbPath, keyPath string) (*Store, error) {
	if dbPath == "" {
		return nil, errors.New("账号库路径不能为空")
	}
	if keyPath == "" {
		keyPath = DefaultKeyPath(dbPath)
	}
	if dir := filepath.Dir(dbPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	dsn := "file:" + dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite 写是库级串行的，单连接避免本进程内自己跟自己抢锁。
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化账号库: %w", err)
	}
	// 老库缺新列要 ALTER 补上——schema 里的 CREATE IF NOT EXISTS 管不了已存在的表。
	if err := ensureColumn(db, "ssh_pubkeys", `ALTER TABLE users ADD COLUMN ssh_pubkeys TEXT NOT NULL DEFAULT ''`); err != nil {
		db.Close()
		return nil, fmt.Errorf("升级账号库: %w", err)
	}
	tightenPerms(dbPath)
	return &Store{db: db, key: key, dbPath: dbPath}, nil
}

// ensureColumn 检查 users 表有没有 name 这一列，没有就执行 ddl（一句
// ALTER TABLE ... ADD COLUMN）补上。给老版本建的库做平滑升级用。
func ensureColumn(db *sql.DB, name, ddl string) error {
	rows, err := db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			colName string
			colType string
			notNull int
			dflt    any
			pk      int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &pk); err != nil {
			return err
		}
		if colName == name {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec(ddl)
	return err
}

// tightenPerms 把账号库文件权限收到 0600：库里有 bcrypt 哈希和加密 token，
// SQLite 按 umask 建文件（常见 0644），这里主动收紧。尽力而为——文件不存在
// 或 chmod 失败都不影响启动。
func tightenPerms(dbPath string) {
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal"} {
		_ = os.Chmod(p, 0o600)
	}
}

// Path 返回账号库文件路径。
func (s *Store) Path() string { return s.dbPath }

func (s *Store) Close() error { return s.db.Close() }

// ---- 加解密辅助 ----

func (s *Store) encToken(tok string) ([]byte, error) {
	return s.key.seal("token", []byte(tok))
}

func (s *Store) decToken(blob []byte) (string, error) {
	pt, err := s.key.open("token", blob)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (s *Store) encTOTP(secret []byte) ([]byte, error) {
	return s.key.seal("totp", secret)
}

func (s *Store) decTOTP(blob []byte) ([]byte, error) {
	return s.key.open("totp", blob)
}

// ---- 校验 ----

func validPassword(pw string) error {
	if len(pw) < 10 {
		return errors.New("密码至少 10 位")
	}
	return nil
}

// RandomPassword 生成 16 位强随机密码（12 字节 = 96 位熵）：user add 不给
// 密码时用它，打印一次，落库的是 bcrypt 哈希。
func RandomPassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func validateAllowIPs(ips []string) error {
	_, err := allow.Parse(ips)
	return err
}

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "w2s-" + base64.RawURLEncoding.EncodeToString(b)
}

// ---- 账号操作 ----

// Add 新建账号，生成全局唯一 token。contact 是可选的追溯备注，
// agentAllowIPs 是 agent 连接的来源白名单（空 = 不限）。
func (s *Store) Add(username, password string, allowIPs []string, contact string, agentAllowIPs []string) (Account, error) {
	if !proto.ValidName(username) {
		return Account{}, fmt.Errorf("用户名 %q 不合法，只能用字母、数字、点、下划线和短横线", username)
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
	_, err = s.db.Exec(
		`INSERT INTO users (username, password_hash, token_enc, contact, agent_allow_ips, allow_ips, disabled, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
		username, hash, tEnc, cleanText(contact), string(agentIPs), string(ips), time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Account{}, fmt.Errorf("%w: %s", ErrExists, username)
		}
		return Account{}, err
	}
	return Account{
		Username:      username,
		Token:         tok,
		Contact:       contact,
		AgentAllowIPs: append([]string{}, agentAllowIPs...),
		AllowIPs:      append([]string{}, allowIPs...),
		CreatedAt:     time.Now(),
	}, nil
}

// newUniqueToken 生成不与现有账号重复的 token。
func (s *Store) newUniqueToken() (string, error) {
	for i := 0; i < 10; i++ {
		tok := randomToken()
		enc, err := s.encToken(tok)
		if err != nil {
			return "", err
		}
		var one int
		err = s.db.QueryRow(`SELECT 1 FROM users WHERE token_enc = ?`, enc).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return tok, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("生成唯一 token 失败")
}

// Remove 删除账号；那台机器的 agent 会因 token 失效而连不上。
func (s *Store) Remove(username string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE username = ?`, username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
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

// SetAgentAllow 设置 agent 连接的来源白名单；传空表示不限。这和 SSH 登录的
// allow_ips 是两回事：SSH 的来源是登录的人，agent 的来源是被控机器的出口，
// 混在一起会把 NAT 后面的正常机群挡在外面。
func (s *Store) SetAgentAllow(username string, ips []string) error {
	if err := validateAllowIPs(ips); err != nil {
		return fmt.Errorf("agent 来源白名单: %w", err)
	}
	blob, _ := json.Marshal(ips)
	res, err := s.db.Exec(`UPDATE users SET agent_allow_ips = ? WHERE username = ?`, string(blob), username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// CheckAgentIP 在 agent 连接时校验来源：
//   - 账号设了 agent 来源白名单 → 来源不在名单里就拒绝（硬校验）；
//   - 没设白名单 → 放行。
//
// 无论哪种，都把这次的来源 IP 记成 agent_last_ip（拒绝的不记——攻击者不能
// 靠反复试探挪动基线），并返回上次的来源 IP：调用方用它识别「换了地方连」
// （合法机器也会换网络，所以变更只审计告警，不拦）。
func (s *Store) CheckAgentIP(username string, remote net.Addr) (prev string, err error) {
	var allowBlob, prevIP string
	err = s.db.QueryRow(
		`SELECT agent_allow_ips, agent_last_ip FROM users WHERE username = ?`, username).
		Scan(&allowBlob, &prevIP)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNotFound, username)
	}
	var items []string
	_ = json.Unmarshal([]byte(allowBlob), &items)
	if len(items) > 0 {
		list, perr := allow.Parse(items)
		if perr != nil {
			return "", fmt.Errorf("账号 %s 的 agent 来源白名单配置无效: %w", username, perr)
		}
		if !list.AllowsAddr(remote) {
			return prevIP, fmt.Errorf("来源 %s 不在账号 %s 的 agent 来源白名单里", addrHost(remote), username)
		}
	}
	ip := addrHost(remote)
	if ip != prevIP {
		if _, uerr := s.db.Exec(`UPDATE users SET agent_last_ip = ? WHERE username = ?`, ip, username); uerr != nil {
			return prevIP, uerr
		}
	}
	return prevIP, nil
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

// ---- TOTP（SSH 登录第二因素）----

// EnrollTOTP 绑定验证器。secret 应是调用方已让用户验证过一个码的秘钥
// （CLI 绑定流程先要用户输一次码），lastStep 传验证用掉的时间片，防止
// 绑定时的那个码再被用来登录。
func (s *Store) EnrollTOTP(username string, secret []byte, lastStep int64) error {
	enc, err := s.encTOTP(secret)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(
		`UPDATE users SET totp_secret_enc = ?, totp_last_step = ? WHERE username = ?`,
		enc, lastStep, username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// RemoveTOTP 解绑验证器，账号退回纯密码登录。
func (s *Store) RemoveTOTP(username string) error {
	res, err := s.db.Exec(
		`UPDATE users SET totp_secret_enc = NULL, totp_last_step = 0 WHERE username = ?`, username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// VerifyTOTP 校验 6 位码并原子推进「已消费时间片」：同一个码在有效期内
// 只能被消费一次（条件 UPDATE 保证并发下也不重放）。未绑定返回 false。
func (s *Store) VerifyTOTP(username, code string) bool {
	var enc []byte
	var lastStep int64
	err := s.db.QueryRow(
		`SELECT totp_secret_enc, totp_last_step FROM users WHERE username = ?`, username).
		Scan(&enc, &lastStep)
	if err != nil || len(enc) == 0 {
		return false
	}
	secret, err := s.decTOTP(enc)
	if err != nil {
		return false
	}
	step, ok := totp.Verify(secret, code, lastStep, time.Now())
	if !ok {
		return false
	}
	res, err := s.db.Exec(
		`UPDATE users SET totp_last_step = ? WHERE username = ? AND totp_last_step < ?`,
		step, username, step)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// Rename 改用户名；agent 不用动（它靠 token 认，不靠名字）。
func (s *Store) Rename(oldName, newName string) error {
	if !proto.ValidName(newName) {
		return fmt.Errorf("用户名 %q 不合法，只能用字母、数字、点、下划线和短横线", newName)
	}
	var one int
	if err := s.db.QueryRow(`SELECT 1 FROM users WHERE username = ?`, newName).Scan(&one); err == nil {
		return fmt.Errorf("%w: %s", ErrExists, newName)
	}
	res, err := s.db.Exec(`UPDATE users SET username = ? WHERE username = ?`, newName, oldName)
	if err != nil {
		// 并发下可能恰好有人抢注了新名，UNIQUE 报错也归为重名。
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("%w: %s", ErrExists, newName)
		}
		return err
	}
	return requireAffected(res, oldName)
}

// RegenToken 换一个新 token；旧 token 立刻作废，那台机器要改用新 token 重连。
func (s *Store) RegenToken(username string) (string, error) {
	tok, err := s.newUniqueToken()
	if err != nil {
		return "", err
	}
	tEnc, err := s.encToken(tok)
	if err != nil {
		return "", err
	}
	res, err := s.db.Exec(`UPDATE users SET token_enc = ? WHERE username = ?`, tEnc, username)
	if err != nil {
		return "", err
	}
	if err := requireAffected(res, username); err != nil {
		return "", err
	}
	return tok, nil
}

// Get 返回账号副本。
func (s *Store) Get(username string) (Account, bool) {
	row := s.db.QueryRow(
		`SELECT username, password_hash, token_enc, contact, totp_secret_enc, totp_last_step, agent_allow_ips, allow_ips, ssh_pubkeys, disabled, created_at
		 FROM users WHERE username = ?`, username)
	a, err := scanAccount(row, s)
	if err != nil {
		return Account{}, false
	}
	return a, true
}

// Brief 是不解密 token 的账号摘要：/status 这种高频路径用，别为每个账号
// 都跑一遍 AES 解密。
type Brief struct {
	Username string
	Disabled bool
}

// ListBasic 列出全部账号的用户名和停用状态，按用户名排序。
func (s *Store) ListBasic() []Brief {
	rows, err := s.db.Query(`SELECT username, disabled FROM users`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Brief
	for rows.Next() {
		var name string
		var disabled int
		if err := rows.Scan(&name, &disabled); err != nil {
			continue
		}
		out = append(out, Brief{Username: name, Disabled: disabled != 0})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// List 返回全部账号，按用户名排序。
func (s *Store) List() []Account {
	rows, err := s.db.Query(
		`SELECT username, password_hash, token_enc, contact, totp_secret_enc, totp_last_step, agent_allow_ips, allow_ips, ssh_pubkeys, disabled, created_at FROM users`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows, s)
		if err != nil {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

type rowScanner interface{ Scan(dest ...any) error }

func scanAccount(r rowScanner, s *Store) (Account, error) {
	var (
		username    string
		hash        string
		tEnc        []byte
		contact     string
		totpEnc     []byte // NULL = 未绑定
		totpLastStp int64
		agentBlob   string
		ipsBlob     string
		keysBlob    string
		disabled    int
		createdAt   string
	)
	if err := r.Scan(&username, &hash, &tEnc, &contact, &totpEnc, &totpLastStp, &agentBlob, &ipsBlob, &keysBlob, &disabled, &createdAt); err != nil {
		return Account{}, err
	}
	token, err := s.decToken(tEnc)
	if err != nil {
		return Account{}, err
	}
	var ips []string
	_ = json.Unmarshal([]byte(ipsBlob), &ips)
	var agentIPs []string
	_ = json.Unmarshal([]byte(agentBlob), &agentIPs)
	var sshKeys []string
	_ = json.Unmarshal([]byte(keysBlob), &sshKeys)
	created, _ := time.Parse(time.RFC3339, createdAt)
	return Account{
		Username:      username,
		Password:      hash,
		Token:         token,
		Contact:       contact,
		TOTPEnabled:   len(totpEnc) > 0,
		AgentAllowIPs: agentIPs,
		AllowIPs:      ips,
		SSHKeys:       sshKeys,
		Disabled:      disabled != 0,
		CreatedAt:     created,
	}, nil
}

// dummyBcrypt 是一个真实格式的 bcrypt 哈希（明文是无关的固定串）。「账号
// 不存在」「账号停用」的登录也做一次同样耗时的 bcrypt 比较，让三条失败路径
// （不存在/停用/密码错）耗时一致——不然按响应时间就能枚举出有效用户名。
const dummyBcrypt = "$2a$10$8/ASPNnE/jG9nU6/2MsnDuj7vu6ucIjli2ND.mvqVARUzO44oJ8KC"

// Verify 校验 SSH 用户名密码。账号不存在、停用、密码不对都返回 false，
// 且三条路径耗时一致（见 dummyBcrypt）。
func (s *Store) Verify(username, password string) bool {
	var hash string
	var disabled int
	err := s.db.QueryRow(`SELECT password_hash, disabled FROM users WHERE username = ?`, username).Scan(&hash, &disabled)
	if err != nil || disabled != 0 {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcrypt), []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// BurnPassword 对 password 做一次和真实校验同样耗时的假 bcrypt 比较，返回值
// 无意义。给那些「不看密码就要拒绝」的路径用（比如 TOTP 账号走纯密码通道），
// 让它们的响应时间和密码错一样，不然快慢一比就能筛出特定账号。
func (s *Store) BurnPassword(password string) {
	_ = bcrypt.CompareHashAndPassword([]byte(dummyBcrypt), []byte(password))
}

// AddSSHKey 给账号登记一把 SSH 登录公钥：line 是 authorized_keys 格式的一行
// （可带行尾注释）。重复登记同一把不报错也不重复存。
func (s *Store) AddSSHKey(username, line string) error {
	pk, comment, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return fmt.Errorf("不是有效的 SSH 公钥: %w", err)
	}
	stored := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pk)))
	if comment != "" {
		stored += " " + comment
	}
	acct, ok := s.Get(username)
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, username)
	}
	for _, existing := range acct.SSHKeys {
		epk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(existing))
		if err != nil {
			continue
		}
		if bytes.Equal(epk.Marshal(), pk.Marshal()) {
			return nil
		}
	}
	blob, err := json.Marshal(append(acct.SSHKeys, stored))
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE users SET ssh_pubkeys = ? WHERE username = ?`, string(blob), username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// RemoveSSHKey 删掉账号的一把公钥：keyOrFingerprint 可以是 authorized_keys
// 一行，也可以是「SHA256:...」指纹。匹配不到报错。
func (s *Store) RemoveSSHKey(username, keyOrFingerprint string) error {
	acct, ok := s.Get(username)
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, username)
	}
	var wantBytes []byte
	if pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(keyOrFingerprint)); err == nil {
		wantBytes = pk.Marshal()
	}
	var keep []string
	removed := false
	for _, line := range acct.SSHKeys {
		pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			keep = append(keep, line)
			continue
		}
		if bytes.Equal(pk.Marshal(), wantBytes) || gossh.FingerprintSHA256(pk) == keyOrFingerprint {
			removed = true
			continue
		}
		keep = append(keep, line)
	}
	if !removed {
		return fmt.Errorf("账号 %s 没有这把公钥", username)
	}
	blob, err := json.Marshal(keep)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE users SET ssh_pubkeys = ? WHERE username = ?`, string(blob), username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// ClearSSHKeys 清空账号的全部登录公钥。
func (s *Store) ClearSSHKeys(username string) error {
	res, err := s.db.Exec(`UPDATE users SET ssh_pubkeys = '' WHERE username = ?`, username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// VerifySSHKey 校验 SSH 公钥登录：账号存在、未停用、这把钥匙登记过。
// 不看密码也不看 TOTP——公钥是给自动化用的第二种凭据。
func (s *Store) VerifySSHKey(username string, key gossh.PublicKey) bool {
	acct, ok := s.Get(username)
	if !ok || acct.Disabled {
		return false
	}
	for _, line := range acct.SSHKeys {
		pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		if bytes.Equal(pk.Marshal(), key.Marshal()) {
			return true
		}
	}
	return false
}

// UsernameByToken 用 agent token 查账号；token 无效或账号停用时 ok 为 false。
func (s *Store) UsernameByToken(token string) (string, bool) {
	enc, err := s.encToken(token)
	if err != nil {
		return "", false
	}
	var (
		username string
		disabled int
	)
	err = s.db.QueryRow(`SELECT username, disabled FROM users WHERE token_enc = ?`, enc).Scan(&username, &disabled)
	if err != nil || disabled != 0 {
		return "", false
	}
	return username, true
}

func requireAffected(res sql.Result, username string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, username)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
