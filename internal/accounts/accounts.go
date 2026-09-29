package accounts

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	sqlite "modernc.org/sqlite"

	"github.com/towstrap/towstrap/internal/allow"
)

var (
	ErrNotFound = errors.New("账号不存在")
	ErrExists   = errors.New("账号已存在")
	// ErrBadInput 包住所有用户输入校验错（名字不合法、密码太短、白名单
	// 写错、公钥格式不对）——HTTP 层据此回 400 而不是 500。
	ErrBadInput = errors.New("输入不合法")
)

// isUniqueErr 判 SQLite 唯一约束冲突：看错误码不拼文案（驱动哪天改了
// "UNIQUE" 字样也不会静默失效）。1555=PRIMARYKEY、2067=UNIQUE，都算重名。
func isUniqueErr(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code() == 1555 || se.Code() == 2067
	}
	return false
}

// Account 是一个账号（人/凭据）：外人用 Username/Password 走 SSH 登录。
// 账号下挂若干 Machine（被控机），每台机器有独立 token（见 machines.go）；
// SSH 用户名写「账号」默认落到唯一那台，多台时用「账号+机器名」指定。
// 数据库里 Username 明文存放（注册查重、登录查询都按它来），机器 token
// 和 TOTP 秘钥是 AES-GCM 加密存的，Password 是 bcrypt（自带随机盐）。
// Contact 是运维备注（负责人邮箱/工单号），只做追溯，不参与认证。
type Account struct {
	Username    string    `json:"username"`
	Password    string    `json:"-"`                      // bcrypt 哈希，只进不出
	Contact     string    `json:"contact,omitempty"`      // 追溯用备注：负责人/联系方式
	TOTPEnabled bool      `json:"totp_enabled,omitempty"` // 绑了 TOTP 验证器就要二因素登录
	AllowIPs    []string  `json:"allow_ips,omitempty"`    // 谁能 SSH 登录这个账号；空 = 不限
	SSHKeys     []string  `json:"ssh_keys,omitempty"`     // SSH 公钥登录用的钥匙（authorized_keys 格式），给自动化用
	Disabled    bool      `json:"disabled,omitempty"`
	OAuthOnly   bool      `json:"oauth_only,omitempty"` // SSH 只收 OAuth 换来的凭据（密码/公钥一律拒）
	Machines    []Machine `json:"machines,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Store 是账号 SQLite 库。CLI（towstrap user）和服务器进程各自 Open 同一个库，
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
	contact         TEXT    NOT NULL DEFAULT '',
	totp_secret_enc BLOB,
	totp_last_step  INTEGER NOT NULL DEFAULT 0,
	allow_ips       TEXT    NOT NULL DEFAULT '',
	ssh_pubkeys     TEXT    NOT NULL DEFAULT '',
	disabled        INTEGER NOT NULL DEFAULT 0,
	oauth_only      INTEGER NOT NULL DEFAULT 0, -- 1 = SSH 只收 OAuth 换来的凭据
	created_at      TEXT    NOT NULL
);

-- machines 是账号下的被控机：一个账号可挂多台，每台独立 token。
-- token_enc 同一把 key、同一个 seal 上下文 "token" 的确定性加密，可索引。
CREATE TABLE IF NOT EXISTS machines (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	username        TEXT    NOT NULL,
	name            TEXT    NOT NULL,
	token_enc       BLOB    NOT NULL UNIQUE,
	agent_allow_ips TEXT    NOT NULL DEFAULT '',
	agent_last_ip   TEXT    NOT NULL DEFAULT '',
	oauth_only      INTEGER NOT NULL DEFAULT 0, -- 1 = 这台机器 SSH 只收 OAuth 凭据
	created_at      TEXT    NOT NULL,
	UNIQUE(username, name)
);
CREATE INDEX IF NOT EXISTS idx_machines_token ON machines(token_enc);

-- mcp_clients 是服务器内嵌 MCP（/mcp）的客户端凭据表：名字 + token +
-- 可见机器集合 + 来源白名单。token 和 agent token 一样确定性加密存放
--（seal 可索引），库里不留明文。
CREATE TABLE IF NOT EXISTS mcp_clients (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT    NOT NULL UNIQUE,
	owner      TEXT    NOT NULL DEFAULT '', -- 账号本人自签时的所属账号；管理员签发留空
	token_enc  BLOB    NOT NULL UNIQUE,
	machines   TEXT    NOT NULL DEFAULT '', -- JSON 数组；["*"] = 全部机器
	allow_ips  TEXT    NOT NULL DEFAULT '',
	disabled   INTEGER NOT NULL DEFAULT 0,
	created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mcp_token ON mcp_clients(token_enc);
-- idx_mcp_owner 不在建表语句里：老库要先补 owner 列（见 Open 里的
-- ensureColumn），列还不存在时建索引会让整份 schema 执行失败、库直接开
-- 不起来。索引在补列之后建。

-- oauth_identities 是管理员预先绑定的外部身份：(issuer, sub) 唯一指向
-- 一个本地账号。OAuth 回调验完 IdP 身份后按它找「这人是谁」。
CREATE TABLE IF NOT EXISTS oauth_identities (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	username   TEXT    NOT NULL,
	issuer     TEXT    NOT NULL,
	sub        TEXT    NOT NULL,
	email      TEXT    NOT NULL DEFAULT '',
	created_at TEXT    NOT NULL,
	UNIQUE(issuer, sub)
);

-- ssh_grants 是 OAuth 授权通过后下发的短时效 SSH 凭据。明文 secret 不落库，
-- 只存 bcrypt；pub_id 是 secret 里的一段公开前缀，校验时按它精确取行，
-- 不用对全部候选跑 bcrypt。uses_left 用尽或到 expires_at 即作废。
CREATE TABLE IF NOT EXISTS ssh_grants (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	pub_id      TEXT    NOT NULL UNIQUE,
	machine     TEXT    NOT NULL, -- 完整机器名 账号+机器名
	secret_hash TEXT    NOT NULL,
	expires_at  TEXT    NOT NULL,
	uses_left   INTEGER NOT NULL DEFAULT 0,
	created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_grants_pub ON ssh_grants(pub_id);

-- register_fps 是自助注册的机器指纹绑定：一台机器（指纹）只许注册一个
-- 账号。删账号时对应行一并释放。
CREATE TABLE IF NOT EXISTS register_fps (
	fingerprint TEXT    PRIMARY KEY,
	username    TEXT    NOT NULL,
	created_at  TEXT    NOT NULL
);
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
	// 库文件已在而 key 读不出来 = 密封凭据不可救——拒绝启动让管理员
	// 来处理，绝不静默重建（见 loadOrCreateKey 注释）。stat 失败（权限
	// 不足、IO 错）也算「库可能在」——不能当不存在去生成新 key，那
	// 会让已有凭据变成解不开的乱码、看起来像数据丢了。
	_, statErr := os.Stat(dbPath)
	key, err := loadOrCreateKey(keyPath, statErr == nil || !os.IsNotExist(statErr))
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
	if err := ensureColumn(db, "users", "ssh_pubkeys", `ALTER TABLE users ADD COLUMN ssh_pubkeys TEXT NOT NULL DEFAULT ''`); err != nil {
		db.Close()
		return nil, fmt.Errorf("升级账号库: %w", err)
	}
	// 老库迁移：users 里的 token/agent 字段搬到 machines 表（每台一个 default）。
	if err := migrateMachines(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("迁移 machines 表: %w", err)
	}
	// owner 列的存在与否就是「要不要回填」的迁移标记：列刚补上这一趟
	// 按旧命名规则回填一次，之后 owner='' 是「管理员签发、@mcp 碰不到」
	// 的正常取值，不能每次 Open 都再按名字猜——否则后来签发的
	// 「alice.laptop」会在下次启动被收养给 alice，等于凭据易主。
	hadOwner, err := hasColumn(db, "mcp_clients", "owner")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("检查 mcp_clients.owner: %w", err)
	}
	// oauth_only 是后加的列（migrateMachines 重建 users 时也不会带上）。
	for _, col := range []struct{ table, name, ddl string }{
		{"users", "oauth_only", `ALTER TABLE users ADD COLUMN oauth_only INTEGER NOT NULL DEFAULT 0`},
		{"machines", "oauth_only", `ALTER TABLE machines ADD COLUMN oauth_only INTEGER NOT NULL DEFAULT 0`},
		// pending_token_enc：轮换中的暂存新 token。ack 丢了但 agent 已写
		// 盘时，它拿新 token 连上即自动转正（服务端当协调者，裂脑自愈）。
		{"machines", "pending_token_enc", `ALTER TABLE machines ADD COLUMN pending_token_enc TEXT`},
		// owner：MCP 客户端的所属账号。/@mcp 自助面靠它判定归属，不再靠
		// 「账号.名字」前缀猜（账号名本身可以带点，前缀不是无歧义的名字
		// 空间，见 backfillMCPOwner）。
		{"mcp_clients", "owner", `ALTER TABLE mcp_clients ADD COLUMN owner TEXT NOT NULL DEFAULT ''`},
	} {
		if err := ensureColumn(db, col.table, col.name, col.ddl); err != nil {
			db.Close()
			return nil, fmt.Errorf("升级账号库 %s.%s: %w", col.table, col.name, err)
		}
	}
	// 老库的 mcp_clients 没有 owner 列，补列这一趟按旧命名规则回填：自签
	// 的一律是「<账号>.<名字>」，管理员签发的不带前缀（留空）。只认
	// 「恰好一个点且前半截是库里真实存在的账号」这种无歧义的名字；点更多
	// 的一律留空——账号名本身可以带点，多点名字猜不出主人，猜错就是越
	// 权，宁可留给管理员手工处理。只在 !hadOwner 时跑（见上面），列存在
	// 后 owner='' 可能是管理员刚签发的新客户端，绝不能动。
	if !hadOwner {
		if err := backfillMCPOwner(db); err != nil {
			db.Close()
			return nil, fmt.Errorf("回填 mcp_clients.owner: %w", err)
		}
	}
	// 索引必须在补列之后建（见 schema 里的说明）。
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_mcp_owner ON mcp_clients(owner)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("建 mcp_clients.owner 索引: %w", err)
	}
	tightenPerms(dbPath)
	return &Store{db: db, key: key, dbPath: dbPath}, nil
}

// hasColumn 检查表有没有这一列。
func hasColumn(db *sql.DB, table, name string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
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
			return false, err
		}
		if colName == name {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ensureColumn 检查表里有没有 name 这一列，没有就执行 ddl（一句
// ALTER TABLE ... ADD COLUMN）补上。给老版本建的库做平滑升级用。
func ensureColumn(db *sql.DB, table, name, ddl string) error {
	has, err := hasColumn(db, table, name)
	if err != nil || has {
		return err
	}
	_, err = db.Exec(ddl)
	return err
}

// backfillMCPOwner 给老库的 mcp_clients 回填 owner 列。旧库没有这一列，
// 归属只能从名字反推，而「<账号>.<名字>」在账号名允许点号时不是无歧义
// 分解（账号 alice.bob 的 laptop 是 alice.bob.laptop，alice 也能拼出同名），
// 所以只认「恰好一个点 + 前半截是真实存在的账号」这一种能确定的写法；
// 其余一律留空交给管理员——把凭据误认到别人名下比谁都管不着更糟。
func backfillMCPOwner(db *sql.DB) error {
	// 注意：先把行全读完再逐条查账号。db 是单连接（SetMaxOpenConns(1)），
	// 游标没关就发新查询会自锁等自己。
	rows, err := db.Query(`SELECT name FROM mcp_clients WHERE owner = ''`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, name := range names {
		u, short, ok := strings.Cut(name, ".")
		if !ok || short == "" || strings.Contains(short, ".") {
			continue // 管理员签发（无点）或多点名字（认不准）→ 留空
		}
		var exists int
		if err := db.QueryRow(`SELECT 1 FROM users WHERE username = ?`, u).Scan(&exists); err != nil {
			continue // 前半截不是账号 → 管理员签发
		}
		if _, err := db.Exec(`UPDATE mcp_clients SET owner = ? WHERE name = ?`, u, name); err != nil {
			return err
		}
	}
	return nil
}

// migrateMachines 把老库 users 表的 token_enc/agent_allow_ips/agent_last_ip
// 搬到 machines 表：每个账号得到一台名为 default 的机器，沿用原 token
// （同一把 key 同一个 seal 上下文，BLOB 直接搬，不用解密重加密）。
// 幂等：users 没有 token_enc 列说明已是新库，跳过。
func migrateMachines(db *sql.DB) error {
	has, err := hasColumn(db, "users", "token_enc")
	if err != nil || !has {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO machines (username, name, token_enc, agent_allow_ips, agent_last_ip, created_at)
		 SELECT username, 'default', token_enc, agent_allow_ips, agent_last_ip, created_at FROM users`); err != nil {
		return err
	}
	// SQLite 删列的标准做法：建新表 → 搬数据 → 删旧表 → 改名。
	// DROP TABLE 会连带删掉旧表上的索引（idx_users_token）。
	if _, err := tx.Exec(`CREATE TABLE users_new (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		username        TEXT    NOT NULL UNIQUE,
		password_hash   TEXT    NOT NULL,
		contact         TEXT    NOT NULL DEFAULT '',
		totp_secret_enc BLOB,
		totp_last_step  INTEGER NOT NULL DEFAULT 0,
		allow_ips       TEXT    NOT NULL DEFAULT '',
		ssh_pubkeys     TEXT    NOT NULL DEFAULT '',
		disabled        INTEGER NOT NULL DEFAULT 0,
		created_at      TEXT    NOT NULL
	)`); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO users_new (id, username, password_hash, contact, totp_secret_enc, totp_last_step, allow_ips, ssh_pubkeys, disabled, created_at)
		 SELECT id, username, password_hash, contact, totp_secret_enc, totp_last_step, allow_ips, ssh_pubkeys, disabled, created_at FROM users`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE users`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE users_new RENAME TO users`); err != nil {
		return err
	}
	return tx.Commit()
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
		return fmt.Errorf("%w: 密码至少 10 位", ErrBadInput)
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
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadInput, err)
	}
	return nil
}

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// NewAgentToken 生成一个新 agent token（tsa-...）。服务器换发 token 时用：
// 先下推给 agent 写进文件，收到 ack 才调 SetMachineToken 落库。
func NewAgentToken() string { return randomToken() }

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "tsa-" + base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) Get(username string) (Account, bool) {
	row := s.db.QueryRow(
		`SELECT username, password_hash, contact, totp_secret_enc, totp_last_step, allow_ips, ssh_pubkeys, disabled, oauth_only, created_at
		 FROM users WHERE username = ?`, username)
	a, err := scanAccount(row, s)
	if err != nil {
		return Account{}, false
	}
	a.Machines = s.Machines(username)
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

// List 返回全部账号（含机器列表），按用户名排序。
func (s *Store) List() []Account {
	rows, err := s.db.Query(
		`SELECT username, password_hash, contact, totp_secret_enc, totp_last_step, allow_ips, ssh_pubkeys, disabled, oauth_only, created_at FROM users`)
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
	byUser := s.machinesByUser()
	for i := range out {
		out[i].Machines = byUser[out[i].Username]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

type rowScanner interface{ Scan(dest ...any) error }

func scanAccount(r rowScanner, s *Store) (Account, error) {
	var (
		username    string
		hash        string
		contact     string
		totpEnc     []byte // NULL = 未绑定
		totpLastStp int64
		ipsBlob     string
		keysBlob    string
		disabled    int
		oauthOnly   int
		createdAt   string
	)
	if err := r.Scan(&username, &hash, &contact, &totpEnc, &totpLastStp, &ipsBlob, &keysBlob, &disabled, &oauthOnly, &createdAt); err != nil {
		return Account{}, err
	}
	var ips []string
	_ = json.Unmarshal([]byte(ipsBlob), &ips)
	var sshKeys []string
	_ = json.Unmarshal([]byte(keysBlob), &sshKeys)
	created, _ := time.Parse(time.RFC3339, createdAt)
	return Account{
		Username:    username,
		Password:    hash,
		Contact:     contact,
		TOTPEnabled: len(totpEnc) > 0,
		AllowIPs:    ips,
		SSHKeys:     sshKeys,
		Disabled:    disabled != 0,
		OAuthOnly:   oauthOnly != 0,
		CreatedAt:   created,
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
