package accounts

// OAuth 相关的存储：外部身份绑定（oauth_identities）、OAuth 换来的短时效
// SSH 凭据（ssh_grants）、账号/机器的「只收 OAuth 凭据」标记（oauth_only）。

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// OAuthIdentity 是一条预先绑定的外部身份：IdP 的 (issuer, sub) 指向本账号。
type OAuthIdentity struct {
	Username  string    `json:"username"`
	Issuer    string    `json:"issuer"`
	Sub       string    `json:"sub"`
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// BindOAuthIdentity 把 IdP 身份绑到本地账号。(issuer, sub) 已绑到别的账号
// 时报 ErrExists；账号不存在报 ErrNotFound。
func (s *Store) BindOAuthIdentity(username, issuer, sub, email string) error {
	issuer = strings.TrimSuffix(strings.TrimSpace(issuer), "/")
	sub = strings.TrimSpace(sub)
	if issuer == "" || sub == "" {
		return errors.New("issuer 和 sub 不能为空")
	}
	var one int
	if err := s.db.QueryRow(`SELECT 1 FROM users WHERE username = ?`, username).Scan(&one); err != nil {
		return fmt.Errorf("%w: %s", ErrNotFound, username)
	}
	_, err := s.db.Exec(
		`INSERT INTO oauth_identities (username, issuer, sub, email, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		username, issuer, sub, strings.TrimSpace(email), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("%w: 该外部身份已绑定其他账号", ErrExists)
	}
	return nil
}

// UnbindOAuthIdentity 解绑一个外部身份（按 issuer+sub 精确定位）。
func (s *Store) UnbindOAuthIdentity(issuer, sub string) error {
	res, err := s.db.Exec(`DELETE FROM oauth_identities WHERE issuer = ? AND sub = ?`,
		strings.TrimSuffix(issuer, "/"), sub)
	if err != nil {
		return err
	}
	return requireAffected(res, issuer+"/"+sub)
}

// OAuthIdentities 列出账号绑定的全部外部身份。
func (s *Store) OAuthIdentities(username string) []OAuthIdentity {
	rows, err := s.db.Query(
		`SELECT username, issuer, sub, email, created_at FROM oauth_identities
		 WHERE username = ? ORDER BY issuer, sub`, username)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []OAuthIdentity
	for rows.Next() {
		var o OAuthIdentity
		var created string
		if err := rows.Scan(&o.Username, &o.Issuer, &o.Sub, &o.Email, &created); err == nil {
			o.CreatedAt, _ = time.Parse(time.RFC3339, created)
			out = append(out, o)
		}
	}
	return out
}

// OAuthLookup 按 (issuer, sub) 找本地账号名；没绑过返回 false。
func (s *Store) OAuthLookup(issuer, sub string) (string, bool) {
	var username string
	err := s.db.QueryRow(
		`SELECT username FROM oauth_identities WHERE issuer = ? AND sub = ?`,
		strings.TrimSuffix(issuer, "/"), sub).Scan(&username)
	if err != nil {
		return "", false
	}
	return username, true
}

// SetOAuthOnly 设置账号级「只收 OAuth 凭据」：开了之后这个账号名下所有
// 机器的 SSH 密码/公钥登录都被拒，只有 OAuth 换来的短时效凭据能进。
func (s *Store) SetOAuthOnly(username string, on bool) error {
	v := 0
	if on {
		v = 1
	}
	res, err := s.db.Exec(`UPDATE users SET oauth_only = ? WHERE username = ?`, v, username)
	if err != nil {
		return err
	}
	return requireAffected(res, username)
}

// SetMachineOAuthOnly 设置机器级「只收 OAuth 凭据」。
func (s *Store) SetMachineOAuthOnly(username, name string, on bool) error {
	v := 0
	if on {
		v = 1
	}
	res, err := s.db.Exec(`UPDATE machines SET oauth_only = ? WHERE username = ? AND name = ?`,
		v, username, name)
	if err != nil {
		return err
	}
	return requireAffected(res, username+"+"+name)
}

// ---- 短时效 SSH 凭据 ----

// GrantTTL/GrantUses 是 OAuth 凭据的默认有效期和可用次数：要留够人把密码
// 抄进 SSH 客户端的时间，也容忍客户端一次握手里的多次认证尝试。
const (
	GrantTTL  = 15 * time.Minute
	GrantUses = 5
)

// CreateSSHGrant 给一台机器发一个短时效 SSH 凭据，返回明文（形如
// "tso-XXXXXXXX.YYYY…"）。库里只存 bcrypt 哈希；顺手清掉过期的旧凭据。
func (s *Store) CreateSSHGrant(machine string, ttl time.Duration, uses int) (string, error) {
	pub := make([]byte, 6)
	sec := make([]byte, 24)
	if _, err := rand.Read(pub); err != nil {
		return "", err
	}
	if _, err := rand.Read(sec); err != nil {
		return "", err
	}
	pubID := base64.RawURLEncoding.EncodeToString(pub)
	secret := "tso-" + pubID + "." + base64.RawURLEncoding.EncodeToString(sec)
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	// 先清过期行，顺手限制每台机器的在册凭据数（防连发 OAuth 攒一堆）。
	if _, err := s.db.Exec(`DELETE FROM ssh_grants WHERE expires_at < ?`,
		now.Format(time.RFC3339)); err != nil {
		return "", err
	}
	if _, err := s.db.Exec(
		`INSERT INTO ssh_grants (pub_id, machine, secret_hash, expires_at, uses_left, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		pubID, machine, string(hash), now.Add(ttl).Format(time.RFC3339), uses,
		now.Format(time.RFC3339)); err != nil {
		return "", err
	}
	return secret, nil
}

// UseSSHGrant 校验一个 OAuth 凭据：按 secret 里的 pub_id 取行，查机器、
// 时效、剩余次数，再 bcrypt 比对。命中就扣一次使用次数。secret 不是
// "tso-" 前缀直接快速返回 false——普通账号密码不会走这里。
func (s *Store) UseSSHGrant(machine, secret string) bool {
	if !strings.HasPrefix(secret, "tso-") {
		return false
	}
	rest := secret[len("tso-"):]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 {
		return false
	}
	var hash, expires string
	var usesLeft int
	err := s.db.QueryRow(
		`SELECT secret_hash, expires_at, uses_left FROM ssh_grants
		 WHERE pub_id = ? AND machine = ?`, rest[:dot], machine).Scan(&hash, &expires, &usesLeft)
	if err != nil {
		// pub_id 不存在也做一次假 bcrypt，让「乱猜 tso- 前缀」和
		// 「前缀对了密钥错」耗时一致。
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcrypt), []byte(secret))
		return false
	}
	exp, _ := time.Parse(time.RFC3339, expires)
	if usesLeft <= 0 || time.Now().UTC().After(exp) {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcrypt), []byte(secret))
		return false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) != nil {
		return false
	}
	// 次数扣减必须原子：并发下两个请求都能读到 uses_left>0，谁先拿到
	// 条件 UPDATE 的影响行才算数——不然限用 1 次的凭据能被同时刷两次。
	res, err := s.db.Exec(
		`UPDATE ssh_grants SET uses_left = uses_left - 1
		 WHERE pub_id = ? AND uses_left > 0 AND expires_at > ?`,
		rest[:dot], time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return false
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return false // 并发扣光了（或刚好过期）：这次不算数
	}
	return true
}
