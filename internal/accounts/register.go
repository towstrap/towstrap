package accounts

import (
	"database/sql"
	"strings"
	"time"
)

// normFP 统一指纹形态：客户端报的是十六进制哈希，大小写两种写法必须
// 撞同一行——不然 AA.. 和 aa.. 会当两台机器，同一硬件重复占账号。
func normFP(fp string) string { return strings.ToLower(strings.TrimSpace(fp)) }

// FingerprintAccount 查这个机器指纹已绑定的账号；没绑过返回 ""（无错）。
// 用于注册去重：同一台机器只允许注册一个账号。
func (s *Store) FingerprintAccount(fp string) (string, error) {
	var username string
	err := s.db.QueryRow(`SELECT username FROM register_fps WHERE fingerprint = ?`, normFP(fp)).Scan(&username)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return username, err
}

// BindFingerprint 把机器指纹绑到账号。bound=false = 这个指纹已被别的
// 账号占用了（调用方回 409）。inserted=true 表示是本调用新插的行——
// 并发下同指纹的败方只是「查到已存在」，它去回滚会把胜方的绑定
// 错杀掉，所以只有 inserted 的调用方才允许走 ReleaseFingerprint。
func (s *Store) BindFingerprint(fp, username string) (bound, inserted bool, err error) {
	fp = normFP(fp)
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO register_fps (fingerprint, username, created_at) VALUES (?, ?, ?)`,
		fp, username, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return false, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, false, err
	}
	if n == 1 {
		return true, true, nil
	}
	// 已存在；看下是不是同一个账号（幂等重试通过，换了人才算占用）
	owner, err := s.FingerprintAccount(fp)
	if err != nil {
		return false, false, err
	}
	return owner == username, false, nil
}

// ReleaseFingerprint 解除指纹绑定（注册流程里占坑后建账号失败时回滚用；
// 删账号走 Remove 里的事务级清理，不经这里）。
func (s *Store) ReleaseFingerprint(fp, username string) error {
	_, err := s.db.Exec(`DELETE FROM register_fps WHERE fingerprint = ? AND username = ?`, normFP(fp), username)
	return err
}
