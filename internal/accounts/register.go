package accounts

import (
	"database/sql"
	"time"
)

// FingerprintAccount 查这个机器指纹已绑定的账号；没绑过返回 ""（无错）。
// 用于注册去重：同一台机器只允许注册一个账号。
func (s *Store) FingerprintAccount(fp string) (string, error) {
	var username string
	err := s.db.QueryRow(`SELECT username FROM register_fps WHERE fingerprint = ?`, fp).Scan(&username)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return username, err
}

// BindFingerprint 把机器指纹绑到账号。返回 false = 这个指纹已被别的
// 账号占用了（调用方回 409）。
func (s *Store) BindFingerprint(fp, username string) (bool, error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO register_fps (fingerprint, username, created_at) VALUES (?, ?, ?)`,
		fp, username, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		// 已存在；看下是不是同一个账号（幂等重试通过，换了人才算占用）
		owner, err := s.FingerprintAccount(fp)
		if err != nil {
			return false, err
		}
		return owner == username, nil
	}
	return true, nil
}

// ReleaseFingerprint 解除指纹绑定（注册流程里占坑后建账号失败时回滚用；
// 删账号走 Remove 里的事务级清理，不经这里）。
func (s *Store) ReleaseFingerprint(fp, username string) error {
	_, err := s.db.Exec(`DELETE FROM register_fps WHERE fingerprint = ? AND username = ?`, fp, username)
	return err
}
