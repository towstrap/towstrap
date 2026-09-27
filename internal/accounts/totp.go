package accounts

import (
	"time"

	"github.com/towstrap/towstrap/internal/totp"
)

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

// CheckTOTP 校验 6 位码但不消费时间片：给「同一流程里要先验一次、后面
// 还要真正消费一次」的场景用（TOTP 换绑的 begin 验身份，confirm 才落库
// 消费）。已被消费过的码照样拒——重放一个旧登录码过不了这里。
func (s *Store) CheckTOTP(username, code string) bool {
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
	_, ok := totp.Verify(secret, code, lastStep, time.Now())
	return ok
}
