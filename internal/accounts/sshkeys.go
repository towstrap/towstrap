package accounts

// SSH 公钥凭据：登记/移除/校验。公钥是给自动化用的第二种登录凭据。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// AddSSHKey 给账号登记一把 SSH 登录公钥：line 是 authorized_keys 格式的一行
// （可带行尾注释）。重复登记同一把不报错也不重复存。
func (s *Store) AddSSHKey(username, line string) error {
	pk, comment, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return fmt.Errorf("%w: 不是有效的 SSH 公钥: %v", ErrBadInput, err)
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
		return fmt.Errorf("%w: 账号 %s 没有这把公钥", ErrNotFound, username)
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
