package accounts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// token 在数据库里不以明文存放：用 AES-256-GCM 加密。
// 同一明文每次加密结果相同（「确定性加密」），这样才能按密文建唯一索引、按密文查询；
// 不同明文的 nonce 各不相同（由 HMAC 派生），不会出现 GCM 的 nonce 复用。
// 用户名明文存放：注册时查重、SSH 登录查询都要按它找。
// 密钥单独放在 key 文件里（0600），第一次使用时自动生成——备份账号库时把 key 一起备，
// key 丢了 token 就解不开（密码是 bcrypt 哈希，本来就不需要解）。

const keyFileSize = 64 // 32 字节 AES 密钥 + 32 字节 MAC 密钥

type secretKey struct {
	aesKey []byte
	macKey []byte
}

// loadOrCreateKey 读密钥文件；只有「文件真不存在 + 账号库还不存在」
// 才生成新的。其他任何读失败（权限、磁盘坏块）都不重建——重建等于
// 亲手把库里所有密封 token/TOTP 密钥永久销毁；账号库已在而 key 没了
// 同理拒绝（静默重建只会把丢钥事故藏成「全员登不上」）。
func loadOrCreateKey(path string, dbExists bool) (*secretKey, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) != keyFileSize {
			return nil, fmt.Errorf("密钥文件 %s 长度不对", path)
		}
		// 顺手收敛权限（和 tightenPerms 对 users.db 做的同款）。
		_ = os.Chmod(path, 0o600)
		return &secretKey{aesKey: raw[:32], macKey: raw[32:]}, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("读密钥文件 %s: %w（非「不存在」错误不重建——重建会永久摧毁库里的凭据，请修复后重试或从备份恢复）", path, err)
	case dbExists:
		return nil, fmt.Errorf("密钥文件 %s 不存在但账号库已在：重建会让库里所有 token/TOTP 永久报废。请从备份恢复 %s；确认从零开始请先删掉账号库文件", path, path)
	}
	raw = make([]byte, keyFileSize)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	// O_EXCL：并发/残留的 key 文件绝不覆盖——覆盖和重建一样是摧毁。
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("写密钥文件 %s: %w", path, err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return nil, fmt.Errorf("写密钥文件 %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("写密钥文件 %s: %w", path, err)
	}
	return &secretKey{aesKey: raw[:32], macKey: raw[32:]}, nil
}

// nonceFor 由明文派生 12 字节 nonce，保证确定性。
func (k *secretKey) nonceFor(purpose string, plaintext []byte) []byte {
	m := hmac.New(sha256.New, k.macKey)
	m.Write([]byte(purpose))
	m.Write(plaintext)
	return m.Sum(nil)[:12]
}

// seal 加密。purpose 绑定字段用途（目前只有 "token"），
// 把密文挪到别的用途会解密失败。
func (k *secretKey) seal(purpose string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := k.nonceFor(purpose, plaintext)
	return gcm.Seal(nonce, nonce, plaintext, []byte(purpose)), nil
}

func (k *secretKey) open(purpose string, blob []byte) ([]byte, error) {
	if len(blob) < 12+16 {
		return nil, errors.New("密文太短")
	}
	block, err := aes.NewCipher(k.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ct := blob[:12], blob[12:]
	return gcm.Open(nil, nonce, ct, []byte(purpose))
}
