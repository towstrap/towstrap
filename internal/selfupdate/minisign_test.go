package selfupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// makeMinisigFixture 造一份符合 minisign 格式的签名：返回公钥 base64 和
// 对 data 的 .minisig 文件文本。
func makeMinisigFixture(t *testing.T, data []byte, tcText string) (pubB64, sigFile string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var keynum [8]byte
	if _, err := rand.Read(keynum[:]); err != nil {
		t.Fatal(err)
	}
	digest := blake2b.Sum512(data)
	sig := ed25519.Sign(priv, digest[:])
	gsig := ed25519.Sign(priv, append(append([]byte{}, sig...), tcText...))
	pubRaw := append(append([]byte("Ed"), keynum[:]...), pub...)
	sigRaw := append(append([]byte("ED"), keynum[:]...), sig...)
	gsigRaw := append(append([]byte("ED"), keynum[:]...), gsig...)
	return base64.StdEncoding.EncodeToString(pubRaw),
		"untrusted comment: signature from minisign secret key\n" +
			base64.StdEncoding.EncodeToString(sigRaw) + "\n" +
			"trusted comment: " + tcText + "\n" +
			base64.StdEncoding.EncodeToString(gsigRaw) + "\n"
}

func TestVerifyMinisig(t *testing.T) {
	data := []byte("abc123  towstrap-linux-amd64\n")
	pub, sigFile := makeMinisigFixture(t, data, "timestamp:12345")

	if err := verifyMinisig(pub, data, sigFile); err != nil {
		t.Fatalf("合法签名应通过: %v", err)
	}
	// 内容被换 → 内容签名不过
	if err := verifyMinisig(pub, []byte("evil  towstrap-linux-amd64\n"), sigFile); err == nil {
		t.Fatal("篡改过的内容不应通过")
	}
	// trusted comment 被换 → 全局签名不过
	tampered := strings.Replace(sigFile, "timestamp:12345", "timestamp:99999", 1)
	if err := verifyMinisig(pub, data, tampered); err == nil {
		t.Fatal("trusted comment 被改不应通过")
	}
	// 别的钥匙签的 → keynum 对不上
	pub2, _ := makeMinisigFixture(t, data, "timestamp:12345")
	if err := verifyMinisig(pub2, data, sigFile); err == nil {
		t.Fatal("别的公钥不应通过")
	}
	// 签名文件缺行
	if err := verifyMinisig(pub, data, "untrusted comment: x\nAAAA\n"); err == nil {
		t.Fatal("残缺签名文件不应通过")
	}
	// 公钥接受整份 minisign.pub 文本
	full := "untrusted comment: minisign public key ABC\n" + pub + "\n"
	if err := verifyMinisig(full, data, sigFile); err != nil {
		t.Fatalf("整份 pub 文件文本也应能验: %v", err)
	}
}
