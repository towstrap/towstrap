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
	gsigRaw := gsig // 全局签名行是裸 64 字节签名，无前缀无 keynum
	return base64.StdEncoding.EncodeToString(pubRaw),
		"untrusted comment: signature from minisign secret key\n" +
			base64.StdEncoding.EncodeToString(sigRaw) + "\n" +
			"trusted comment: " + tcText + "\n" +
			base64.StdEncoding.EncodeToString(gsigRaw) + "\n"
}

// TestVerifyMinisigRealFile：官方 minisign 真产出的 .minisig——全局签名
// 行是裸 64 字节签名（无 "ED" 前缀、无 keynum），和内容签名行的 74 字节
// 格式不同。回归钉死兼容：之前按同一格式解两行，真签名必拒。
func TestVerifyMinisigRealFile(t *testing.T) {
	// v0.4.1 release 实际产出的签名（公钥即内嵌的 releasePubKey）
	const realSig = `untrusted comment: signature from minisign secret key
RUTbpo7F0knbUYsO76N9wLsCZzI++hs6EHKgLQypxtPP79e+pqw+vgGZvVWsaTTwVOtXL48KIIJZ1X2Azxdhs2mf1IuLqhNfUAM=
trusted comment: timestamp:1790490919	file:SHA256SUMS	hashed
DCKZMC0I5zl4HVlSBkEYCszEkRb0J4ZeVqNtmufWNqwxXC4xBMBCOYcG9IgwDEVrNFAIGPQ/TmOjY4ChsiqqDw==
`
	const realSums = `97f576852db32733dbec0f106179972bd819a18f0f545985e2617d873470be51  towstrap-darwin-amd64
bed63ad3c8a6cf5ad81e6b59524d39231617e6f78b415a5015247066d1118a5e  towstrap-darwin-arm64
be67023d04a310c80f92f994574dd38142b80f5a3c4522cd27c7c49093861e99  towstrap-linux-amd64
b076b0f8bb4048f04f19b307ca5c48dc8fbf41a8f96744f214bc5591723811fc  towstrap-linux-arm64
897c22682824345f238ea641aa987d8c75af1021ca4c893ef6c5ac506e629c59  towstrap-mcp-darwin-amd64
f514df72dccccd521e154287fa4e017a31a438526aa165b1fd6b20368554115a  towstrap-mcp-darwin-arm64
8f63aa670016281b902860b597c84f9b22aa2d4bbc98cf782083d2c950dac09a  towstrap-mcp-linux-amd64
7426c8a0cb115dd5f241447230aea247b70e7753493e9f88f4c1f9f470de8ebf  towstrap-mcp-linux-arm64
30226c43973419b3e3c5415c3722ce542603710575329c8e70c107d66c6e8b47  towstrap-mcp-windows-amd64.exe
c2c00f9078a9cee655630519b2fc090635ff0d4f86f9bc840b616a6f656a8adc  towstrap-mcp-windows-arm64.exe
203323d10dd7684559dad8795585e338897ec06d0bcb23d24a0630e3d2e17fae  towstrap-server-darwin-amd64
3b812b9218a0683c411d425406c54cce3046b967ff0d012720fc1364194cabba  towstrap-server-darwin-arm64
dc5181f373ed7df1069d3d6b4d4748c4d17a6d61313971d5c7e125870e766c69  towstrap-server-linux-amd64
335218fe7063f044178b2986f2a05bdf9c2d37919a7b2b581034e7fb55518e8f  towstrap-server-linux-arm64
a503e2aa1c3db1eca75856ed3eb2f6f8efd7bdd4280bcb2a73f9e3797f51c7db  towstrap-server-windows-amd64.exe
eeb3dd062f751b26b19cd6bf87d7b8cb9ab9286c5244f16ae3e9264010c8b6f8  towstrap-server-windows-arm64.exe
c4d3ba333d1308d73d34e9c947aea5010be12897effe5b1580811b12e5ef29f7  towstrap-windows-amd64.exe
939728bf626f2bce6c5bb7034616f6bd6b2d52c574d1a07abaacb23ff8e0b736  towstrap-windows-arm64.exe
`
	if err := verifyMinisig("RWTbpo7F0knbUQIoW3pAhERl7E/Uh2YKlQu+3Cwjadh0Clz6A4BEA746", []byte(realSums), realSig); err != nil {
		t.Fatalf("官方 minisign 产出应能通过: %v", err)
	}
	// 篡改过的清单必须拒
	if err := verifyMinisig("RWTbpo7F0knbUQIoW3pAhERl7E/Uh2YKlQu+3Cwjadh0Clz6A4BEA746", []byte(realSums+"x"), realSig); err == nil {
		t.Fatal("篡改过的内容竟然验过了")
	}
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
