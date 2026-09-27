package selfupdate

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// 发行签名（minisign）的公钥：维护者把 `minisign -V` 用的公钥（base64
// 那行，或 minisign.pub 第二行的内容）粘到这里并随代码发布。置空 =
// 信任根只有 SHA256SUMS（和清单同一个 Release 出——只能挡传输损坏，
// 挡不住发布源被替换）。一旦填上，update 会强校验 SHA256SUMS.minisig：
// 拉不到签名/签名不过都拒绝安装。
var releasePubKey = "RWTbpo7F0knbUQIoW3pAhERl7E/Uh2YKlQu+3Cwjadh0Clz6A4BEA746"

// minisign 文件格式的骨架（只实现验签需要的部分）：
//
//	公钥 base64 = "Ed"(2) || keynum(8) || ed25519 pubkey(32)      = 42 字节
//	签名行 base64 = "ED"(2) || keynum(8) || sig(64)               = 74 字节
//	全局签名行   = "ED"(2) || keynum(8) || gsig(64)               = 74 字节
//	  gsig 签的是 sig || trusted-comment 文本——把「签名确实出自这把
//	  钥匙、签的是这份清单」绑定在一起，不换 trusted comment 就不验它。
//
// -H 预哈希模式（发布脚本用的）：被签消息 = BLAKE2b-512(文件内容)。
const (
	sigAlgoPubkey = "Ed"
	sigAlgoSig    = "ED"
	minisigPubLen = 2 + 8 + ed25519.PublicKeySize
	minisigSigLen = 2 + 8 + ed25519.SignatureSize
)

// verifyMinisig 用公钥核一份 minisign 签名：data 是被签文件内容，
// sigFile 是 .minisig 文件的文本。返回 nil = 签名有效。
func verifyMinisig(pubB64 string, data []byte, sigFile string) error {
	keynum, pub, err := parseMinisignPub(pubB64)
	if err != nil {
		return fmt.Errorf("公钥本身有问题：%w", err)
	}
	sig, tc, gsig, err := parseMinisig(sigFile)
	if err != nil {
		return err
	}
	if string(sig[:10]) != sigAlgoSig+string(keynum[:]) {
		return fmt.Errorf("签名不是这把公钥签的（keynum 对不上）")
	}
	digest := blake2b.Sum512(data)
	if !ed25519.Verify(pub, digest[:], sig[10:]) {
		return fmt.Errorf("minisign 签名校验失败（内容签名不对）")
	}
	// 全局签名盖 (内容签名 || trusted comment)：防止拿别处的合法签名
	// 拼到本文件上混用。
	if !ed25519.Verify(pub, append(append([]byte{}, sig[10:]...), tc...), gsig[10:]) {
		return fmt.Errorf("minisign 签名校验失败（trusted comment 绑定不对）")
	}
	return nil
}

// parseMinisignPub 解 minisign 公钥：接受裸 base64 或整份 minisign.pub
// 文本（「untrusted comment:」行 + base64 行）。
func parseMinisignPub(s string) ([8]byte, ed25519.PublicKey, error) {
	var kn [8]byte
	line := ""
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			line = l
		}
	}
	if line == "" {
		return kn, nil, fmt.Errorf("公钥是空的")
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(raw) != minisigPubLen || string(raw[:2]) != sigAlgoPubkey {
		return kn, nil, fmt.Errorf("公钥格式不对（应为 minisign 公钥的 base64 行）")
	}
	copy(kn[:], raw[2:10])
	return kn, ed25519.PublicKey(raw[10:]), nil
}

// parseMinisig 拆 .minisig 文件：签名行、trusted comment 文本、全局签名行。
func parseMinisig(text string) (sig []byte, tc []byte, gsig []byte, err error) {
	var tcText string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, "\r")
		switch {
		case strings.HasPrefix(l, "untrusted comment:"), l == "":
		case strings.HasPrefix(l, "trusted comment:"):
			tcText = strings.TrimPrefix(l, "trusted comment: ")
		case sig == nil:
			if sig, err = decodeSigLine(l); err != nil {
				return nil, nil, nil, err
			}
		default:
			if gsig, err = decodeSigLine(l); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	if sig == nil || tcText == "" || gsig == nil {
		return nil, nil, nil, fmt.Errorf(".minisig 文件不全（缺签名行/trusted comment/全局签名）")
	}
	return sig, []byte(tcText), gsig, nil
}

func decodeSigLine(l string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(l))
	if err != nil || len(raw) != minisigSigLen || string(raw[:2]) != sigAlgoSig {
		return nil, fmt.Errorf("签名行格式不对")
	}
	return raw, nil
}
