package proto

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// 服务器和 agent 之间的消息。会话有两种方向：
//   - 外人 → 服务器 → agent：open（开命令行）、data（键入）、resize、close
//   - agent → 服务器：ok、data（输出）、close、err
const (
	TypeHello  = "hello"
	TypeOpen   = "open"
	TypeData   = "data"
	TypeResize = "resize"
	TypeClose  = "close"
	TypeOK     = "ok"
	TypeErr    = "err"
)

// 连接保活与消息上限，服务器和 agent 两侧共用同一套值。
const (
	// MaxMessageBytes 单条 WebSocket 消息上限。数据分片是 32KB，base64 后约
	// 44KB，留足余量；没有上限的话，持 token 的人一条大消息就能把内存打爆。
	MaxMessageBytes = 256 << 10
	// PingPeriod 心跳间隔；PongWait 内没收到任何消息（含 pong）就断开——
	// 对端死了或卡住都不能让会话永久挂着。
	PingPeriod = 30 * time.Second
	PongWait   = 90 * time.Second
	// WriteWait 单条消息的写超时：对端不读时不能无限等（同一台机器的会话
	// 共用一个写锁，卡住一个就卡住全部）。
	WriteWait = 10 * time.Second
)

type Msg struct {
	T    string `json:"t"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Ver  string `json:"ver,omitempty"`  // hello 时 agent 自报的二进制版本（运维可见性；可伪造，别当安全依据）
	From string `json:"from,omitempty"` // open 时服务器带上「登录账号@来源 IP」，agent 拿它告知被控机用户
	D    string `json:"d,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
	Err  string `json:"err,omitempty"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func ValidName(s string) bool {
	return nameRe.MatchString(s)
}

func SanitizeName(s string) string {
	s = strings.TrimSpace(s)
	if ValidName(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 64 {
		out = out[:64]
	}
	if !ValidName(out) {
		return "agent"
	}
	return out
}

func (m Msg) Bytes() []byte {
	b, err := json.Marshal(m)
	if err != nil {
		return []byte(`{"t":"err","err":"encode"}`)
	}
	return b
}

func Decode(raw []byte) (Msg, error) {
	var m Msg
	err := json.Unmarshal(raw, &m)
	return m, err
}

func EncodeData(id string, payload []byte) Msg {
	return Msg{T: TypeData, ID: id, D: base64.StdEncoding.EncodeToString(payload)}
}

func (m Msg) Payload() ([]byte, error) {
	if m.D == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(m.D)
}
