package proto

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// 服务器和 agent 之间的消息。会话有两种方向：
//   - 外人 → 服务器 → agent：open（开命令行；cmd 带命令、pty 标记要不要
//     终端）、data（键入）、eof（客户端关了 stdin，无 PTY 时传给子进程）、
//     resize、close
//   - agent → 服务器：ok、data（输出，s="e" 是 stderr）、close（code 是
//     子进程退出码）、err
//   - token 换发是服务器 → agent 的独立消息对：服务器发 token（ID 是请求
//     号，D 是新 token 明文），agent 把新 token 写进自己的 token 文件后回
//     ok（同 ID）；写不了回 err（同 ID，Err 是原因）。没回 ok 服务器就不
//     换库里的 token。
const (
	TypeHello  = "hello"
	TypeOpen   = "open"
	TypeData   = "data"
	TypeEOF    = "eof"
	TypeResize = "resize"
	TypeClose  = "close"
	TypeOK     = "ok"
	TypeErr    = "err"
	TypeToken  = "token"
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
	// MaxCommandBytes open 消息里命令的上限：命令混在 WebSocket 消息里发给
	// agent，那边单条消息上限 256KB——服务器要先挡住超长命令，别让 agent
	// 收到一条放不下的消息把整条连接打断。
	MaxCommandBytes = 64 << 10
)

type Msg struct {
	T    string `json:"t"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Ver  string `json:"ver,omitempty"` // hello 时 agent 自报的二进制版本（运维可见性；可伪造，别当安全依据）
	// 下面三个只在 hello 里用：agent 上报自己机器上的禁碰文件（token
	// 文件、配置文件——已清洗成绝对路径）和它的家目录、工作目录。服务器
	// 把这些加进 MCP read_file/write_file 的拒名单；Home/Dir 用来把
	// LLM 给的 ~/ 和相对路径解析成绝对形式再精确比对。只能收紧访问，
	// 不会放宽——agent 自报错了最坏是自己文件保护不住。
	Protect []string `json:"protect,omitempty"`
	Home    string   `json:"home,omitempty"`
	Dir     string   `json:"dir,omitempty"`
	From    string   `json:"from,omitempty"` // open 时服务器带上「登录账号@来源 IP」，agent 拿它告知被控机用户
	D       string   `json:"d,omitempty"`
	Cols    int      `json:"cols,omitempty"`
	Rows    int      `json:"rows,omitempty"`
	Cmd     string   `json:"cmd,omitempty"`  // open 时要执行的命令；空 = 交互 shell
	Pty     bool     `json:"pty,omitempty"`  // open 时是否要 PTY（SSH 客户端申请了才 true）
	S       string   `json:"s,omitempty"`    // data 属于哪条流：空 = stdout/PTY，"e" = stderr
	Code    int      `json:"code,omitempty"` // close 时子进程的退出码
	Err     string   `json:"err,omitempty"`
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

// EncodeStream 打包一条 data 消息；stream 为空是 stdout/PTY 输出，"e" 是 stderr。
func EncodeStream(id, stream string, payload []byte) Msg {
	return Msg{T: TypeData, ID: id, S: stream, D: base64.StdEncoding.EncodeToString(payload)}
}

func EncodeData(id string, payload []byte) Msg {
	return EncodeStream(id, "", payload)
}

func (m Msg) Payload() ([]byte, error) {
	if m.D == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(m.D)
}
