// Package monitor 是服务器的旁路监控推送器：把审计事件和周期指标
// 通过 WebSocket 主动推给外部接收端（一个独立的接收进程，网页展示由
// 它负责）。旁路语义是硬约束——推送链路的任何失败都内部消化：队列有
// 上限，满了丢新事件并计数，接收端断了按退避自动重连，Emit 永不阻塞。
package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/towstrap/towstrap/internal/version"
)

const (
	defaultInterval = 5 * time.Second
	defaultBuffer   = 1024
	writeWait       = 10 * time.Second
	dialWait        = 10 * time.Second
	backoffInit     = time.Second
	backoffMax      = 30 * time.Second
	// kvValueMax 限制单个字段值的长度：一条巨型命令不该把监控帧撑爆。
	kvValueMax = 4096
	// frameMax 单帧上限；超过就丢（意味着字段裁剪还不够，正常到不了）。
	frameMax = 256 << 10
)

// Config 是 monitor: 配置小节翻译后的运行时参数。URL 空 = 功能关闭。
type Config struct {
	URL      string        // ws(s):// 接收端地址
	Token    string        // 握手时带 Authorization: Bearer，接收端校验用
	Interval time.Duration // metrics 推送周期，默认 5s
	Buffer   int           // 事件队列条数，默认 1024
	Name     string        // hello 帧里的服务器标识，空 = hostname
}

// frame 是线上协议：每条 WS 文本消息一个 JSON 对象。
//
//	type=hello：建连即发的报到帧，带版本、服务器名和累计丢帧数。
//	type=event：一条审计事件，kv 是字段表。
//	type=metrics：周期指标快照，附累计丢帧数（接收端据此发现丢失）。
type frame struct {
	Type    string            `json:"type"`
	TS      string            `json:"ts"`
	Event   string            `json:"event,omitempty"`
	KV      map[string]string `json:"kv,omitempty"`
	Metrics map[string]any    `json:"metrics,omitempty"`
	Ver     string            `json:"ver,omitempty"`
	Name    string            `json:"name,omitempty"`
	Dropped int64             `json:"dropped,omitempty"`
}

type Monitor struct {
	cfg     Config
	snap    func() map[string]any
	ch      chan frame
	done    chan struct{}
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	dropped atomic.Int64
	dialer  websocket.Dialer
}

// New 装配推送器；cfg.URL 为空返回 nil——调用方按可 nil 使用，
// Emit/Close 等都做了 nil 短路，未启用时开销就是一次判空。
func New(cfg Config) *Monitor {
	if cfg.URL == "" {
		return nil
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = defaultBuffer
	}
	if cfg.Name == "" {
		cfg.Name, _ = os.Hostname()
	}
	return &Monitor{
		cfg:    cfg,
		ch:     make(chan frame, cfg.Buffer),
		done:   make(chan struct{}),
		dialer: websocket.Dialer{HandshakeTimeout: dialWait},
	}
}

// SetSnapshot 注册指标提供者，每 Interval 调一次，返回值原样进 metrics
// 帧。必须在 Start 前调用；提供者要快（读原子量/快照），不许阻塞。
func (m *Monitor) SetSnapshot(fn func() map[string]any) {
	m.snap = fn
}

// Dropped 返回累计被丢的帧数（队列满或编码超限）。也随 hello/metrics 帧
// 上报，这里给本机排查用。
func (m *Monitor) Dropped() int64 {
	if m == nil {
		return 0
	}
	return m.dropped.Load()
}

// Emit 投递一条审计事件。永不阻塞：队列满就丢并计数。kv 成对出现。
func (m *Monitor) Emit(event string, kv ...string) {
	if m == nil {
		return
	}
	f := frame{Type: "event", TS: now(), Event: event}
	if len(kv) > 0 {
		f.KV = make(map[string]string, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			v := kv[i+1]
			if len(v) > kvValueMax {
				v = v[:kvValueMax]
			}
			f.KV[kv[i]] = v
		}
	}
	m.push(f)
}

func (m *Monitor) push(f frame) {
	select {
	case m.ch <- f:
	default:
		m.dropped.Add(1)
	}
}

// Start 起推送 goroutine；Close 停掉并等它退出（在途拨号也取消）。
func (m *Monitor) Start() {
	if m == nil {
		return
	}
	var ctx context.Context
	ctx, m.cancel = context.WithCancel(context.Background())
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.run(ctx)
	}()
}

func (m *Monitor) Close() {
	if m == nil {
		return
	}
	close(m.done)
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

// run 连接主管：连上就跑 pump（推 hello、事件队列、周期 metrics），
// 断了按 1s→30s 退避重连。断线期间事件在队列里攒着，恢复后按序补发。
func (m *Monitor) run(ctx context.Context) {
	backoff := backoffInit
	for {
		conn, err := m.dial(ctx)
		if err == nil {
			backoff = backoffInit
			err = m.pump(conn)
			_ = conn.Close()
		}
		select {
		case <-m.done:
			return
		default:
		}
		slog.Warn("monitor 推送链路断开，稍后重连", "url", m.cfg.URL, "err", err, "retry_in", backoff)
		select {
		case <-m.done:
			return
		case <-time.After(backoff):
		}
		if backoff < backoffMax {
			backoff *= 2
		}
	}
}

func (m *Monitor) dial(ctx context.Context) (*websocket.Conn, error) {
	h := http.Header{}
	if m.cfg.Token != "" {
		h.Set("Authorization", "Bearer "+m.cfg.Token)
	}
	conn, _, err := m.dialer.DialContext(ctx, m.cfg.URL, h)
	return conn, err
}

// pump 单条连接的推送循环：先报 hello（带累计丢帧数），然后三选一——
// 关停、推队列里的事件、到点推 metrics。
func (m *Monitor) pump(conn *websocket.Conn) error {
	if err := m.write(conn, frame{Type: "hello", TS: now(),
		Ver: version.String(), Name: m.cfg.Name, Dropped: m.dropped.Load()}); err != nil {
		return err
	}
	// 排水读循环：WS 的 close/ping/pong 只有读的时候才处理，而且对端
	// 断开也靠读错误第一时间发现——只写不读要等下次写入才撞上。
	dead := make(chan error, 1)
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				dead <- err
				return
			}
		}
	}()
	tick := time.NewTicker(m.cfg.Interval)
	defer tick.Stop()
	for {
		select {
		case <-m.done:
			return errClosed
		default:
		}
		select {
		case <-m.done:
			return errClosed
		case err := <-dead:
			return err
		case f := <-m.ch:
			if err := m.write(conn, f); err != nil {
				return err
			}
		case <-tick.C:
			if m.snap == nil {
				continue
			}
			err := m.write(conn, frame{Type: "metrics", TS: now(),
				Metrics: m.snap(), Dropped: m.dropped.Load()})
			if err != nil {
				return err
			}
		}
	}
}

var errClosed = errors.New("monitor closed")

func (m *Monitor) write(conn *websocket.Conn, f frame) error {
	b, err := json.Marshal(f)
	if err != nil || len(b) > frameMax {
		// 编码失败或帧超限是程序问题不是链路问题：丢帧计数，不重连。
		m.dropped.Add(1)
		return nil
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
	return conn.WriteMessage(websocket.TextMessage, b)
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
