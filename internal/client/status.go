package client

import (
	"errors"
	"os"
	"sync"
	"time"

	"github.com/towstrap/towstrap/internal/version"
)

// ErrNoLocalSock 本机查询通道不存在（Windows 暂没有 mirror.sock）。
var ErrNoLocalSock = errors.New("本机 mirror socket 不可用")

// StatusInfo 是 mirror.sock status op 的应答，也是 towstrap status 展示的
// 数据源。socket 能应答本身就证明 agent 进程活着——这是权威的在线信号，
// 不用去猜 pid 或猜服务管理器的状态。
type StatusInfo struct {
	PID         int       `json:"pid"`
	ID          string    `json:"id"`
	Server      string    `json:"server"`
	Version     string    `json:"version"`
	StartedAt   time.Time `json:"started_at"`
	Connected   bool      `json:"connected"`
	ConnectedAt time.Time `json:"connected_at,omitempty"`
	LastErr     string    `json:"last_err,omitempty"`
	LastErrAt   time.Time `json:"last_err_at,omitempty"`
	Dials       int       `json:"dials"`    // 连接尝试次数（含重连）
	Sessions    int       `json:"sessions"` // 当前活跃远程会话
	Mirrors     int       `json:"mirrors"`  // 活着的镜像终端数
}

// connState 进程内连接账本：Run 的重连循环每试/每成/每断各记一笔，
// status op 靠它回答「连没连上、上次为什么断」。
type connState struct {
	mu   sync.Mutex
	info StatusInfo
}

func newConnState(id, server string) *connState {
	return &connState{info: StatusInfo{
		PID:       os.Getpid(),
		ID:        id,
		Server:    server,
		Version:   version.String(),
		StartedAt: time.Now(),
	}}
}

func (s *connState) dialing() {
	s.mu.Lock()
	s.info.Dials++
	s.mu.Unlock()
}

func (s *connState) connected() {
	s.mu.Lock()
	s.info.Connected = true
	s.info.ConnectedAt = time.Now()
	s.info.LastErr = ""
	s.mu.Unlock()
}

func (s *connState) disconnected(err error) {
	s.mu.Lock()
	s.info.Connected = false
	if err != nil {
		s.info.LastErr = err.Error()
		s.info.LastErrAt = time.Now()
	}
	s.mu.Unlock()
}

func (s *connState) snapshot() StatusInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}
