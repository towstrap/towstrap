package mcpsrv

import (
	"context"
	"time"
)

// Runner 是命令执行后端：ws2ssh-mcp 的 stdio 模式用 SSH 连接池 Pool，
// ws2ssh-server 内嵌模式直接经 Hub 在 agent 上执行。Run 的语义和
// Pool.Run 一致：cmd 经被控机 shell -c 解释，stdin 原样喂入，超时/取消
// 由实现方负责杀掉进程；maxOut 是 stdout/stderr 各自的返回上限。
type Runner interface {
	Run(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int) (Result, error)
	// Connected 报告机器当前是否可达（stdio 模式=已有 SSH 连接，服务器模式=agent 在线）。
	Connected(machine string) bool
}
