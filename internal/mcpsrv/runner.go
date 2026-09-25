package mcpsrv

import (
	"context"
	"io"
	"time"
)

// Runner 是命令执行后端：towstrap-mcp 的 stdio 模式用 SSH 连接池 Pool，
// towstrap-server 内嵌模式直接经 Hub 在 agent 上执行。Run 的语义和
// Pool.Run 一致：cmd 经被控机 shell -c 解释，stdin 原样喂入，超时/取消
// 由实现方负责杀掉进程；maxOut 是 stdout/stderr 各自的返回上限。
type Runner interface {
	Run(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int) (Result, error)
	// Connected 报告机器当前是否可达（stdio 模式=已有 SSH 连接，服务器模式=agent 在线）。
	Connected(machine string) bool
}

type WorkingDirectoryRunner interface {
	RunAt(ctx context.Context, machine, cmd string, stdin []byte, timeout time.Duration, maxOut int, cwd string) (Result, error)
}

// Shell 是一个常驻的远端 shell 进程（exec 模式，无 PTY）：Write 往它的
// stdin 写，Stdout/Stderr 两条流持续出输出，Close 杀进程。供 run_command
// 的 session 参数用——同一个 Shell 里 cd、export、后台任务全部保留。
type Shell interface {
	io.Writer // 写 stdin
	Stdout() io.Reader
	Stderr() io.Reader
	Close() error
}

// ShellOpener 是可选能力：runner 支持常驻 shell 才实现它（内嵌模式走
// Hub 开一个空命令 exec 会话，stdio 模式走 SSH shell 通道）。runner
// 没实现时带 session 的 run_command 报「不支持」。
type ShellOpener interface {
	OpenShell(ctx context.Context, machine string) (Shell, error)
}

// TerminalOptions 是一次远端 PTY 的启动参数。Command 经被控机 shell -c
// 解释；Cwd 为空时用 agent 的默认目录。
type TerminalOptions struct {
	Command string
	Cwd     string
	Cols    int
	Rows    int
}

// Terminal 是一个远端 PTY：Read 读终端输出，Write 写键盘输入，Resize 改
// 窗口大小，Close 结束远端进程。输出只有一条合并流（stdout/stderr/控制
// 序列都在里面），这是 PTY 的本义。Wait 等远端进程退出并返回退出码；
// 远端进程自然退出或本地 Close 后，Read 最终会返回 io.EOF，然后 Wait
// 才能可靠拿到状态。
type Terminal interface {
	io.Reader
	io.Writer
	Resize(cols, rows int) error
	Close() error
	Wait() int
}

// TerminalOpener 是可选能力：runner 支持 PTY 终端才实现它。stdio 模式
// 走 SSH pty-req，服务器内嵌模式走 Hub 开 Pty 会话。
type TerminalOpener interface {
	OpenTerminal(ctx context.Context, machine string, opts TerminalOptions) (Terminal, error)
}

// MachineChecker 是可选能力：内嵌模式的 runner 用它按当前数据库里的
// MCP 客户端授权逐次复核机器，避免会话建立后撤权还沿用旧清单。stdio
// 模式的静态配置不需要实现。
type MachineChecker interface {
	MachineAllowed(machine string) bool
}
