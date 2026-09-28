package client

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// 单实例锁：同一台机器上跑两个同配置的 agent 会拿同一个 token 反复顶
// 号（服务端踢旧接新），互相把对方蹬下线。锁保证「新的启动旧的关闭」——
// 新实例发现锁被占就读 pidfile 杀掉旧进程再接管。
//   Windows：命名 mutex（Local\TowStrap-<tag>）
//   Unix：   ~/.towstrap/agent-<tag>.lock 上的 flock
// pidfile 记持锁进程，新实例靠它找到旧进程杀掉。
//
// 只有常驻入口 Run 持锁——status/ConnectOnce 这类一次性调用不碰，
// 不然探活会把活着的 agent 杀了。

func agentTag(cfg Config) string {
	sum := sha256.Sum256([]byte(cfg.Server + "|" + cfg.ID))
	return hex.EncodeToString(sum[:])[:12]
}

// agentLockPath 返回锁/pidfile 落点：~/.towstrap/agent-<tag>.lock。
// 家目录拿不到就退回 os.TempDir——宁可锁弱一点也别让 agent 起不来。
func agentLockPath(cfg Config) string {
	dir, err := os.UserHomeDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, ".towstrap", "agent-"+agentTag(cfg)+".lock")
}

func readPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}
