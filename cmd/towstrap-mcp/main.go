// towstrap-mcp 是 towstrap 的 MCP 入口：LLM 应用通过它跑命令、读写被控机
// 上的文件，带策略过滤和人工批准。
//
// 用法：
//
//	towstrap-mcp [--config 路径] [serve]   起 stdio MCP server（默认）
//	towstrap-mcp [--config 路径] pending   列出等待批准的请求
//	towstrap-mcp [--config 路径] approve <id>|--all
//	towstrap-mcp [--config 路径] deny <id>|--all
//	towstrap-mcp connect ...               把 towstrap skill 装进本机 AI 编码助手
//	towstrap-mcp version
//
// serve 模式下 stdout 是 MCP 协议通道，所有日志只走 stderr。
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/towstrap/towstrap/internal/mcpsrv"
	"github.com/towstrap/towstrap/internal/version"
)

func main() {
	cfgPath := mcpsrv.DefaultPath()
	args := os.Args[1:]
	// 先摘出 --config，剩下的第一个词是子命令。
	rest := args[:0]
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			cfgPath = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	args = rest

	sub := "serve"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "serve":
		serve(cfgPath)
	case "pending":
		pending(cfgPath)
	case "approve", "deny":
		all := len(args) > 1 && args[1] == "--all"
		id := ""
		if len(args) > 1 && !all {
			id = args[1]
		}
		settle(cfgPath, sub, id, all)
	case "connect":
		connect(cfgPath, args[1:])
	case "version":
		fmt.Println(version.String())
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %q\n\n", sub)
		fmt.Fprintf(os.Stderr, `用法：
  towstrap-mcp [--config 路径] [serve]    起 stdio MCP server（默认）
  towstrap-mcp [--config 路径] pending    列出等待批准的请求
  towstrap-mcp [--config 路径] approve <id>|--all   批准
  towstrap-mcp [--config 路径] deny <id>|--all      拒绝
  towstrap-mcp connect ...                把 towstrap skill 装进本机 AI 编码助手
                                        （connect help 看细项）
  towstrap-mcp version                    打印版本
`)
		os.Exit(2)
	}
}

// loadForCLI 给 pending/approve/deny 找 approvals_dir：--config 给了就必须
// 能读；没给就试默认路径，读不了用缺省目录（反正子命令只是往里面写文件）。
func loadForCLI(cfgPath string) *mcpsrv.Config {
	cfg, err := mcpsrv.LoadConfig(cfgPath)
	if err == nil {
		return cfg
	}
	if cfgPath != mcpsrv.DefaultPath() {
		fmt.Fprintf(os.Stderr, "读配置 %s 失败: %v\n", cfgPath, err)
		os.Exit(1)
	}
	return &mcpsrv.Config{ApprovalsDir: mcpsrv.DefaultApprovalsDir()}
}

func serve(cfgPath string) {
	cfg, err := mcpsrv.LoadConfig(cfgPath)
	if err != nil {
		slog.Error("读配置失败", "path", cfgPath, "err", err)
		os.Exit(1)
	}
	pool, err := mcpsrv.NewPool(cfg)
	if err != nil {
		slog.Error("初始化失败", "err", err)
		os.Exit(1)
	}
	srv, err := mcpsrv.New(cfg, pool)
	if err != nil {
		slog.Error("初始化失败", "err", err)
		os.Exit(1)
	}
	defer srv.Close()
	slog.Info("towstrap-mcp 运行中", "server", cfg.Server, "machines", len(cfg.Machines),
		"policy", cfg.Policy.Default)
	// stdout 只走 MCP 协议；slog 默认写 stderr，不要动。
	if err := srv.MCP().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		slog.Error("MCP server 退出", "err", err)
		os.Exit(1)
	}
}

func pending(cfgPath string) {
	cfg := loadForCLI(cfgPath)
	list, err := mcpsrv.Pending(cfg.ApprovalsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读批准目录失败: %v\n", err)
		os.Exit(1)
	}
	if len(list) == 0 {
		fmt.Println("没有等待批准的请求")
		return
	}
	for _, p := range list {
		fmt.Printf("%s  %s  %-8s  %s  （等了 %s）\n",
			p.ID, p.Machine, p.Kind, p.Detail,
			time.Since(p.Created).Round(time.Second))
	}
	fmt.Println("\n批准：towstrap-mcp approve <id>|--all；拒绝：towstrap-mcp deny <id>|--all")
}

func settle(cfgPath, verb, id string, all bool) {
	cfg := loadForCLI(cfgPath)
	var n int
	var err error
	if verb == "approve" {
		n, err = mcpsrv.ApprovePending(cfg.ApprovalsDir, id, all)
	} else {
		n, err = mcpsrv.DenyPending(cfg.ApprovalsDir, id, all)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("已处理 %d 条\n", n)
}
