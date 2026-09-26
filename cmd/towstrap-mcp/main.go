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
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/mcpsrv"
	"github.com/towstrap/towstrap/internal/version"
)

func main() {
	cfgPath := mcpsrv.DefaultPath()
	approvalsDir := ""
	args := os.Args[1:]
	// 先摘出 --config / --approvals-dir，剩下的第一个词是子命令。
	// --approvals-dir 是批准命令的指路牌（通知里提示的批准命令就带着
	// 它），approve/deny/pending 三个子命令都认。
	rest := args[:0]
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--config" && i+1 < len(args):
			cfgPath = args[i+1]
			i++
		case args[i] == "--approvals-dir" && i+1 < len(args):
			approvalsDir = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--approvals-dir="):
			approvalsDir = strings.TrimPrefix(args[i], "--approvals-dir=")
		default:
			rest = append(rest, args[i])
		}
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
		pending(cfgPath, approvalsDir)
	case "approve", "deny":
		var id string
		var all, rem bool
		for _, a := range args[1:] {
			switch a {
			case "--all":
				all = true
			case "--remember":
				rem = true
			default:
				if id == "" {
					id = a
				}
			}
		}
		settle(cfgPath, approvalsDir, sub, id, all, rem)
	case "connect":
		connect(cfgPath, args[1:])
	case "version":
		fmt.Println(version.String())
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %q\n\n", sub)
		fmt.Fprintf(os.Stderr, `用法：
  towstrap-mcp [--config 路径] [serve]    起 stdio MCP server（默认）
  towstrap-mcp [--config 路径] [--approvals-dir 目录] pending    列出等待批准的请求
  towstrap-mcp [--approvals-dir 目录] approve [--remember] <id>|--all   批准（--remember：本会话内相同命令不再问）
  towstrap-mcp [--approvals-dir 目录] deny <id>|--all      拒绝
  towstrap-mcp connect ...                把 towstrap skill 装进本机 AI 编码助手
                                        （connect help 看细项）
  towstrap-mcp version                    打印版本
`)
		os.Exit(2)
	}
}

// loadForCLI 给 pending/approve/deny 找 approvals_dir：--approvals-dir
// 直接指定最优先；--config 给了就必须能读；没给就试默认路径，读不了
// 用缺省目录（反正子命令只是往里面写文件）。
// HOME 没设时默认路径/缺省目录都推导不出来——明说原因，别去读 cwd
// 相对路径（cwd 可能是别人给的目录，里面塞个 mcp.yaml 就成了配置）。
func loadForCLI(cfgPath, approvalsDir string) *mcpsrv.Config {
	if approvalsDir != "" {
		return &mcpsrv.Config{ApprovalsDir: approvalsDir}
	}
	if cfgPath != "" {
		cfg, err := mcpsrv.LoadConfig(cfgPath)
		if err == nil {
			return cfg
		}
		if cfgPath != mcpsrv.DefaultPath() {
			fmt.Fprintf(os.Stderr, "读配置 %s 失败: %v\n", cfgPath, err)
			os.Exit(1)
		}
	}
	dir := mcpsrv.DefaultApprovalsDir()
	if dir == "" {
		fmt.Fprintln(os.Stderr, "HOME 未设置，批准目录推导不出来——请用 --config 指定带 approvals_dir 的 mcp.yaml")
		os.Exit(1)
	}
	return &mcpsrv.Config{ApprovalsDir: dir}
}

func serve(cfgPath string) {
	if cfgPath == "" {
		slog.Error("HOME 未设置，默认配置路径推导不出来——请用 --config 显式指定 mcp.yaml")
		os.Exit(1)
	}
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

func pending(cfgPath, approvalsDir string) {
	cfg := loadForCLI(cfgPath, approvalsDir)
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
		// Detail/Machine/Preview 是 LLM 给的原文——打进终端前过一遍
		// 清洗，不然一条带转义序列的「命令」能在审批人终端上画假提示。
		fmt.Printf("%s  %s  %-8s  %s  （等了 %s）\n",
			p.ID, auditlog.Clean(p.Machine), auditlog.Clean(p.Kind), auditlog.Clean(p.Detail),
			time.Since(p.Created).Round(time.Second))
		if p.Preview != "" {
			fmt.Printf("    ↳ %s\n", auditlog.Clean(p.Preview))
		}
	}
	fmt.Println("\n批准：towstrap-mcp approve [--remember] <id>|--all；拒绝：towstrap-mcp deny <id>|--all")
}

func settle(cfgPath, approvalsDir, verb, id string, all, rem bool) {
	cfg := loadForCLI(cfgPath, approvalsDir)
	var n int
	var err error
	if verb == "approve" {
		n, err = mcpsrv.ApprovePending(cfg.ApprovalsDir, id, all, rem)
	} else {
		n, err = mcpsrv.DenyPending(cfg.ApprovalsDir, id, all)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("已处理 %d 条\n", n)
}
