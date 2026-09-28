package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/harness"
	"github.com/towstrap/towstrap/internal/mcpsrv"
)

const connectUsage = `towstrap-mcp connect —— 把随项目发布的 towstrap skill 装进本机各家 AI 编码助手

用法：
  towstrap-mcp connect [--dry-run]                  安装到检测到的所有 harness
  towstrap-mcp connect --path <skills目录> [--force] [--dry-run]
                                                  只装到指定目录（如项目级 .claude/skills），不扫描
  towstrap-mcp connect list                         列出支持的 harness、检测状态、安装状态
  towstrap-mcp connect uninstall [--path 目录] [--force] [--dry-run]
                                                  卸载本工具装过的 skill
  towstrap-mcp connect mcp --url https://S:7880/mcp --token tsm-...
                                                  把 MCP 接入写进检测到的 harness 配置文件（即插即用）
  towstrap-mcp connect mcp --stdio [--config mcp.yaml]
                                                  写本机 stdio 方式的接入（需先配好 mcp.yaml）
  towstrap-mcp connect mcp --harness claude,codex --url ... --token ...
                                                  只写给定 harness（不管检测）；id 见 connect mcp list
  towstrap-mcp connect print-mcp --url https://S:7880/mcp --token tsm-...
  towstrap-mcp connect print-mcp --stdio [--config mcp.yaml]
                                                  打印各家 harness 的 MCP 配置片段（不写文件）

支持的 harness：Claude Code、Codex、Grok Build、Cursor、Gemini CLI、
OpenCode、GitHub Copilot CLI、Devin CLI、Pi。Codex / Grok 共用 ~/.agents/skills，
只写一次。skill 源文件在仓库 skills/towstrap/，也可以手工拷进任意 skills 目录。
connect mcp 写入前会把原文件备份成 <文件>.bak。
`

// connect 是 towstrap-mcp connect 的入口；cfgPath 是全局 --config 摘出来的值。
func connect(cfgPath string, args []string) {
	verb := "install"
	if len(args) > 0 {
		switch args[0] {
		case "list", "uninstall", "print-mcp", "mcp":
			verb = args[0]
			args = args[1:]
		case "help", "--help", "-h":
			fmt.Print(connectUsage)
			return
		}
	}

	fs := flag.NewFlagSet("towstrap-mcp connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("path", "", "只装到指定 skills 目录，不扫描 harness")
	force := fs.Bool("force", false, "覆盖/删除非本工具安装的同名 skill")
	dry := fs.Bool("dry-run", false, "只打印会做什么，不写文件")
	url := fs.String("url", "", "服务器 /mcp 地址")
	token := fs.String("token", "", "tsm- token")
	stdio := fs.Bool("stdio", false, "生成本机 stdio 方式的接入")
	harnesses := fs.String("harness", "", "connect mcp：逗号分隔的 harness id（claude,codex,grok,cursor,gemini,opencode,copilot,devin,pi）；默认检测到的都写")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprint(os.Stderr, connectUsage)
		os.Exit(2)
	}

	switch verb {
	case "list":
		connectList()
	case "install":
		connectWrite(*path, *force, *dry, false)
	case "uninstall":
		connectWrite(*path, *force, *dry, true)
	case "mcp":
		connectMCP(cfgPath, *url, *token, *stdio, *harnesses, *dry)
	case "print-mcp":
		connectPrintMCP(cfgPath, *url, *token, *stdio)
	}
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "拿不到用户主目录: %v\n", err)
		os.Exit(1)
	}
	return home
}

// connectTargets 解析安装/卸载的目标集合：--path 给了一个就用它，
// 否则扫描本机检测到的 harness 并按目录去重。
func connectTargets(path string) []harness.Target {
	if path != "" {
		return []harness.Target{{Names: "指定目录", SkillsDir: path}}
	}
	return harness.Targets(harness.Detect(homeDir()))
}

func connectList() {
	home := homeDir()
	fmt.Printf("%-20s %-6s %-44s %s\n", "harness", "检测到", "skill 目标目录", "安装状态")
	for _, h := range harness.Table(home) {
		det := "否"
		if harness.CheckDir(h.DetectDir) {
			det = "是"
		}
		present, ours, ver := harness.Installed(h.SkillsDir)
		st := "未安装"
		switch {
		case present && ours:
			st = "已安装 " + ver
		case present:
			st = "有同名目录（非本工具安装）"
		}
		fmt.Printf("%-20s %-6s %-44s %s\n", h.Name, det, harness.Tilde(home, h.SkillsDir), st)
	}
}

// connectWrite 是 install/uninstall 共用的一趟：解析目标、逐个执行、打结果。
func connectWrite(path string, force, dry, uninstall bool) {
	targets := connectTargets(path)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "没检测到任何支持的 harness。可以用 --path 指定一个 skills 目录手动装。")
		os.Exit(1)
	}
	home := homeDir()
	failed := false
	for _, t := range targets {
		var r harness.Result
		if uninstall {
			r = harness.Uninstall(t.SkillsDir, force, dry)
		} else {
			r = harness.Install(t.SkillsDir, force, dry, time.Now())
		}
		if r.Status == harness.StFailed {
			failed = true
		}
		fmt.Printf("%-24s %-46s %s\n", t.Names, harness.Tilde(home, r.TargetDir), r.StatusLine())
	}
	if !uninstall {
		fmt.Println("\n卸载：towstrap-mcp connect uninstall")
	}
	if failed {
		os.Exit(1)
	}
}

func connectPrintMCP(cfgPath, url, token string, stdio bool) {
	var r harness.MCPRequest
	if stdio {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "拿不到可执行文件路径: %v\n", err)
			os.Exit(1)
		}
		r = harness.MCPRequest{Stdio: true, Command: exe, Config: cfgPath}
	} else {
		if url == "" || token == "" {
			fmt.Fprintln(os.Stderr, "print-mcp 需要 --url 和 --token（服务器内嵌 HTTP 方式），或者 --stdio（本机 towstrap-mcp 方式）")
			os.Exit(2)
		}
		r = harness.MCPRequest{URL: url, Token: token}
	}
	for i, s := range harness.MCPSnippets(r) {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("── %s ──\n写进：%s\n\n%s\n", s.Harness, s.File, s.Text)
		if s.Extra != "" {
			fmt.Printf("%s\n", s.Extra)
		}
	}
	if !stdio {
		fmt.Println("\n提醒：token 是凭据，别贴进聊天/仓库。")
	}
}

// connectMCP 是 connect mcp：把 towstrap 的 MCP 接入直接写进各家
// harness 的配置文件——写之前原文件备份成 .bak，已有同名条目按新参数
// 更新（幂等，换 token 重跑就行），内容相同不动。
func connectMCP(cfgPath, url, token string, stdio bool, harnessList string, dry bool) {
	var r harness.MCPRequest
	if stdio {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "拿不到可执行文件路径: %v\n", err)
			os.Exit(1)
		}
		// --config 没给时用默认路径：harness 拉起 towstrap-mcp 时也会读它
		if cfgPath == "" {
			cfgPath = mcpsrv.DefaultPath()
		}
		r = harness.MCPRequest{Stdio: true, Command: exe, Config: cfgPath}
	} else {
		if url == "" || token == "" {
			fmt.Fprintln(os.Stderr, "connect mcp 需要 --url 和 --token（服务器内嵌 HTTP 方式），或者 --stdio（本机 towstrap-mcp 方式）")
			os.Exit(2)
		}
		r = harness.MCPRequest{URL: url, Token: token}
	}

	var only []string
	if harnessList != "" {
		only = strings.Split(harnessList, ",")
	}
	home := homeDir()
	results := harness.WriteMCP(home, r, only, dry)
	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "没检测到任何支持的 harness。可以 --harness 显式指定（可选：%s），\n或手工合并：towstrap-mcp connect print-mcp --url %s --token %s\n",
			harness.MCPIDs(), url, "tsm-...")
		os.Exit(1)
	}
	failed := false
	for _, res := range results {
		verb := res.Status.Line()
		if dry && (res.Status == harness.MCPWritten || res.Status == harness.MCPUpdated) {
			verb += "（dry-run 未写）"
		}
		fmt.Printf("%-22s %-8s %s\n", res.Target.Name, verb, harness.Tilde(home, res.File))
		if res.Err != nil {
			failed = true
			fmt.Printf("    %v\n", res.Err)
		}
		if res.Status == harness.MCPManual && res.Snippet != "" {
			failed = true
			fmt.Printf("    原文件解析不了（可能含注释），请手工合并这段：\n%s\n", indent(res.Snippet, "    "))
		}
		if res.Target.Note != "" && (res.Status == harness.MCPWritten || res.Status == harness.MCPUpdated) {
			fmt.Printf("    %s\n", res.Target.Note)
		}
	}
	fmt.Println("\n改动前原文件已备份成 <配置>.bak；让 harness 重读配置生效（多数重启客户端即可）。")
	if failed {
		os.Exit(1)
	}
}

func indent(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}
