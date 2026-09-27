package mcpsrv

// 文件工具：read_file/write_file 的路径审查（checkPath）与执行。

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type readIn struct {
	Machine string `json:"machine" jsonschema:"机器名"`
	Path    string `json:"path" jsonschema:"要读的文件路径，建议绝对路径或 ~/ 开头"`
}

type readOut struct {
	Content string `json:"content"`
	Bytes   int    `json:"bytes"`
}

type writeIn struct {
	Machine   string `json:"machine" jsonschema:"机器名"`
	Path      string `json:"path" jsonschema:"要写的文件路径，用绝对路径或 ~/ 开头；在机器 roots 里自动放行，否则要用户批准"`
	Content   string `json:"content" jsonschema:"要写入的完整内容（覆盖写）"`
	Confirmed bool   `json:"confirmed,omitempty" jsonschema:"仅 llm 会话内确认路径生效：用户在对话中明确同意后，配合「需要用户确认」的报错原样重试；其它批准路径下此参数无效；没问过用户不要设"`
	Remember  bool   `json:"remember,omitempty" jsonschema:"随 confirmed 一起设（仅 llm 会话内确认路径生效）：用户说此类操作以后都允许时用"`
}

type writeOut struct {
	BytesWritten int `json:"bytes_written"`
}

// checkPath 是文件工具的统一入口审查：成员/授权 → 文本层 deny_paths
// （原文 + 清洗形）→ 远端文件系统解析出真实路径 → 对真实路径再过一遍
// deny_paths 和 agent 自报的禁碰清单。返回的真实路径直接拿去执行——
// 所有别名（大小写、Unicode、符号链接、/proc/self/root）都在远端现形，
// 白名单按文本放行过的路径执行时已是等价的真实形态。
func (s *Server) checkPath(ctx context.Context, machine, rawPath, kind string) (resolved string, m *Machine, ri remoteInfo, early *mcp.CallToolResult, err error) {
	if _, ok := s.cfg.Machines[machine]; !ok || s.machineBlocked(machine) {
		r, e := errResult("机器 %q 不在配置里或当前凭据无权访问", machine)
		return "", nil, remoteInfo{}, r, e
	}
	ri, rerr := s.remoteInfo(ctx, machine)
	if rerr != nil {
		r, e := errResult("%v", rerr)
		return "", nil, remoteInfo{}, r, e
	}
	m = s.machineFor(machine)
	win := ri.dialect.windows()
	if !s.pol.PathFor(rawPath, win) {
		s.audit("MCP-POLICY-DENY", "machine", machine, "kind", kind, "detail", rawPath, "reason", "deny_paths")
		r, e := errResult("策略拒绝：路径 %q 命中 deny_paths（私钥、凭证、agent 配置这类文件不开放）。如确有必要，请向用户说明并由用户调整策略。", rawPath)
		return "", nil, remoteInfo{}, r, e
	}
	resolved, rerr = s.resolvePath(ctx, machine, rawPath, ri.dialect)
	if rerr != nil {
		// 解析不出真实路径就拒：没法证明它不是受保护文件的别名，
		// 宁可误伤也不能放行别名（机器离线/目录不可达/链接环都走到这）。
		s.audit("MCP-POLICY-DENY", "machine", machine, "kind", kind, "detail", rawPath, "reason", "resolve-failed")
		r, e := errResult("路径 %q 无法解析（机器离线、目录不可达或链接环）：%v。文件操作只对能确认真实身份的路径放行。", rawPath, rerr)
		return "", nil, remoteInfo{}, r, e
	}
	if !s.pol.PathResolved(resolved, win, ri.fold) {
		s.audit("MCP-POLICY-DENY", "machine", machine, "kind", kind, "detail", rawPath, "resolved", resolved, "reason", "deny_paths-resolved")
		r, e := errResult("策略拒绝：%q 解析后的真实路径 %q 命中 deny_paths（路径别名改变不了文件身份）。", rawPath, resolved)
		return "", nil, remoteInfo{}, r, e
	}
	if m.ProtectedResolved(resolved, ri.fold) {
		s.audit("MCP-POLICY-DENY", "machine", machine, "kind", kind, "detail", rawPath, "resolved", resolved, "reason", "agent-protect")
		r, e := errResult("策略拒绝：%q 实际指向这台机器 agent 自报的禁碰文件（token/配置文件），任何路径写法都不开放。", rawPath)
		return "", nil, remoteInfo{}, r, e
	}
	return resolved, m, ri, nil, nil
}

// resolvedRootsFor 把机器的 roots 经远端解析成真实路径再比对——符号链接
// 目录也摊平成物理路径，~/x 由远端自己展开。roots 内容变了（指纹不符）
// 才重解；解析失败的条目丢弃（那条 root 名存实亡）。
func (s *Server) resolvedRootsFor(ctx context.Context, machine string, m *Machine, d shellDialect) []string {
	key := strings.Join(m.Roots, "\x00")
	s.mu.Lock()
	ri, cached := s.remotes[machine]
	cached = cached && ri.rootsKey == key && ri.resolvedRoots != nil
	s.mu.Unlock()
	if cached {
		return ri.resolvedRoots
	}
	out := make([]string, 0, len(m.Roots))
	for _, r := range m.Roots {
		if rp, err := s.resolvePath(ctx, machine, r, d); err == nil {
			out = append(out, rp)
		}
	}
	s.mu.Lock()
	ri = s.remotes[machine]
	ri.rootsKey, ri.resolvedRoots = key, out
	s.remotes[machine] = ri
	s.mu.Unlock()
	return out
}

// inResolvedRoots 拿解析后的输入路径对解析后的 roots 做前缀比对——
// 两边都是文件系统认的真实形态，前缀关系即包含关系；fold（macOS/
// Windows）把大小写/Unicode 拼法差异也折叠掉。
func inResolvedRoots(resolved string, roots []string, windows, fold bool) bool {
	if windows {
		cp := cleanWinPath(resolved)
		for _, r := range roots {
			cr := cleanWinPath(r)
			if cp == cr || strings.HasPrefix(cp, cr+"/") {
				return true
			}
		}
		return false
	}
	for _, r := range roots {
		if resolved == r || strings.HasPrefix(resolved, r+"/") {
			return true
		}
		if fold {
			fp, fr := foldPath(resolved), foldPath(r)
			if fp == fr || strings.HasPrefix(fp, fr+"/") {
				return true
			}
		}
	}
	return false
}

func (s *Server) readFile(ctx context.Context, _ *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, readOut, error) {
	in.Machine = s.resolveMachine(in.Machine)
	resolved, _, ri, early, err := s.checkPath(ctx, in.Machine, in.Path, "read_file")
	if early != nil {
		return early, readOut{}, err
	}
	win := ri.dialect.windows()
	// 解析+比对+读取挤在一条远端命令里做（TOCTOU）：解析结果和批准时
	// 不一致就拒，一致就紧接着打开，两次远端调用之间没有掉包窗口。
	// 多读一个字节用来判断超限；head -c 对不存在的文件也会走 stderr 报错。
	var cmd string
	if win {
		cmd = psFileCommand(in.Path, resolved, psReadAction(s.cfg.Limits.MaxFile+1))
	} else {
		cmd = fmt.Sprintf(posixFileCmd, shellQuote(in.Path), shellQuote(resolved),
			fmt.Sprintf("exec head -c %d --", s.cfg.Limits.MaxFile+1))
	}
	res, err := s.runner.Run(ctx, in.Machine, cmd, nil, s.cfg.Limits.Timeout, s.cfg.Limits.MaxFile+1024)
	if err != nil {
		r, e := errResult("执行失败：%v", err)
		return r, readOut{}, e
	}
	if res.ExitCode != 0 {
		r, e := errResult("读 %s 失败（exit_code=%d）：%s", in.Path, res.ExitCode, strings.TrimSpace(res.Stderr))
		return r, readOut{}, e
	}
	if len(res.Stdout) > s.cfg.Limits.MaxFile {
		r, e := errResult("文件 %s 超过上限 %d 字节，请用 run_command 的 head/tail/grep 读一部分", in.Path, s.cfg.Limits.MaxFile)
		return r, readOut{}, e
	}
	if strings.IndexByte(res.Stdout, 0) >= 0 {
		r, e := errResult("文件 %s 含 NUL 字节，是二进制文件，不支持读取", in.Path)
		return r, readOut{}, e
	}
	return textResult("%s", res.Stdout), readOut{Content: res.Stdout, Bytes: len(res.Stdout)}, nil
}

func (s *Server) writeFile(ctx context.Context, req *mcp.CallToolRequest, in writeIn) (*mcp.CallToolResult, writeOut, error) {
	in.Machine = s.resolveMachine(in.Machine)
	resolved, m, ri, early, err := s.checkPath(ctx, in.Machine, in.Path, "write_file")
	if early != nil {
		return early, writeOut{}, err
	}
	win, fold := ri.dialect.windows(), ri.fold
	if len(in.Content) > s.cfg.Limits.MaxFile {
		r, e := errResult("内容 %d 字节超过上限 %d", len(in.Content), s.cfg.Limits.MaxFile)
		return r, writeOut{}, e
	}
	// roots 对解析后的真实路径判：符号链接摊开之后逃出 roots 的写法
	// 按「根外」走批准，不再混进自动放行。roots 本身也经远端解析——
	// 文本配置里的 /var/... 和真实路径 /private/var/... 是同一目录。
	inRoots := inResolvedRoots(resolved, s.resolvedRootsFor(ctx, in.Machine, m, ri.dialect), win, fold)
	var authID string // 非空 = 这次写是批了才落的，结尾要留授权会话记录
	if !inRoots && s.machineOpen(in.Machine) {
		s.audit("MCP-POLICY-OPEN", "machine", in.Machine, "kind", "write_file",
			"detail", fmt.Sprintf("写入 %s（%d 字节）", resolved, len(in.Content)))
	} else if !inRoots {
		ar := ApprovalRequest{
			Machine: in.Machine, Kind: "write_file",
			Detail:  fmt.Sprintf("写入 %s（%d 字节）", resolved, len(in.Content)),
			Digest:  digestOf(in.Content), // 批准绑死内容：换内容要重批
			Preview: previewOf("写入内容", in.Content),
		}
		out, askAgain, aid, err := s.approve(ctx, req, ar, in.Confirmed, in.Remember)
		authID = aid
		if askAgain {
			return elicitRequest(ar), writeOut{}, nil
		}
		if out == AwaitingLLM {
			return llmConfirmResult(ar), writeOut{}, nil
		}
		if err != nil && out != Timeout {
			r, e := errResult("批准环节出错：%v", err)
			return r, writeOut{}, e
		}
		switch out {
		case Approved, ApprovedRemember, ApprovedLLM:
		case DeniedByUser:
			r, e := errResult("用户拒绝了写入 %s。请向用户说明目的，由用户决定；或把目录加进机器的 roots。", resolved)
			return r, writeOut{}, e
		case Timeout:
			r, e := errResult("等待批准超时（%s）", humanDur(s.cfg.Policy.AskTimeout))
			return r, writeOut{}, e
		default:
			r, e := errResult("批准环节不可用：%v", err)
			return r, writeOut{}, e
		}
	}
	var cmd string
	if win {
		cmd = psFileCommand(in.Path, resolved, psWriteAction())
	} else {
		cmd = fmt.Sprintf(posixFileCmd, shellQuote(in.Path), shellQuote(resolved), "exec cat >")
	}
	res, err := s.runner.Run(ctx, in.Machine,
		cmd, []byte(in.Content),
		s.cfg.Limits.Timeout, 4096)
	if err != nil {
		r, e := errResult("执行失败：%v", err)
		return r, writeOut{}, e
	}
	if authID != "" {
		// 授权写入留档：记路径、字节数、结果和内容指纹——不记全文
		// （内容可能很大），要核对原文去机器上找文件。
		sum := sha256.Sum256([]byte(in.Content))
		s.recordAuthExec(authID, in.Machine, "write_file",
			fmt.Sprintf("写入 %s（%d 字节，sha256=%x）", resolved, len(in.Content), sum[:8]), "", "", res)
	}
	if res.ExitCode != 0 {
		r, e := errResult("写 %s 失败（exit_code=%d）：%s", resolved, res.ExitCode, strings.TrimSpace(res.Stderr))
		return r, writeOut{}, e
	}
	return textResult("已写入 %s（%d 字节）", resolved, len(in.Content)),
		writeOut{BytesWritten: len(in.Content)}, nil
}
