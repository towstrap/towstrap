package mcpsrv

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Decision 是策略对一条命令/一个动作的裁定。
type Decision int

const (
	Run  Decision = iota // 自动放行
	Ask                  // 需要人工批准
	Deny                 // 直接拒绝
)

// 内置名单。注意：这是方便过滤，不是安全边界——朴素切段绕得过完整 shell
// 语法就别指望它拦，真正的边界是被控机上 agent 进程的系统用户权限。
var (
	// DefaultAllow 是只读/低风险命令的默认放行名单。注意几个口子：
	// env 只许裸跑（env rm -rf x 能顺带执行任意命令）；git branch 只枚举
	// 只读形态（-D/-m 这些删改分支的不算）；find/rg 的危险旗标在
	// DefaultDeny 里挡（-exec/-delete、--pre）。
	DefaultAllow = []string{
		`^(ls|pwd|cat|head|tail|wc|grep|rg|find|stat|file|echo|which|whoami|id|uname|df|du|ps|date|tree)\b`,
		`^env$`,
		`^git (status|diff|log|show|remote|rev-parse|ls-files|blame)\b`,
		`^git branch( -a| -r| -v| -vv| --list| --show-current|$)`,
		`^go (build|test|vet|fmt|list|mod tidy|doc|version)\b`,
		`^(npm|pnpm|yarn) (test|run (test|lint|build)|ls)\b`,
		`^(cargo|make) (test|build|check|fmt)\b`,
		`^(python3?|node) --version$`,
		`^gofmt\b`,
	}

	// DefaultDeny 是默认直接拒绝的命令名单：删根、格盘、管道执行远程
	// 脚本、读私钥/sudoers、动 agent 自身——这些没有「确认一下就行」
	// 的正当场景，不给批准机会。
	DefaultDeny = []string{
		`\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(/|~|\$HOME)(\s|$)`,
		`\bmkfs\b`,
		`\bdd\b.*\bof=/dev/`,
		`curl[^|]*\|\s*(ba|z)?sh\b`,
		`wget[^|]*\|\s*(ba|z)?sh\b`,
		`\brg\b.*--pre\b`,
		`>\s*/dev/sd`,
		`\bchmod\s+(-R\s+)?777\s+/`,
		`\.ssh/(id_|authorized_keys)`,
		`/etc/(shadow|sudoers)`,
		// 动 agent 自身。老名 towstrap-agent 整词挡；新名 towstrap 和仓库名、
		// towstrap-server/-mcp 撞车，只挡「杀进程 / 服务启停 / 覆盖删除二进制
		// 和单元文件」这几种写法。towstrap([^-\w]|$) = 后面不接 - 或字母数字。
		`towstrap-agent`,
		`\b(pkill|killall|kill|taskkill|Stop-Process)\b[^;&|\n]*\btowstrap([^-\w]|$)`,
		`\b(systemctl|service|launchctl|sc|schtasks|rc-service)\b[^;&|\n]*\btowstrap([^-\w]|$)`,
		`bin/towstrap([^-\w]|$)`,
		`\btowstrap\.(service|plist)\b`,
	}

	// DefaultAsk 是默认要人工确认的命令名单：危险但有正当场景——删
	// 文件、提权、杀进程、关机重启、改远端或丢本地改动的 git 操作、
	// 动权限/属主/磁盘。命中后进批准环节，批了才执行。判定顺序在
	// Command 里：deny > ask > allow > default——管理员 allow 了也
	// 压不过 ask，想静默放行得把对应 ask 规则撤掉。
	DefaultAsk = []string{
		`\brm\b`,
		`\bsudo\b`,
		`\bsu\s`,
		`\b(kill|pkill|killall)\b`,
		`\b(shutdown|reboot|halt|poweroff)\b`,
		`\bfind\b.*\s-(exec|execdir|ok|okdir|delete)\b`,
		`git\s+(push|reset|clean|rebase)\b`,
		`\b(chmod|chown)\b`,
		`\b(dd|fdisk|diskutil)\b`,
	}

	// DefaultDenyPaths 是 read_file/write_file 默认禁碰的路径：私钥、
	// 凭证、agent 自己的 token 和配置。
	DefaultDenyPaths = []string{
		`(^|/)\.ssh/`,
		`(^|/)\.gnupg/`,
		`^/etc/(shadow|sudoers)`,
		`(^|/)\.aws/credentials$`,
		`towstrap/(token|agent\.yaml)$`,
	}
)

// Policy 是编译好的命令/路径策略。
type Policy struct {
	def       Decision
	allow     []*regexp.Regexp
	deny      []*regexp.Regexp
	ask       []*regexp.Regexp
	denyPaths []*regexp.Regexp
}

// newPolicy 编译配置里的名单；某份名单没写就用内置默认，写了（哪怕空）
// 就照用户给的来。
func newPolicy(cfg *PolicyCfg) (*Policy, error) {
	p := &Policy{}
	switch cfg.Default {
	case "run":
		p.def = Run
	case "deny":
		p.def = Deny
	default:
		p.def = Ask
	}
	var err error
	if p.allow, err = compileAll("policy.allow", cfg.Allow, DefaultAllow); err != nil {
		return nil, err
	}
	if p.deny, err = compileAll("policy.deny", cfg.Deny, DefaultDeny); err != nil {
		return nil, err
	}
	if p.ask, err = compileAll("policy.ask", cfg.Ask, DefaultAsk); err != nil {
		return nil, err
	}
	if p.denyPaths, err = compileAll("policy.deny_paths", cfg.DenyPaths, DefaultDenyPaths); err != nil {
		return nil, err
	}
	return p, nil
}

func compileAll(name string, pats, def []string) ([]*regexp.Regexp, error) {
	if pats == nil {
		pats = def
	}
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, pat := range pats {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("%s 里的正则 %q 编译失败: %w", name, pat, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Command 裁定一条 shell 命令。流程：整串和每个段都过 deny → 整串过
// ask（命中即去批准，$() 里藏的危险命令在段文本里也照中）→ 段里出现
// 命令替换/重定向/后台符号就不敢自动放行 → 每段都命中 allow 才 Run →
// 否则落到 policy.default。切段是按 && || ; | 换行的朴素切法，不是完整
// shell 解析。
func (p *Policy) Command(cmd string) (Decision, string) {
	segs := splitCmd(cmd)
	for _, re := range p.deny {
		if m := re.FindString(cmd); m != "" {
			return Deny, fmt.Sprintf("命中 deny 规则 %q（%q）", re.String(), m)
		}
	}
	for _, re := range p.ask {
		if m := re.FindString(cmd); m != "" {
			return Ask, ""
		}
	}
	safe := true
	for _, seg := range segs {
		for _, re := range p.deny {
			if m := re.FindString(seg); m != "" {
				return Deny, fmt.Sprintf("命中 deny 规则 %q（%q）", re.String(), m)
			}
		}
		// 命令替换、重定向、后台执行都可能藏第二动作，没法朴素判断，不自动放行。
		if strings.ContainsAny(seg, "`<>") || strings.Contains(seg, "$(") || strings.Contains(seg, "&") {
			safe = false
		}
	}
	if safe && len(segs) > 0 {
		for _, seg := range segs {
			matched := false
			for _, re := range p.allow {
				if re.MatchString(seg) {
					matched = true
					break
				}
			}
			if !matched {
				return p.def, ""
			}
		}
		return Run, ""
	}
	return p.def, ""
}

// splitCmd 按 && || ; | 换行朴素切段，去掉空段。
func splitCmd(cmd string) []string {
	r := strings.NewReplacer("&&", "\n", "||", "\n", ";", "\n", "|", "\n", "\r", "\n")
	var out []string
	for _, seg := range strings.Split(r.Replace(cmd), "\n") {
		if seg = strings.TrimSpace(seg); seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// Path 判断一个路径能不能碰：命中 deny_paths 就不行。
func (p *Policy) Path(path string) bool {
	return p.PathFor(path, false)
}

func (p *Policy) PathFor(path string, windows bool) bool {
	if windows {
		if winPathBad(path) || !winPathAbs(path) {
			return false
		}
		clean := cleanWinPath(path)
		for _, re := range p.denyPaths {
			if re.MatchString(path) || re.MatchString(clean) {
				return false
			}
		}
		return true
	}
	clean := cleanRemotePath(path)
	for _, re := range p.denyPaths {
		if re.MatchString(path) || re.MatchString(clean) {
			return false
		}
	}
	return true
}

// InRoots 判断路径是否落在机器的放行目录里。相对路径一律算不在——远端
// 家目录我们并不知道，写文件请用绝对路径或 ~/ 开头。匹配是文本前缀：
// ~ 不展开成真实家目录，配置里 roots 写 ~/x 就匹配远端路径 ~/x。
// 已知绕法：roots 目录里若有指向外面的符号链接（如 ~/work/link -> /etc），
// 写 ~/work/link/x 会逃过前缀匹配——远端不解析真实路径，roots 里别放这种链接。
func (m *Machine) InRoots(p string) bool {
	return m.InRootsFor(p, false)
}

func (m *Machine) InRootsFor(p string, windows bool) bool {
	if windows {
		if winPathBad(p) || !winPathAbs(p) {
			return false
		}
		cp := cleanWinPath(p)
		for _, r := range m.Roots {
			cr := cleanWinPath(r)
			if cp == cr || strings.HasPrefix(cp, cr+"/") {
				return true
			}
		}
		return false
	}
	if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "~/") {
		return false
	}
	cp := cleanRemotePath(p)
	for _, r := range m.Roots {
		cr := cleanRemotePath(r)
		if cp == cr || strings.HasPrefix(cp, cr+"/") {
			return true
		}
	}
	return false
}

// cleanRemotePath 用 POSIX 规则清路径（被控机按 Unix 对待）。
func cleanRemotePath(p string) string {
	return path.Clean(p)
}

func cleanWinPath(p string) string {
	q := strings.ReplaceAll(p, `\`, "/")
	return strings.ToLower(path.Clean(q))
}

func isDriveLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func winPathBad(p string) bool {
	if strings.HasPrefix(p, `\\?\`) || strings.HasPrefix(p, `\\.\`) ||
		strings.HasPrefix(p, "//?/") || strings.HasPrefix(p, "//./") {
		return true
	}
	if len(p) >= 2 && p[1] == ':' && isDriveLetter(p[0]) {
		if len(p) == 2 {
			return true
		}
		return p[2] != '/' && p[2] != '\\'
	}
	return false
}

func winPathAbs(p string) bool {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && isDriveLetter(p[0]) && (p[2] == '/' || p[2] == '\\') {
		return true
	}
	return strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//")
}

// Protected 判断路径是否命中这台机器 agent 自报的禁碰清单（token 文件、
// 配置文件）。~/ 用上报的 Home 展开、相对路径按上报的 Dir 解析，清洗后
// 和清单逐项精确比对——LLM 换写法（./x、a/../x）洗完后是同一个路径。
// 清单是文件级精确匹配，不含目录前缀关系；机器没上报（离线/旧版本/
// stdio 模式）返回 false。
func (m *Machine) Protected(p string) bool {
	return m.ProtectedFor(p, false)
}

func (m *Machine) ProtectedFor(p string, windows bool) bool {
	if m == nil || len(m.Protect) == 0 {
		return false
	}
	if windows {
		if winPathBad(p) || !winPathAbs(p) {
			return true
		}
		q := strings.ReplaceAll(p, `\`, "/")
		cp := cleanWinPath(q)
		switch {
		case strings.HasPrefix(q, "~/") && m.Home != "":
			cp = cleanWinPath(m.Home + "/" + q[2:])
		case q == "~" && m.Home != "":
			cp = cleanWinPath(m.Home)
		}
		for _, t := range m.Protect {
			if cleanWinPath(t) == cp {
				return true
			}
		}
		return false
	}
	cp := cleanRemotePath(p)
	switch {
	case strings.HasPrefix(p, "~/") && m.Home != "":
		cp = cleanRemotePath(m.Home + "/" + p[2:])
	case p == "~" && m.Home != "":
		cp = cleanRemotePath(m.Home)
	case !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "~/") && m.Dir != "":
		cp = cleanRemotePath(m.Dir + "/" + p)
	}
	for _, t := range m.Protect {
		if cleanRemotePath(t) == cp {
			return true
		}
	}
	return false
}
