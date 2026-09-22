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

	// DefaultDeny 是默认直接拒绝的命令名单：删根、格盘、关机、管道执行
	// 远程脚本、读私钥/sudoers、提权、动 agent 自身。
	DefaultDeny = []string{
		`\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(/|~|\$HOME)(\s|$)`,
		`\bmkfs\b`,
		`\bdd\b.*\bof=/dev/`,
		`\b(shutdown|reboot|halt|poweroff)\b`,
		`curl[^|]*\|\s*(ba|z)?sh\b`,
		`wget[^|]*\|\s*(ba|z)?sh\b`,
		`\bfind\b.*\s-(exec|execdir|ok|okdir|delete)\b`,
		`\brg\b.*--pre\b`,
		`>\s*/dev/sd`,
		`\bchmod\s+(-R\s+)?777\s+/`,
		`\.ssh/(id_|authorized_keys)`,
		`/etc/(shadow|sudoers)`,
		`\bsudo\b`,
		`\bsu\s`,
		`ws2ssh-agent`,
	}

	// DefaultDenyPaths 是 read_file/write_file 默认禁碰的路径：私钥、
	// 凭证、agent 自己的 token 和配置。
	DefaultDenyPaths = []string{
		`(^|/)\.ssh/`,
		`(^|/)\.gnupg/`,
		`^/etc/(shadow|sudoers)`,
		`(^|/)\.aws/credentials$`,
		`ws2ssh/(token|agent\.yaml)$`,
	}
)

// Policy 是编译好的命令/路径策略。
type Policy struct {
	def       Decision
	allow     []*regexp.Regexp
	deny      []*regexp.Regexp
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

// Command 裁定一条 shell 命令。流程：整串和每个段都过 deny → 段里出现
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
