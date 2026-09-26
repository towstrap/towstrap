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
	// rm 删根/删家不在正则里——词法层面的判定交给 Command 里的
	// rmFatalTargets（~user、~/、$() 包裹这些形态正则表述不齐）。
	DefaultDeny = []string{
		`\bmkfs\b`,
		`\bdd\b.*\bof=/dev/`,
		`curl[^|]*\|\s*(ba|z)?sh\b`,
		`wget[^|]*\|\s*(ba|z)?sh\b`,
		`\brg\b.*--pre\b`,
		`>\s*/dev/sd`,
		`\bchmod\s+(-R\s+)?777\s+/`,
		`\.ssh/(id_|authorized_keys)`,
		`/etc/(shadow|sudoers)`,
		// deny_paths 保护清单同步到命令通道：不然 read_file 拒掉的
		// 凭据文件（aws credentials、gnupg、agent token）一条 cat 就拿走。
		`\.aws/credentials`,
		`\.gnupg/`,
		`towstrap/(token|agent\.yaml)([^-\w]|$)`,
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
//
// 所有判定都同时对着原文和「剥掉引号/反斜杠的归一化文本」跑一遍：
// r”m、p"k"ill、-ex""ec 这种拼装在远端 shell 里就是原命令，只判原文
// 会被绕过去（剥引号不产生新语义，单纯显形）。
func (p *Policy) Command(cmd string) (Decision, string) {
	segs := splitCmd(cmd)
	dq := dequote(cmd)
	if rmFatalTargets(cmd) || (dq != cmd && rmFatalTargets(dq)) {
		return Deny, "rm 递归删根目录/家目录没有正当场景"
	}
	for _, re := range p.deny {
		if m := re.FindString(cmd); m != "" {
			return Deny, fmt.Sprintf("命中 deny 规则 %q（%q）", re.String(), m)
		}
		if dq != cmd {
			if m := re.FindString(dq); m != "" {
				return Deny, fmt.Sprintf("命中 deny 规则 %q（%q；原文用引号/转义做了伪装）", re.String(), m)
			}
		}
	}
	for _, re := range p.ask {
		if m := re.FindString(cmd); m != "" {
			return Ask, ""
		}
		if dq != cmd && re.MatchString(dq) {
			return Ask, ""
		}
	}
	safe := true
	for _, seg := range segs {
		dseg := dequote(seg)
		for _, re := range p.deny {
			if m := re.FindString(seg); m != "" {
				return Deny, fmt.Sprintf("命中 deny 规则 %q（%q）", re.String(), m)
			}
			if dseg != seg {
				if m := re.FindString(dseg); m != "" {
					return Deny, fmt.Sprintf("命中 deny 规则 %q（%q；原文用引号/转义做了伪装）", re.String(), m)
				}
			}
		}
		// 命令替换、重定向、后台执行都可能藏第二动作，没法朴素判断，不自动放行。
		if strings.ContainsAny(seg, "`<>") || strings.Contains(seg, "$(") || strings.Contains(seg, "&") ||
			strings.ContainsAny(dseg, "`<>") || strings.Contains(dseg, "$(") || strings.Contains(dseg, "&") {
			safe = false
		}
	}
	if safe && len(segs) > 0 {
		for _, seg := range segs {
			dseg := dequote(seg)
			matched := false
			for _, re := range p.allow {
				if re.MatchString(seg) || re.MatchString(dseg) {
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

// rmFatalTargets 在词流里找「rm 递归删根/删家」。词法判断比正则稳：
// -r 可以藏在 -rf/-fr/--recursive 任何形态里，目标是 /、//、/..、~、
// ~root、~/x、$HOME/… 这些正则枚举不全的写法；`sudo rm`、`$(rm …)`、
// `; rm` 里的 rm 也逃不掉（每个词都当一次潜在命令名看）。
func rmFatalTargets(s string) bool {
	f := strings.Fields(s)
	for i, raw := range f {
		// 剥掉包壳字符：$(rm)、`rm`、"rm"、$(echo rm) 里的 rm) 都要显形
		if tok := strings.Trim(raw, "$({\"'`)}]"); tok != "rm" {
			continue
		}
		rec := false
		for _, a := range f[i+1:] {
			switch {
			case a == "--" || strings.HasPrefix(a, "--interactive"):
				continue
			case a == "--recursive" || a == "--dir":
				rec = true
			case strings.HasPrefix(a, "--"):
				continue // --preserve-root 之类不改变方向
			case strings.HasPrefix(a, "-"):
				if strings.ContainsAny(a[1:], "rR") {
					rec = true
				}
			case rec && isFatalRmTarget(a):
				return true
			}
		}
	}
	return false
}

// isFatalRmTarget 判定「递归下去就是整盘/整个家」的目标写法。目标必须
// 就是根目录或家目录本身——~/work、$HOME/x 删的是子目录，留给人批。
func isFatalRmTarget(p string) bool {
	t := strings.TrimSuffix(p, "/")
	switch {
	case t == "" || t == "/*":
		return true // "/" 被剥空；/* 等价于根
	case strings.HasPrefix(t, "/"):
		// path.Clean 归一：//、/.、/..、/../.. 全坍回根
		return path.Clean(t) == "/"
	case t == "~" || (strings.HasPrefix(t, "~") && !strings.ContainsRune(t[1:], '/')):
		return true // ~、~root、~alice ——整个家目录
	case t == "$HOME" || t == "${HOME}":
		return true
	}
	return false
}

// dequote 剥掉命令里的 shell 引用（'..'、".."、\x 转义、$'...'），让命令
// 显形。只归一文本不展开任何东西：$()、~、$VAR 原样保留，反斜杠换行
// （续行）整对吃掉。结果可能不再是合法 shell——它只用来给名单做第二次比对。
func dequote(s string) string {
	if !strings.ContainsAny(s, "'\"\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '$':
			// ANSI-C 引用 $'...'：\xNN 转义能把关键字藏进字节里
			// （$'\x72\x6d' 展开就是 rm）。bash/zsh 认这套；POSIX sh
			// 不认——按展开后的字面值比对，多算不算误判。
			if i+1 < len(s) && s[i+1] == '\'' {
				b.WriteString(ansiCDecode(s, &i))
				break
			}
			// $"..." 本地化字符串：内容按字面走
			if i+1 < len(s) && s[i+1] == '"' {
				i += 2
				for i < len(s) && s[i] != '"' {
					b.WriteByte(s[i])
					i++
				}
				break
			}
			b.WriteByte(c)
		case '\'':
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
		case '"':
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				b.WriteByte(s[i])
				i++
			}
		case '\\':
			if i+1 < len(s) {
				i++
				if s[i] != '\n' {
					b.WriteByte(s[i])
				}
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ansiCDecode 解码一段 $'...' ANSI-C 引用。s[*i] 指向 $，函数返回解码
// 后的字面内容并把 *i 留在收尾引号上（或串尾）。
func ansiCDecode(s string, i *int) string {
	j := *i + 2 // 跳过 $'
	var b strings.Builder
	for j < len(s) && s[j] != '\'' {
		if s[j] != '\\' || j+1 >= len(s) {
			b.WriteByte(s[j])
			j++
			continue
		}
		j++
		switch s[j] {
		case 'x', 'u', 'U':
			n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[s[j]]
			v, k := 0, 0
			for k < n && j+k+1 < len(s) && isHex(s[j+k+1]) {
				v = v*16 + int(hexVal(s[j+k+1]))
				k++
			}
			if k > 0 {
				b.WriteRune(rune(v))
				j += k
			} else {
				b.WriteByte(s[j])
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			v, k := 0, 0
			for k < 3 && j+k < len(s) && s[j+k] >= '0' && s[j+k] <= '7' {
				v = v*8 + int(s[j+k]-'0')
				k++
			}
			b.WriteByte(byte(v))
			j += k - 1
		default:
			if v, ok := ansiCSimple(s[j]); ok {
				b.WriteByte(v)
			} else {
				b.WriteByte(s[j]) // \cX 等不常见的写法按字面留
			}
		}
		j++
	}
	*i = j
	return b.String()
}

func ansiCSimple(c byte) (byte, bool) {
	switch c {
	case 'n':
		return '\n', true
	case 't':
		return '\t', true
	case 'r':
		return '\r', true
	case 'a':
		return '\a', true
	case 'b':
		return '\b', true
	case 'f':
		return '\f', true
	case 'v':
		return '\v', true
	case 'e', 'E':
		return 0x1b, true
	case '\\':
		return '\\', true
	case '\'':
		return '\'', true
	}
	return 0, false
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
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

// PathResolved 对「远端文件系统解析后的真实路径」再过一遍 deny_paths：
// 文本层那道判不了文件系统别名（大小写、Unicode 拼法、符号链接），
// 解析后这道对着文件系统认出的路径判。fold 表示远端文件系统不区分
// 大小写/Unicode 拼法（macOS、Windows 默认如此）——这时连折叠形态
// 一起查，不然解析后的目录是真名、末级名字仍可被大小写变体绕过。
func (p *Policy) PathResolved(resolved string, windows, fold bool) bool {
	if windows {
		if winPathBad(resolved) || !winPathAbs(resolved) {
			return false
		}
		clean := cleanWinPath(resolved)
		for _, re := range p.denyPaths {
			if re.MatchString(resolved) || re.MatchString(clean) {
				return false
			}
		}
		return true
	}
	for _, re := range p.denyPaths {
		if re.MatchString(resolved) {
			return false
		}
		if fold && re.MatchString(foldPath(resolved)) {
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
	// UNC/网络路径一律不收：远端 resolver 在策略判定之前就会触碰它
	// （Resolve-Path 发起 SMB/NTLM 协商），\\evil\share 这种输入等于
	// 一条把凭据送出去的通道；\\localhost\C$ 形式也只是盘符规则的别名。
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") {
		return true
	}
	// 冒号只在盘符第二位合法；盘符以外再出现冒号一律拒——尾部的
	// `token::$DATA`、`file:stream` 这类 ADS 写法远端 GetFullPath 不会
	// 归一化，Get-Item 拿不到条目时按原样放行，正好绕过按全名比对的
	// 禁碰清单（不能只查第一个冒号：C:\x\token::$DATA 的第一个冒号是
	// 合法盘符）。
	rest := p
	if len(p) >= 2 && isDriveLetter(p[0]) && p[1] == ':' {
		rest = p[2:]
		if rest == "" || (rest[0] != '/' && rest[0] != '\\') {
			return true
		}
	}
	if strings.IndexByte(rest, ':') >= 0 {
		return true
	}
	// Windows 文件名不能以点或空格结尾——结尾的点会被系统吃掉等价于
	// 没点的文件，正好用来绕过按全名比对的禁碰清单。
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return true
		}
		// 8.3 短名别名（PROGRA~1、TOKEN~1.TXT）：远端 GetFullPath 不会
		// 把它映射回长名，按全名比对的清单认不出；正常文件名里 ~紧跟
		// 数字的写法极少，不收更稳。
		if i := strings.IndexByte(seg, '~'); i >= 0 && i+1 < len(seg) && seg[i+1] >= '1' && seg[i+1] <= '9' {
			return true
		}
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

// ProtectedResolved 对「远端解析后的真实路径」比对保护清单：清单是
// agent 自报的真实路径，入参已经过文件系统归一化，逐字相等即命中。
// fold（macOS/Windows，文件系统不区分大小写/Unicode 拼法）时连折叠
// 形态一起比——末级名字是用户打的，文件系统并不较真拼法。
func (m *Machine) ProtectedResolved(p string, fold bool) bool {
	if m == nil || len(m.Protect) == 0 {
		return false
	}
	for _, t := range m.Protect {
		if t == p {
			return true
		}
		if fold && foldPath(t) == foldPath(p) {
			return true
		}
	}
	return false
}
