package main

// towstrap-server init —— 服务端装完后的交互式初始化向导。
// curl|sh 装脚本时 stdin 被管道占着没法提问，所以向导做成独立子命令，
// install-server.sh 装完提示跑它；改配置时也能反复用（幂等，已是
// 目标值的项直接跳过不写）。

// 问三件事：对外地址（public_url，决定下发安装脚本里的地址）、要不要
// 自助注册（register/register_invite）、第一个账号（内联建号+打印
// token）。YAML 用 Node 级改写保留原有注释和无关字段；改完如果
// systemd 服务在跑就重启生效。

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/proto"
)

func usageInit() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap-server init [选项]

装完服务端后的初始化向导（交互式；幂等，可反复跑改配置）：

  1. 对外地址 public_url   —— 下发安装命令/落地页里的服务器地址
  2. 自助注册 register     —— 开了后机器上 towstrap register 就能建号
  3. 第一个账号            —— 内联建号并打印这台机器的 agent token

写完配置后如果 systemd 服务 towstrap-server 在跑会自动重启生效。

  --config 路径        server.yaml 位置（默认 /etc/towstrap/server.yaml，
                       否则 ~/.config/towstrap/server.yaml）
  --users-db 路径      账号库位置（默认读 yaml 的 users_db）
  --public-url 地址    脚本模式直接给值（如 wss://s.example.com:443）
  --register           开自助注册（脚本模式用；--no-register 关）
  --no-register        关自助注册
  --register-invite 码 邀请码（配合 --register；空串清除）
  --account 名字       脚本模式建号用的账号名
  --password-stdin     脚本模式：账号密码从 stdin 读一行
  --no-restart         不重启 systemd 服务
  --yes                非交互模式标志：没给的项保持现状不提问
`)
}

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.Usage = usageInit
	configPath := fs.String("config", "", "")
	usersDB := fs.String("users-db", "", "")
	publicURL := fs.String("public-url", "", "")
	regYes := fs.Bool("register", false, "")
	regNo := fs.Bool("no-register", false, "")
	regInvite := fs.String("register-invite", "", "")
	account := fs.String("account", "", "")
	pwStdin := fs.Bool("password-stdin", false, "")
	noRestart := fs.Bool("no-restart", false, "")
	yes := fs.Bool("yes", false, "")
	_ = fs.Parse(args)

	interactive := term.IsTerminal(int(os.Stdin.Fd())) && !*yes && !*pwStdin
	if !interactive && !*yes {
		fmt.Fprintln(os.Stderr, "非终端环境：加 --yes 走脚本模式（没给的项保持现状），或在终端里交互跑")
		return 2
	}

	// 配置路径：旗标 > /etc（root 或已存在）> 用户目录
	path := *configPath
	if path == "" {
		if dir, err := os.Stat("/etc/towstrap/server.yaml"); err == nil && !dir.IsDir() {
			path = "/etc/towstrap/server.yaml"
		} else if os.Geteuid() == 0 {
			path = "/etc/towstrap/server.yaml"
		} else {
			path = filepath.Join(os.Getenv("HOME"), ".config", "towstrap", "server.yaml")
			if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
				path = filepath.Join(xdg, "towstrap", "server.yaml")
			}
		}
	}

	// 现状：能读就读（没有会现场建最小文件）。LoadServer 两种写法都认
	// （server: 小节 / 顶层扁平键）——直接 Unmarshal 一个 {Server} 壳会
	// 把扁平文件的现状全部看成零值，默认值提示会把真配置盖掉。
	cur := config.Server{}
	exists := false
	if _, err := os.ReadFile(path); err == nil {
		exists = true
		if c, err := config.LoadServer(path); err == nil {
			cur = c
		}
	}
	fmt.Fprintf(os.Stderr, "配置文件：%s\n", path)

	// ① 对外地址
	newPublic := *publicURL
	if interactive {
		newPublic = promptInit("对外地址（域名或 域名:端口，下发安装命令用；留空跳过）", cur.PublicURL)
	}
	if newPublic != "" {
		newPublic = normPublicURL(newPublic)
		if err := validPublicURL(newPublic); err != nil {
			fmt.Fprintln(os.Stderr, "public_url 不对：", err)
			return 2
		}
	}

	// ② 自助注册（register_invite 用 Visit 区分"没给"和"显式清空"）
	newReg := cur.Register
	setReg := false
	switch {
	case *regYes:
		newReg, setReg = true, true
	case *regNo:
		newReg, setReg = false, true
	case interactive:
		newReg = promptInitYN("对外开放自助注册（用户装完 agent 跑 towstrap register 自己建号；不开则管理员建号）", cur.Register)
		setReg = true
	}
	var invite *string // nil=不动；否则写（含空串=清除）
	invSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "register-invite" {
			invSet = true
		}
	})
	if invSet {
		invite = regInvite
	} else if interactive && newReg {
		v := promptInit("注册邀请码（留空=任何人都能注册；填了则建号要带 --invite）", cur.RegisterInvite)
		if v != cur.RegisterInvite {
			invite = &v
		}
	}

	// ③ 第一个账号（可选）
	acct := *account
	var pw string
	if interactive {
		if promptInitYN("现在建一个账号（SSH 登录名 + 第一台机器的 token）", true) {
			for {
				acct = promptInit("账号名（字母数字 ._-）", "")
				if proto.ValidName(acct) {
					break
				}
				fmt.Fprintln(os.Stderr, "  名字不合法，重来")
			}
			var err error
			pw, err = promptInitPassword()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
		}
	} else if acct != "" {
		if !proto.ValidName(acct) {
			fmt.Fprintln(os.Stderr, "账号名不合法：", acct)
			return 2
		}
		if *pwStdin {
			pw = readInitLine()
		}
		if pw == "" {
			pw = accounts.RandomPassword()
			defer fmt.Printf("SSH 密码（只显示这一次，请保存）: %s\n", pw)
		}
	}

	// —— 写配置（Node 级改写，保住注释和无关字段）——
	changed := writeServerYAML(path, exists, newPublic, setReg, newReg, invite)
	if changed {
		fmt.Fprintf(os.Stderr, ">> 配置已写入 %s\n", path)
	} else {
		fmt.Fprintln(os.Stderr, ">> 配置没变化")
	}

	// 重新读最终配置拿 users_db / ssh 端口（扁平/嵌套都认）
	final := config.Server{SSH: ":7822"}
	if c, err := config.LoadServer(path); err == nil {
		final = c
		if final.SSH == "" {
			final.SSH = ":7822"
		}
	}
	db := *usersDB
	if db == "" {
		db = final.UsersDB
	}
	if db == "" {
		// yaml 没写 users_db：跟配置同目录放一个，别去摸 /etc 默认路径
		db = filepath.Join(filepath.Dir(path), "users.db")
	}

	// 建账号
	var token string
	if acct != "" {
		store, err := accounts.Open(db, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, "开账号库失败:", err)
			return 2
		}
		defer store.Close()
		a, err := store.Add(acct, pw, nil, "", nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "建号失败:", err)
			return 2
		}
		token = a.Machines[0].Token
		fmt.Printf(">> 账号已建：%s（机器 %s）\n", a.Username, a.Machines[0].ID())
	}

	// systemd 重启让新配置生效
	if !*noRestart {
		restartSvc()
	}

	// 收尾总结
	pub := newPublic
	if pub == "" {
		pub = cur.PublicURL
	}
	host := pub
	host = strings.TrimPrefix(host, "wss://")
	host = strings.TrimPrefix(host, "ws://")
	host = strings.SplitN(host, "/", 2)[0]
	if h, _, err := splitHostPort(host); err == nil {
		host = h
	}
	sshPort := final.SSH
	if _, p, err := splitHostPort(sshPort); err == nil {
		sshPort = p
	}
	httpAddr := final.HTTP
	if httpAddr == "" {
		httpAddr = ":7880"
	}
	fmt.Println()
	fmt.Println("—— 就绪 ——")
	fmt.Printf("配置文件：  %s\n", path)
	fmt.Printf("HTTP 监听： %s\n", httpAddr)
	fmt.Printf("SSH 监听：  %s\n", final.SSH)
	if host != "" {
		if acct != "" {
			fmt.Printf("SSH 登录：  ssh -p %s %s@%s\n", sshPort, acct, host)
		}
		fmt.Printf("落地页：    %s\n", strings.Replace(pub, "wss://", "https://", 1))
	} else {
		fmt.Printf("对外地址：  没填——安装命令里的地址要手工补 public_url 后再跑一遍 init\n")
	}
	if acct != "" && token != "" {
		fmt.Printf("这台机器的 agent token：%s\n", token)
	}
	if newReg {
		fmt.Println("被控机：    装完跑 towstrap register 自助建号（服务端记得开防火墙放 http/ssh 口）")
	} else {
		fmt.Println("被控机：    towstrap-server user add 名字 建号拿 token → install.sh --token")
	}
	return 0
}

// normPublicURL 把 "example.com"、"example.com:443" 规整成 wss:// 形式；
// 已是 ws(s):// 的原样返回。
func normPublicURL(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://") {
		return s
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return "wss://" + strings.TrimSuffix(s, "/")
}

// validPublicURL：public_url 必须是 ws(s)://host[:port] 形式。
func validPublicURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "wss" && u.Scheme != "ws") || u.Host == "" {
		return fmt.Errorf("要 ws(s)://主机[:端口] 形式，比如 wss://s.example.com:443")
	}
	return nil
}

// writeServerYAML 用 Node 级编辑写回 server.yaml：保注释、保字段顺序、
// 无关字段原样。publicURL 空=不动；invite nil=不动（空串=显式清除）。
// 返回是否真的改了。
func writeServerYAML(path string, exists bool, publicURL string, setReg bool, reg bool, invite *string) bool {
	var root yaml.Node
	if exists {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读配置失败:", err)
			return false
		}
		if err := yaml.Unmarshal(b, &root); err != nil {
			fmt.Fprintln(os.Stderr, "配置文件不是合法 YAML，没敢动：", err)
			return false
		}
	}
	if len(root.Content) == 0 {
		root = yaml.Node{Kind: yaml.DocumentNode}
		root.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		fmt.Fprintln(os.Stderr, "配置根节点不是 mapping，没敢动")
		return false
	}
	srv := yamlMapGet(doc, "server")
	if srv == nil {
		// 老文件可能是扁平写法（键直接铺顶层）：往它追加 server: 小节
		// 会让那些顶层键全部静默失效——LoadServer 只要见到 server:
		// 是 mapping 就只认它。扁平文件就把新键也写在顶层。
		if hasFlatServerKeys(doc) {
			srv = doc
			fmt.Fprintln(os.Stderr, ">> 配置是扁平写法（键在顶层），新键写到顶层——格式保持原样")
		} else {
			srv = &yaml.Node{Kind: yaml.MappingNode}
			doc.Content = append(doc.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: "server"}, srv)
		}
	}
	if srv.Kind != yaml.MappingNode {
		fmt.Fprintln(os.Stderr, "server: 不是 mapping，没敢动")
		return false
	}
	if srv != doc {
		// server: 小节存在但顶层还躺着扁平键——那些键已经不生效了，
		// 说一声免得运维以为 tls/allow_ips 还在起作用。
		for k := range flatServerKeys {
			if yamlMapGet(doc, k) != nil {
				fmt.Fprintf(os.Stderr, ">> 注意：顶层有扁平键（%s 等）被 server: 小节遮住不生效——建议挪进 server: 段\n", k)
				break
			}
		}
	}

	changed := false
	// 文件原本不存在时补最小骨架：http/ssh 监听 + users_db——不然写出的
	// yaml 只有 init 管的三个键，跑起来全靠内置默认值，行为不透明。
	if !exists {
		confDir := filepath.Dir(path)
		for _, kv := range [][2]string{
			{"http", "127.0.0.1:7880"},
			{"ssh", ":7822"},
			{"users_db", filepath.Join(confDir, "users.db")},
		} {
			if yamlMapGet(srv, kv[0]) == nil {
				yamlMapSet(srv, kv[0], &yaml.Node{Kind: yaml.ScalarNode, Value: kv[1]})
				changed = true
			}
		}
	}
	if publicURL != "" {
		if n := yamlMapGet(srv, "public_url"); n == nil || n.Value != publicURL {
			yamlMapSet(srv, "public_url", &yaml.Node{Kind: yaml.ScalarNode, Value: publicURL})
			changed = true
		}
	}
	if setReg {
		want := "false"
		if reg {
			want = "true"
		}
		if n := yamlMapGet(srv, "register"); n == nil || n.Value != want {
			yamlMapSet(srv, "register", &yaml.Node{Kind: yaml.ScalarNode, Value: want, Tag: "!!bool"})
			changed = true
		}
	}
	if invite != nil {
		if *invite == "" {
			// 显式清空：把键整个删掉，别留个 register_invite: 空标量
			if yamlMapGet(srv, "register_invite") != nil {
				yamlMapDel(srv, "register_invite")
				changed = true
			}
		} else if n := yamlMapGet(srv, "register_invite"); n == nil || n.Value != *invite {
			yamlMapSet(srv, "register_invite", &yaml.Node{Kind: yaml.ScalarNode, Value: *invite})
			changed = true
		}
	}
	if !changed {
		return false
	}
	b, err := yaml.Marshal(&root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置序列化失败:", err)
		return false
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "建配置目录失败:", err)
		return false
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "写配置失败:", err)
		return false
	}
	return true
}

// flatServerKeys 是服务端配置在扁平写法下会出现在顶层的键（只收服务端
// 专有的；audit_log/mirror_idle 这类和 agent 共用的不算——不然一份纯
// agent.yaml 会被当成扁平服务端配置）。
var flatServerKeys = map[string]bool{
	"http": true, "ssh": true, "host_key": true, "tls": true,
	"cert": true, "key": true, "users_db": true, "users_key": true,
	"admin_token": true, "public_url": true, "allow_ips": true,
	"idle_verify": true, "max_sessions": true, "max_conns": true,
	"max_conns_per_ip": true, "ssh_idle_timeout": true,
	"ssh_max_timeout": true, "min_agent_version": true,
	"agent_defaults": true, "register": true, "register_invite": true,
	"allow_plain_http": true, "mcp": true, "monitor": true, "oauth": true,
}

// hasFlatServerKeys 判断这份顶层 mapping 是否在用扁平写法写服务端配置。
func hasFlatServerKeys(doc *yaml.Node) bool {
	for k := range flatServerKeys {
		if yamlMapGet(doc, k) != nil {
			return true
		}
	}
	return false
}

func yamlMapGet(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// yamlMapSet 覆盖或追加 key——保留原节点的注释位置（yaml.v3 会带走
// 节点的 Head/Line/FootComment 绑定到值节点上）。
func yamlMapSet(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key}, val)
}

func yamlMapDel(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// restartSvc：systemd 单元在跑就重启让新配置生效。
func restartSvc() {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", "towstrap-server").Run(); err != nil {
		return // 没跑（或没装单元）——不打扰
	}
	if err := exec.Command("systemctl", "restart", "towstrap-server").Run(); err != nil {
		fmt.Fprintln(os.Stderr, ">> systemctl restart towstrap-server 失败:", err, "——手工重启一下生效")
		return
	}
	fmt.Fprintln(os.Stderr, ">> towstrap-server 服务已重启，新配置生效")
}

// —— 交互问答 ——

// readInitLine 逐字节读到换行——不用 fmt.Scanln（一行里多打的词会残留
// 喂给下一个问题），也不用 bufio.Reader（会把后面还没问的行提前吃掉，
// 包括 ReadPassword 要的密码行）。
func readInitLine() string {
	var sb strings.Builder
	var one [1]byte
	for {
		n, err := os.Stdin.Read(one[:])
		if n > 0 {
			if one[0] == '\n' {
				break
			}
			sb.WriteByte(one[0])
		}
		if err != nil {
			break
		}
	}
	return strings.TrimSpace(strings.TrimSuffix(sb.String(), "\r"))
}

func promptInit(label, def string) string {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]：", label, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s：", label)
	}
	if line := readInitLine(); line != "" {
		return line
	}
	return def
}

func promptInitYN(label string, def bool) bool {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	fmt.Fprintf(os.Stderr, "%s？[%s]：", label, hint)
	line := strings.ToLower(readInitLine())
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

func promptInitPassword() (string, error) {
	fmt.Fprint(os.Stderr, "账号密码（SSH 登录用，最少 10 位）：")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(p1) < 10 {
		return "", fmt.Errorf("密码最少 10 位")
	}
	fmt.Fprint(os.Stderr, "再输一遍：")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", fmt.Errorf("两次输入不一致")
	}
	return string(p1), nil
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", "", fmt.Errorf("没端口")
	}
	return s[:i], s[i+1:], nil
}
