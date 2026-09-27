package main

// towstrap ssh-key —— 在这台机器上自助管理账号的 SSH 登录公钥，不依赖 SSH：
//   towstrap ssh-key gen [--add] [--file 私钥路径] 生成 ed25519 密钥对并打印
//                                            私钥；--add 时顺带把公钥挂到账号
//   towstrap ssh-key list                    列已登记的公钥（指纹 + 注释）
//   towstrap ssh-key add [公钥行|--file 文件]  登记一把公钥；不带参数时自动找
//                                            ~/.ssh/id_*.pub
//   towstrap ssh-key remove <指纹|公钥行>      删一把
// 鉴权用本机 agent token + 账号密码（POST /sshkey，和 passwd 同一条链），
// 已绑 TOTP 的账号再要一道当前动态码。公钥就是第二把登录钥匙——加一把
// 等于多开一扇门，所以和密码同级看护。
//
// 接力场景：人先密码登进 SSH 会话，在里面跑 @sshkey add 把手机公钥挂上，
// 之后手机直接 ssh -i 进来。两边（本命令和 @sshkey）效果一样。

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/towstrap/towstrap/internal/proto"
)

func usageSSHKey() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap ssh-key <gen|list|add|remove> [选项]

在这台机器上自助管理账号的 SSH 登录公钥——给免密登录和设备接力用：
账号下登记的每把公钥都是一扇门，ssh -i 进来不要密码、不要 TOTP。

动词（除 gen 单独用以外，都要 agent token + 账号密码 + TOTP 已绑要动态码）：

  gen     本机生成 ed25519 密钥对，写盘后把私钥内容打印出来
          ——新设备接力专用：私钥粘进手机/平板的 SSH 软件即可。
          纯本地操作，不碰网络不要密码；加 --add 才登记公钥。

  list    列账号已登记的公钥：SHA256 指纹 + 注释 + 完整公钥行。
          想分清「这把钥匙是哪台设备的」靠注释（add/gen 用 --comment 挂）。

  add     给账号登记一把公钥，三种给法：
            不带参数       自动找 ~/.ssh/id_ed25519.pub → id_ecdsa → id_rsa
            公钥行         "ssh-ed25519 AAAA… 备注"（行尾注释会存下来）
            --file 文件    从文件读（取第一行有效公钥）

  remove  删一把：给 list 里看到的 SHA256:指纹，或贴完整公钥行。

旗标：

  --file 路径           gen：私钥写哪里（公钥自动加 .pub，默认 ~/.ssh/id_ed25519；
                        已存在的私钥不覆盖——想再生成换个名字）
                        add：从哪个文件读公钥
  --comment 备注        add/gen：给公钥挂说明（list 时显示；gen 默认
                        towstrap-gen@主机名）
  --add                 gen：生成后直接把公钥登记到账号（会问密码/TOTP）
  --server wss://..     服务器地址（默认读 agent.yaml，没有再回落官方）
  --password-stdin      密码从 stdin 读一行（脚本用）
  --totp 6位码          账号已绑 TOTP 时要带的当前动态码（脚本用；argv 会
                        出现在本机进程列表里，介意就用 --totp-stdin）
  --totp-stdin          动态码从 stdin 读一行（不上命令行；配
                        --password-stdin 时排在密码行后）
  --agent-token/-file   token 来源（默认和 agent 同款优先级）
  --config 路径         agent.yaml 位置（默认各平台配置目录）
  --insecure            跳过 TLS 证书校验
  --allow-plain         服务器是明文 ws:// 且不在回环时必须加（密码不裸奔）

典型场景：

  手机接力（最常用）：
    towstrap ssh-key gen --add --comment "手机"
    → 私钥打印在屏幕上，粘贴进手机 SSH 软件
    → 手机 ssh -i <私钥> 账号+机器@服务器 -p 7822 直接进

  换设备/新钥匙：
    ssh-keygen -t ed25519            # 或 towstrap ssh-key gen
    towstrap ssh-key add --comment "新笔记本"

  设备丢了：
    towstrap ssh-key list            # 找到丢的那台的指纹
    towstrap ssh-key remove SHA256:xxxx

注意：
  - gen 打印的私钥会留在终端回滚缓冲里，用完建议清屏/清 scrollback
  - 已登记的公钥改注释：remove 旧行再 add 带新 --comment 的同一行
  - 人已在 SSH 会话里的话，@sshkey list/add/remove 效果一样
`)
}

// defaultPubKey 自动找用户的默认公钥：ed25519 → ecdsa → rsa → dsa 顺序，
// 第一个存在的就用。
func defaultPubKey() (path, line string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", ""
	}
	for _, name := range []string{"id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub", "id_dsa.pub"} {
		p := filepath.Join(home, ".ssh", name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// .pub 文件正常只有一行；取第一个非空非注释行，容忍结尾空白。
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				return p, l
			}
		}
	}
	return "", ""
}

// genKeyPair 生成 ed25519 密钥对写盘：私钥 0600、.pub 0644，父目录 0700。
// 目标已存在时拒写——私钥覆盖找不回来，宁可让用户用 --file 换个名字。
// 私钥不带密码短语：gen 的主要用途就是生成完直接导进手机/其他 SSH 软件，
// 带短语的格式很多客户端导不进去；要短语的自己用 ssh-keygen -p 加。
func genKeyPair(privPath, comment string) (path, pubLine, privPEM string, err error) {
	if privPath == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", "", "", fmt.Errorf("找不着用户目录: %v", herr)
		}
		privPath = filepath.Join(home, ".ssh", "id_ed25519")
	}
	if _, serr := os.Stat(privPath); serr == nil {
		return "", "", "", fmt.Errorf("%s 已存在——不覆盖现有私钥；要再来一把用 --file 换个名字", privPath)
	}
	pub, priv, gerr := ed25519.GenerateKey(rand.Reader)
	if gerr != nil {
		return "", "", "", fmt.Errorf("生成密钥失败: %v", gerr)
	}
	if comment == "" {
		host, _ := os.Hostname()
		comment = "towstrap-gen@" + host
	}
	spub, serr := gossh.NewPublicKey(pub)
	if serr != nil {
		return "", "", "", fmt.Errorf("编码公钥失败: %v", serr)
	}
	pubLine = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(spub))) + " " + comment
	block, merr := gossh.MarshalPrivateKey(priv, comment)
	if merr != nil {
		return "", "", "", fmt.Errorf("编码私钥失败: %v", merr)
	}
	privPEM = string(pem.EncodeToMemory(block))
	if derr := os.MkdirAll(filepath.Dir(privPath), 0700); derr != nil {
		return "", "", "", fmt.Errorf("建目录失败: %v", derr)
	}
	if werr := os.WriteFile(privPath, []byte(privPEM), 0600); werr != nil {
		return "", "", "", fmt.Errorf("写私钥失败: %v", werr)
	}
	if werr := os.WriteFile(privPath+".pub", []byte(pubLine+"\n"), 0644); werr != nil {
		return "", "", "", fmt.Errorf("写公钥失败: %v", werr)
	}
	return privPath, pubLine, privPEM, nil
}

// applyKeyComment 给公钥行换/补行尾注释（list 时显示的就是它，方便分清
// 哪台设备在用这把钥匙）。用解析后的 key 重排，旧的注释/选项段都被规整掉；
// 解析不动的行原样回，交给后面的校验报错。
func applyKeyComment(line, comment string) string {
	pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return line
	}
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pk))) + " " + comment
}

// parsePosInterleaved 解析「旗标和位置参数可交错」的命令行（标准库 flag
// 遇到第一个非 flag 参数就停），返回位置参数。公钥行跟在动词后面，用户
// 把旗标写在后面是常态，不交错解析会被静默丢掉。
func parsePosInterleaved(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for len(args) > 0 {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	return pos
}

// resolveAddKey 确定 add 要登记的公钥行：--file > 位置参数 > 默认文件。
// 返回的 line 是 authorized_keys 格式一行；err 非空时直接给用户看。
func resolveAddKey(file string, pos []string) (line string, err error) {
	switch {
	case file != "":
		b, rerr := os.ReadFile(file)
		if rerr != nil {
			return "", fmt.Errorf("读公钥文件失败: %v", rerr)
		}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				return l, nil
			}
		}
		return "", fmt.Errorf("%s 里没有公钥行", file)
	case len(pos) > 0:
		return strings.Join(pos, " "), nil
	default:
		p, l := defaultPubKey()
		if l == "" {
			return "", fmt.Errorf("没带公钥也没找到 ~/.ssh/id_*.pub——把要登记的公钥行跟在 add 后面，或用 --file 指定文件")
		}
		fmt.Fprintf(os.Stderr, "用默认公钥 %s\n", p)
		return l, nil
	}
}

func runSSHKey(args []string) int {
	fs := flag.NewFlagSet("ssh-key", flag.ExitOnError)
	fs.Usage = usageSSHKey
	cf := addCredFlags(fs)
	pwStdin := fs.Bool("password-stdin", false, "")
	totpCode := fs.String("totp", "", "")
	totpStdin := fs.Bool("totp-stdin", false, "")
	keyFile := fs.String("file", "", "")
	keyComment := fs.String("comment", "", "")
	genAdd := fs.Bool("add", false, "")
	// 动词是位置参数——先摘出来再 Parse，不然 "ssh-key add --password-stdin"
	// 这种写法里 add 后面的旗标会被 flag 包丢下不解析。只摘第一个动词，
	// 多写的动词/其他词留在 rest 里，Parse 后按需报错或当公钥参数。
	verb := ""
	var rest []string
	for _, a := range args {
		if verb == "" && (a == "list" || a == "add" || a == "remove" || a == "gen") {
			verb = a
			continue
		}
		rest = append(rest, a)
	}
	pos := parsePosInterleaved(fs, rest)
	if verb == "" {
		usageSSHKey()
		return 2
	}
	if (verb == "list" && len(pos) > 0) || (verb == "remove" && len(pos) == 0) {
		fmt.Fprintf(os.Stderr, "ssh-key %s 的参数不对——%s\n", verb, map[string]string{
			"list":   "list 不带参数",
			"remove": "remove 要一个指纹或公钥行",
		}[verb])
		return 2
	}

	// gen 纯本地：生成密钥对写盘 + 打印私钥，不碰网络。加 --add 才转 add
	// 走下面的网络流程把公钥挂上账号（密码/TOTP 照常问）。
	var keyArg string
	if verb == "gen" {
		if len(pos) > 0 {
			fmt.Fprintln(os.Stderr, "ssh-key gen 不带位置参数——换路径用 --file")
			return 2
		}
		privPath, pubLine, privPEM, gerr := genKeyPair(*keyFile, *keyComment)
		if gerr != nil {
			fmt.Fprintln(os.Stderr, gerr)
			return 2
		}
		fmt.Printf(">> 已生成密钥对：\n  私钥: %s\n  公钥: %s.pub\n\n", privPath, privPath)
		if pk, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(pubLine)); perr == nil {
			fmt.Printf("指纹: %s\n\n", gossh.FingerprintSHA256(pk))
		}
		fmt.Println("----- 私钥内容（粘贴进手机/其他 SSH 软件；用完记得清屏）-----")
		fmt.Print(privPEM)
		fmt.Println("----- 私钥结束 -----")
		if !*genAdd {
			fmt.Printf("\n把它登记到账号：towstrap ssh-key add --file %s.pub\n", privPath)
			return 0
		}
		fmt.Println()
		keyArg, verb = pubLine, "add"
	}
	// add/remove 先本地校验出公钥行，再进网络环节——明显坏的输入不用出门。
	if (verb == "add" && keyArg == "") || verb == "remove" {
		var err error
		keyArg = strings.Join(pos, " ")
		if verb == "add" {
			keyArg, err = resolveAddKey(*keyFile, pos)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		keyArg = strings.TrimSpace(keyArg)
		if verb == "add" {
			// add 的输入必须是能解析的公钥行，本地先验一遍再发。
			if _, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(keyArg)); perr != nil {
				fmt.Fprintln(os.Stderr, "不是有效的 SSH 公钥行:", perr)
				return 2
			}
		}
	}
	// --comment 给登记的公钥挂/换行尾注释：ssh-key list 时就显示它，
	// 一眼看出这把钥匙是哪台设备。（gen --add 已在生成时写过注释，
	// 这里再套同值是幂等的。）
	if verb == "add" && *keyComment != "" {
		keyArg = applyKeyComment(keyArg, *keyComment)
	}

	env, err := loadAgentCLI(fs, cf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	pw, err := readRegisterPassword(*pwStdin, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	resolveTOTPStdin(sharedStdin(), totpCode, *totpStdin)

	post := func(code string) (int, proto.SSHKeyResp, bool) {
		var res proto.SSHKeyResp
		httpCode, ok := totpPost(env.hc, env.base, env.tok, "/sshkey", proto.SSHKeyReq{
			Password: pw, Code: code, Action: verb, Key: keyArg,
		}, &res)
		return httpCode, res, ok
	}

	code, res, ok := post(*totpCode)
	if !ok {
		return 1
	}
	// 已绑 TOTP 没带码：补问一次重发（--totp 给了但还拒 = 码不对，落到统一失败出口）。
	if code == http.StatusForbidden && res.NeedCode && *totpCode == "" {
		fmt.Fprintln(os.Stderr, "这个账号绑了 TOTP")
		*totpCode = promptLine("当前 6 位动态码", "")
		if *totpCode == "" {
			fmt.Fprintln(os.Stderr, "没给动态码，没执行")
			return 1
		}
		code, res, ok = post(*totpCode)
		if !ok {
			return 1
		}
	}
	if code != 200 || !res.OK {
		fmt.Fprintf(os.Stderr, "公钥%s没成（%d）：%s\n", verb, code, res.Err)
		return 1
	}

	switch verb {
	case "list":
		if len(res.Keys) == 0 {
			fmt.Println("这个账号还没登记公钥——ssh-key add 登记一把")
			return 0
		}
		for _, k := range res.Keys {
			fp := k.Fingerprint
			if fp == "" {
				fp = "（解析不了）"
			}
			if k.Comment != "" {
				fmt.Printf("%s  %s\n", fp, k.Comment)
			} else {
				fmt.Println(fp)
			}
			fmt.Printf("    %s\n", k.Line)
		}
		fmt.Println("\n删除：towstrap ssh-key remove <SHA256:指纹>")
	case "add":
		fmt.Println(">> 公钥已登记：之后拿对应私钥 ssh -i 就能登录（不用密码、不要 TOTP）")
	case "remove":
		fmt.Println(">> 公钥已删除")
	}
	return 0
}
