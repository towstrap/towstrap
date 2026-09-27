package main

// towstrap ssh-key —— 在这台机器上自助管理账号的 SSH 登录公钥，不依赖 SSH：
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
  towstrap ssh-key <list|add|remove> [选项]

在这台机器上管理账号的 SSH 登录公钥（给自动化和免密登录用）：

  towstrap ssh-key list                          列已登记公钥（SHA256 指纹 + 注释）
  towstrap ssh-key add                            自动找 ~/.ssh/id_*.pub 登记
  towstrap ssh-key add "ssh-ed25519 AAAA… 备注"   登记这一行公钥
  towstrap ssh-key add --file ~/.ssh/other.pub    从文件读公钥登记
  towstrap ssh-key remove SHA256:xxxx             按指纹删一把
  towstrap ssh-key remove "ssh-ed25519 AAAA…"     按公钥行删一把

鉴权是本机 agent token + 账号密码（token 证明机器、密码证明本人），
已绑 TOTP 的账号再要当前 6 位动态码。登不进 SSH 也能用——这正是它
存在的意义：密码进来过一趟，把公钥挂上，以后就免密了。

  --server wss://..     服务器地址（默认读 agent.yaml，没有再回落官方）
  --password-stdin      密码从 stdin 读一行（脚本用）
  --totp 6位码          账号已绑 TOTP 时要带的当前动态码（脚本用；argv 会出现在本机进程列表里，介意就用 --totp-stdin）
  --totp-stdin          动态码从 stdin 读一行（不上命令行；配 --password-stdin 时排在密码行后）
  --agent-token/-file   token 来源（默认和 agent 同款优先级）
  --config 路径         agent.yaml 位置（默认各平台配置目录）
  --insecure            跳过 TLS 证书校验
  --allow-plain         服务器是明文 ws:// 且不在回环时必须加（密码不裸奔）
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
	// 动词是位置参数——先摘出来再 Parse，不然 "ssh-key add --password-stdin"
	// 这种写法里 add 后面的旗标会被 flag 包丢下不解析。只摘第一个动词，
	// 多写的动词/其他词留在 rest 里，Parse 后按需报错或当公钥参数。
	verb := ""
	var rest []string
	for _, a := range args {
		if verb == "" && (a == "list" || a == "add" || a == "remove") {
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

	// add/remove 先本地校验出公钥行，再进网络环节——明显坏的输入不用出门。
	var keyArg string
	if verb == "add" || verb == "remove" {
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
