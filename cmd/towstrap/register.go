package main

// towstrap register —— 首次接入入口：先问有没有账号。
// 有：登录（账号+密码），把这台机器挂到名下拿 token ——一个账号多台机器。
// 没有：自助建号（服务器开 register: 才受理），同时建第一台机器。
// 两条路都上报机器指纹（SHA256，不发原始硬件 ID）；一台机器的指纹只许
// 绑一个账号。成功后写 token 文件和最小 agent.yaml，可直接跑 agent。

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/towstrap/towstrap/internal/client"
	"github.com/towstrap/towstrap/internal/machineid"
	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/qrcode"
)

func usageRegister() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap register [选项]

首次接入这台机器。交互模式下会先问你有没有账号：

  没有 → 自助建号（服务器需开 register:，没开会提示找管理员）
  有   → 登录，把这台机器加到你账号下（一个账号可管多台机器）

成功后写好 token 文件和 agent.yaml——接着直接 towstrap 跑起来即可。

  --server wss://..     服务器地址（默认官方 %s）
  --login               跳过提问直接走"已有账号登录"分支（脚本里用）
  --account 名字        账号名（默认当前用户名；不给会交互问）
  --machine 名字        这台机器的名字（交互模式会问，回车取主机名；
                        登录分支里同名=重装换 token；脚本里不给就静默用主机名）
  --invite 码           服务器设了 register_invite 时必填（只建号分支用）
  --password-stdin      密码从 stdin 读一行（脚本用；交互模式自动问）
  --totp 6位码          账号已绑 TOTP 时登录加机要带的当前动态码
  --skip-totp           跳过最后的 TOTP 绑定提问（SSH 登录后 @totp 也能绑）
  --insecure            跳过 TLS 证书校验（自签证书用）
  --allow-plain         服务器是明文 ws:// 且不在回环时必须加（密码不裸奔）
`, proto.OfficialServer)
}

func runRegister(args []string) int {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	fs.Usage = usageRegister
	server := fs.String("server", proto.OfficialServer, "")
	login := fs.Bool("login", false, "")
	account := fs.String("account", "", "")
	machine := fs.String("machine", "", "")
	invite := fs.String("invite", "", "")
	pwStdin := fs.Bool("password-stdin", false, "")
	totpCode := fs.String("totp", "", "")
	skipTOTP := fs.Bool("skip-totp", false, "")
	insecure := fs.Bool("insecure", false, "")
	allowPlain := fs.Bool("allow-plain", false, "")
	_ = fs.Parse(args)

	// 明文出公网不行：ws:///http:// 非回环要显式确认（注册/登录都带密码）。
	if err := client.PlainCheck(*server, *allowPlain); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	base, err := oauthHTTPBase(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	interactive := term.IsTerminal(int(os.Stdin.Fd())) && !*pwStdin

	// 分支：--login 显式走登录；交互模式问一句；脚本模式默认建号。
	have := *login
	if interactive && !*login {
		have = promptYesNo("已有 towstrap 账号（这台机器要挂到它名下）", false)
	}

	acct := *account
	if acct == "" {
		def := ""
		if u, err := user.Current(); err == nil {
			def = proto.SanitizeName(u.Username)
		}
		acct = promptLine("账号名", def)
	}
	if !proto.ValidName(acct) {
		fmt.Fprintln(os.Stderr, "账号名不合法：只能用字母、数字、点、下划线和短横线")
		return 2
	}
	mach := *machine
	if mach == "" {
		def := ""
		if h, err := os.Hostname(); err == nil {
			def = proto.SanitizeName(h)
		}
		if interactive {
			// 机器名是 SSH 登录名、也是服务器机器列表里的显示名——别
			// 闷头用主机名，让人看过再定；回车即取默认。
			mach = promptLine("这台机器的名字", def)
		} else {
			mach = def
		}
	}
	if !proto.ValidName(mach) {
		fmt.Fprintln(os.Stderr, "机器名不合法：", mach)
		return 2
	}

	pw, err := readRegisterPassword(*pwStdin, have)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	fp := machineid.Fingerprint()
	if fp == "" {
		fmt.Fprintln(os.Stderr, "取不到机器指纹（需要较新版本/可写的配置目录）")
		return 1
	}

	endpoint := "/register"
	if have {
		endpoint = "/register/machine"
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	if *insecure {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	var res proto.RegisterResp
	var resp *http.Response
	for i := 0; i < 2; i++ {
		reqBody, _ := json.Marshal(proto.RegisterReq{
			Account: acct, Password: pw, Machine: mach,
			Fingerprint: fp, Invite: *invite, TOTP: *totpCode,
		})
		resp, err = hc.Post(base+endpoint, "application/json", bytes.NewReader(reqBody))
		if err != nil {
			fmt.Fprintln(os.Stderr, "连服务器失败:", err)
			return 1
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		res = proto.RegisterResp{}
		_ = json.Unmarshal(raw, &res)
		// 账号绑了 TOTP 但没带码：交互模式补问一次重发；脚本模式提示 --totp。
		if !(resp.StatusCode == http.StatusForbidden && res.NeedTOTP) {
			break
		}
		if *totpCode != "" {
			break // 带了码还拒 = 码不对，走统一失败出口
		}
		if interactive {
			fmt.Fprintf(os.Stderr, "账号 %s 已绑 TOTP\n", acct)
			*totpCode = promptLine("当前 6 位动态码", "")
			if *totpCode != "" {
				continue
			}
		}
		fmt.Fprintln(os.Stderr, "这个账号绑了 TOTP：加 --totp 带上当前 6 位动态码（或去掉 --password-stdin 走交互）")
		return 1
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusConflict:
		fmt.Fprintln(os.Stderr)
		if res.Owner != "" {
			fmt.Fprintf(os.Stderr, "这台机器已注册过（账号 %s）——用它的密码走 --login 登录即可；确实要换绑找管理员删账号释放指纹。\n", res.Owner)
		} else {
			fmt.Fprintln(os.Stderr, "冲突：", res.Err)
		}
		return 1
	default:
		fmt.Fprintf(os.Stderr, "失败（%d）：%s\n", resp.StatusCode, res.Err)
		return 1
	}

	// 落盘：token 文件 0600 + 最小 agent.yaml（已存在不动，怕覆盖调好的配置）。
	dir, err := machineid.ConfDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "找配置目录失败:", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "建配置目录失败:", err)
		return 1
	}
	tokenfile := filepath.Join(dir, "agent-token")
	if err := os.WriteFile(tokenfile, []byte(res.Token+"\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "写 token 失败:", err)
		return 1
	}
	agentyaml := filepath.Join(dir, "agent.yaml")
	if _, err := os.Stat(agentyaml); os.IsNotExist(err) {
		yaml := fmt.Sprintf("server: %s\nagent_token_file: %s\n", *server, tokenfile)
		if err := os.WriteFile(agentyaml, []byte(yaml), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "写 agent.yaml 失败:", err)
			return 1
		}
	} else {
		fmt.Fprintf(os.Stderr, "注意：%s 已存在没有动它——token 写在了 %s，如果已有配置指的是别的 token 文件，自己合并一下\n", agentyaml, tokenfile)
	}

	// SSH 提示的 host 从服务器地址推导（剥 scheme/port/path）。
	sshHost := strings.TrimPrefix(strings.TrimPrefix(*server, "wss://"), "ws://")
	sshHost = strings.SplitN(sshHost, "/", 2)[0]
	if h, _, err := net.SplitHostPort(sshHost); err == nil {
		sshHost = h
	}
	fmt.Println()
	if have {
		fmt.Printf(">> 登录成功：机器 %s 已挂到账号 %s 名下\n", res.Machine, res.Account)
	} else {
		fmt.Printf(">> 注册成功：账号 %s，机器 %s\n", res.Account, res.Machine)
	}
	fmt.Printf(">> token 写入 %s（0600），配置 %s\n", tokenfile, agentyaml)
	fmt.Println(">> 跑起来：towstrap --config", agentyaml)
	fmt.Println()
	fmt.Println("远程进这台机器（标准 SSH 直连）：")
	fmt.Printf("  ssh -p %s %s@%s\n", res.SSHPort, res.Machine, sshHost)

	// 向导最后一步：交互模式下主动问要不要绑 TOTP 二次验证。
	if interactive && !*skipTOTP {
		totpWizard(hc, base, res.Token, pw)
	} else if !interactive {
		fmt.Fprintln(os.Stderr, "提示：脚本模式跳过了 TOTP 绑定——之后想绑跑 towstrap totp（或 SSH 登录后 @totp）")
	}
	return 0
}

// totpPost 是自助管理端点（/totp/*、/passwd）共用的请求封装：JSON body +
// X-Agent-Token 头（token 反查账号，密码在 body 里）。
func totpPost(hc *http.Client, base, token, path string, body, out any) (int, bool) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(b))
	if err != nil {
		return 0, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", token)
	resp, err := hc.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "请求失败:", err)
		return 0, false
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	return resp.StatusCode, true
}

// totpWizard 向导里的 TOTP 绑定步：先问要不要绑，然后走共享流程。
// 失败不致命——打印原因就行，账号/机器本身已经注册成功。
func totpWizard(hc *http.Client, base, token, password string) {
	fmt.Println()
	if !promptYesNo("顺手给账号绑 TOTP 二次验证（SSH 登录输完密码还要个 6 位动态码，推荐）", true) {
		return
	}
	totpBindFlow(hc, base, token, password)
}

// totpBindFlow 是绑定主流程（register 向导和 towstrap totp 共用）：
// begin 拿秘钥出二维码（已绑账号在 begin 就先验旧码）→ 输新码
// confirm 落库。返回 false 表示没绑成；调用方自己决定致不致命。
func totpBindFlow(hc *http.Client, base, token, password string) bool {
	var beg proto.TOTPBeginResp
	oldCode := ""
	for {
		code, ok := totpPost(hc, base, token, "/totp/begin", proto.TOTPBeginReq{Password: password, OldCode: oldCode}, &beg)
		if !ok {
			return false
		}
		if code == http.StatusForbidden && beg.NeedCode && oldCode == "" {
			fmt.Fprintf(os.Stderr, "账号 %s 已绑过 TOTP——换绑会让旧验证器失效。\n", beg.Account)
			oldCode = promptLine("输当前验证器上的 6 位码验身份", "")
			if oldCode == "" {
				fmt.Fprintln(os.Stderr, "没输旧码，放弃换绑")
				return false
			}
			continue
		}
		if code != 200 {
			fmt.Fprintln(os.Stderr, "TOTP 绑定没成：", beg.Err)
			return false
		}
		break
	}
	fmt.Println("用验证器（Google Authenticator / 1Password / Aegis / 微软 Authenticator 都行）扫下面这个码：")
	if qr, err := qrcode.Terminal(beg.URI); err == nil {
		fmt.Print(qr)
	}
	fmt.Println(" ", beg.URI)
	fmt.Println("  手动录入秘钥:", beg.Secret)
	codeStr := promptLine("输新验证器上现在的 6 位码", "")
	var cf proto.TOTPConfirmResp
	code, ok := totpPost(hc, base, token, "/totp/confirm", proto.TOTPConfirmReq{
		Password: password, Secret: beg.Secret, Code: codeStr, OldCode: oldCode,
	}, &cf)
	if !ok {
		return false
	}
	if code != 200 || !cf.OK {
		fmt.Fprintln(os.Stderr, "TOTP 绑定没成：", cf.Err)
		return false
	}
	fmt.Println(">> TOTP 已绑定：之后 SSH 登录是 密码 + 6 位动态码 两道")
	return true
}

// promptLine 交互读一行（带默认值回车即取）。
func promptLine(label, def string) string {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]：", label, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s：", label)
	}
	var line string
	fmt.Scanln(&line)
	if strings.TrimSpace(line) == "" {
		return def
	}
	return strings.TrimSpace(line)
}

// promptYesNo 交互问一个是/否题，回车取默认值。
func promptYesNo(label string, def bool) bool {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	fmt.Fprintf(os.Stderr, "%s？[%s]：", label, hint)
	var line string
	fmt.Scanln(&line)
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

// readRegisterPassword：--password-stdin 时从 stdin 读一行；否则终端交互。
// login 分支密码只问一次；建号分支问两次确认、最少 10 位（服务端规则）。
func readRegisterPassword(fromStdin, login bool) (string, error) {
	if fromStdin {
		var pw string
		fmt.Scanln(&pw)
		if pw == "" {
			return "", fmt.Errorf("stdin 里没读到密码")
		}
		return pw, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("非终端环境：加 --password-stdin 从 stdin 喂密码")
	}
	if login {
		fmt.Fprint(os.Stderr, "密码：")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if len(pw) == 0 {
			return "", fmt.Errorf("密码不能为空")
		}
		return string(pw), nil
	}
	fmt.Fprint(os.Stderr, "设密码（SSH 登录这台机器用，最少 10 位）：")
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
