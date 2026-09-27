package main

// towstrap passwd —— 在这台机器上自助改账号的 SSH/登录密码，不依赖 SSH：
// 本机 agent token 证明这台机器已登记 + 旧密码证明本人，已绑 TOTP 的账号
// 再要一道当前动态码（POST /passwd）。改完全账号生效——所有机器的 SSH
// 登录都用新密码；忘了旧密码找管理员重置（user set 用户名 --password）。

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/towstrap/towstrap/internal/proto"
)

func usagePasswd() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap passwd [选项]

在这台机器上改账号的 SSH/登录密码：会问旧密码一遍、新密码两遍
（最少 10 位）；账号绑了 TOTP 的话再要一个当前 6 位动态码。
改完全账号生效——名下所有机器的 SSH 登录都换新密码。

鉴权是本机 agent token + 旧密码（token 证明机器、旧密码证明本人），
所以忘旧密码的找回不在这——找管理员跑
towstrap-server user set 用户名 --password 新密码。

  --server wss://..     服务器地址（默认读 agent.yaml，没有再回落官方）
  --password-stdin      密码从 stdin 读两行：第一行旧密码，第二行新密码
  --totp 6位码          账号已绑 TOTP 时要带的当前动态码（脚本用）
  --agent-token/-file   token 来源（默认和 agent 同款优先级）
  --config 路径         agent.yaml 位置（默认各平台配置目录）
  --insecure            跳过 TLS 证书校验
  --allow-plain         服务器是明文 ws:// 且不在回环时必须加（密码不裸奔）
`)
}

func runPasswd(args []string) int {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	fs.Usage = usagePasswd
	cf := addCredFlags(fs)
	pwStdin := fs.Bool("password-stdin", false, "")
	totpCode := fs.String("totp", "", "")
	_ = fs.Parse(args)

	env, err := loadAgentCLI(fs, cf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	oldPW, newPW, err := readPasswdPair(*pwStdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	var res proto.PasswdResp
	code, ok := totpPost(env.hc, env.base, env.tok, "/passwd", proto.PasswdReq{
		Password: oldPW, NewPassword: newPW, Code: *totpCode,
	}, &res)
	if !ok {
		return 1
	}
	// 已绑 TOTP 没带码：补问一次重发（--totp 给了但还拒 = 码不对，落到统一失败出口）。
	if code == http.StatusForbidden && res.NeedCode && *totpCode == "" {
		fmt.Fprintln(os.Stderr, "这个账号绑了 TOTP")
		*totpCode = promptLine("当前 6 位动态码", "")
		if *totpCode == "" {
			fmt.Fprintln(os.Stderr, "没给动态码，没改成")
			return 1
		}
		res = proto.PasswdResp{}
		code, ok = totpPost(env.hc, env.base, env.tok, "/passwd", proto.PasswdReq{
			Password: oldPW, NewPassword: newPW, Code: *totpCode,
		}, &res)
		if !ok {
			return 1
		}
	}
	if code != 200 || !res.OK {
		fmt.Fprintf(os.Stderr, "改密码没成（%d）：%s\n", code, res.Err)
		return 1
	}
	fmt.Println(">> 密码已改：之后 SSH 登录用这个账号名下所有机器都用新密码")
	return 0
}

// readPasswdPair 取（旧密码, 新密码）：stdin 模式读两行（旧、新），
// 终端模式旧密码问一遍、新密码两遍确认。
func readPasswdPair(fromStdin bool) (string, string, error) {
	if fromStdin {
		rd := bufio.NewReader(os.Stdin)
		oldPW, err := rd.ReadString('\n')
		if err != nil && len(oldPW) == 0 {
			return "", "", fmt.Errorf("stdin 里没读到密码（要两行：旧密码、新密码）")
		}
		newPW, err := rd.ReadString('\n')
		if err != nil && len(newPW) == 0 {
			return "", "", fmt.Errorf("stdin 里没读到新密码（要两行：旧密码、新密码）")
		}
		oldPW, newPW = strings.TrimSpace(oldPW), strings.TrimSpace(newPW)
		if oldPW == "" || newPW == "" {
			return "", "", fmt.Errorf("旧密码和新密码都不能空（stdin 两行：旧、新）")
		}
		if len(newPW) < 10 {
			return "", "", fmt.Errorf("新密码最少 10 位")
		}
		return oldPW, newPW, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", "", fmt.Errorf("非终端环境：加 --password-stdin 从 stdin 喂两行密码")
	}
	fmt.Fprint(os.Stderr, "旧密码：")
	oldB, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", "", err
	}
	if len(oldB) == 0 {
		return "", "", fmt.Errorf("旧密码不能为空")
	}
	fmt.Fprint(os.Stderr, "新密码（最少 10 位）：")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", "", err
	}
	if len(p1) < 10 {
		return "", "", fmt.Errorf("新密码最少 10 位")
	}
	fmt.Fprint(os.Stderr, "再输一遍新密码：")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", "", err
	}
	if string(p1) != string(p2) {
		return "", "", fmt.Errorf("两次输入不一致")
	}
	return string(oldB), string(p1), nil
}
