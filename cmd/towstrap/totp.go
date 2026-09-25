package main

// towstrap totp —— 事后管理账号的 TOTP 二因素，不依赖 SSH：
//   towstrap totp         绑定/换绑（出二维码，输新码确认；已绑先要旧码）
//   towstrap totp remove  解绑
// 用本机 agent token + 账号密码鉴权（和 token refresh 同款）——所以
// SSH 登进机器后直接敲这个就行；不在机器上的话走 ssh '@totp'。

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/machineid"
	"github.com/towstrap/towstrap/internal/proto"
)

func usageTOTP() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap totp [remove] [选项]

在这台机器上管理账号的 TOTP 二因素验证：

  towstrap totp         绑定/换绑——出二维码扫进验证器，输 6 位码确认；
                        已绑过的要先输当前动态码验身份（换绑使旧验证器失效）
  towstrap totp remove  解绑——已绑的要当前动态码；丢了验证器找管理员跑
                        towstrap-server user totp 用户名 --remove

鉴权用本机 agent token + 账号密码（token 证明机器、密码证明本人），
所以登不进 SSH 时没法用它找回——那条路是 ssh '@totp' / '@totp remove'。

  --server wss://..     服务器地址（默认读 agent.yaml，没有再回落官方）
  --password-stdin      密码从 stdin 读一行（脚本用）
  --agent-token/-file   token 来源（默认和 agent 同款优先级）
  --config 路径         agent.yaml 位置（默认各平台配置目录）
  --insecure            跳过 TLS 证书校验
  --allow-plain         服务器是明文 ws:// 且不在回环时必须加
`)
}

func runTOTP(args []string) int {
	fs := flag.NewFlagSet("totp", flag.ExitOnError)
	fs.Usage = usageTOTP
	configPath := fs.String("config", "", "")
	server := fs.String("server", "", "")
	agentToken := fs.String("agent-token", "", "")
	tokenFile := fs.String("agent-token-file", "", "")
	pwStdin := fs.Bool("password-stdin", false, "")
	insecure := fs.Bool("insecure", false, "")
	allowPlain := fs.Bool("allow-plain", false, "")
	// remove 是位置参数——先摘出来再 Parse，不然 "totp remove --password-stdin"
	// 这种写法里 remove 后面的旗标会被 flag 包丢下不解析。
	remove := false
	var rest []string
	for _, a := range args {
		if a == "remove" {
			remove = true
			continue
		}
		rest = append(rest, a)
	}
	_ = fs.Parse(rest)

	var file config.Agent
	// 没带 --config 时自动试默认配置目录的 agent.yaml——register 装好的
	// 机器上敲 towstrap totp 应该零旗标直接能用。
	path := *configPath
	if path == "" {
		if dir, err := machineid.ConfDir(); err == nil {
			cand := filepath.Join(dir, "agent.yaml")
			if _, err := os.Stat(cand); err == nil {
				path = cand
			}
		}
	}
	if path != "" {
		var err error
		file, err = config.LoadAgent(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	cfg := config.MergeAgent(file, visited(fs))
	srv := cfg.Server
	if *server != "" {
		srv = *server
	}
	if srv == "" {
		srv = proto.OfficialServer
	}
	// 密码会走这个地址出去——明文出公网必须显式确认。
	if strings.HasPrefix(srv, "ws://") && !*allowPlain {
		host := strings.TrimPrefix(srv, "ws://")
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			fmt.Fprintln(os.Stderr, "服务器地址是明文 ws:// 且不在回环：加 --allow-plain 才继续（密码会被明文传输）")
			return 2
		}
	}
	base, err := oauthHTTPBase(srv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	tok, _, _, err := resolveAgentToken(*agentToken, *tokenFile, os.Getenv("TOWSTRAP_AGENT_TOKEN"), cfg.AgentToken, cfg.AgentTokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读 agent token 失败（先在机器上 towstrap register 或用 --agent-token-file 指）：", err)
		return 2
	}
	pw, err := readRegisterPassword(*pwStdin, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	if *insecure {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	if !remove {
		if !totpBindFlow(hc, base, tok, pw) {
			return 1
		}
		return 0
	}
	// 解绑：已绑账号服务器会回 need_code，补问动态码再发一次。
	var rm proto.TOTPRemoveResp
	code, ok := totpPost(hc, base, tok, "/totp/remove", proto.TOTPRemoveReq{Password: pw}, &rm)
	if !ok {
		return 1
	}
	if code == http.StatusForbidden && rm.NeedCode {
		rm = proto.TOTPRemoveResp{}
		codeStr := promptLine("输当前验证器上的 6 位码", "")
		code, ok = totpPost(hc, base, tok, "/totp/remove", proto.TOTPRemoveReq{Password: pw, Code: codeStr}, &rm)
		if !ok {
			return 1
		}
	}
	if code != 200 || !rm.OK {
		fmt.Fprintln(os.Stderr, "解绑没成：", rm.Err)
		return 1
	}
	fmt.Println(">> TOTP 已解绑——之后 SSH 登录只要密码。SSH 面薄了，建议尽快绑回来")
	return 0
}
