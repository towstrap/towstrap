package main

// towstrap oauth：替机器前的用户向服务器要一条 OIDC 授权链接，
// 打印出来等人去浏览器完成外部身份校验；轮询取回结果——成功时拿到
// 一个短时效的 SSH 登录凭据（tso-...）和登录名。

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
)

func usageOAuth() {
	fmt.Fprintf(os.Stderr, `用法:
  towstrap oauth [--wait 5m] [选项]

向服务器要一条 OIDC 授权链接并打印出来；机器前的用户用浏览器打开、完成
外部身份校验后，这里会拿到一个短时效的 SSH 登录凭据（默认等 5 分钟）。
服务器没配 oauth: 时本命令不可用。

  --wait 5m          等授权结果的最长时间
  --allow-plain      服务器是明文 ws:// 且不在本机回环时必须加（token 不能裸奔）
  其余 --config/--server/--agent-token/--agent-token-file/--insecure 同主命令
`)
}

func runOAuth(args []string) int {
	fs := flag.NewFlagSet("agent oauth", flag.ExitOnError)
	cf := addCredFlags(fs)
	wait := fs.Duration("wait", 5*time.Minute, "")
	_ = fs.Parse(args)

	env, err := loadAgentCLI(fs, cf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	req, err := http.NewRequest(http.MethodPost, env.base+"/oauth/request", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	req.Header.Set("X-Agent-Token", env.tok)
	resp, err := env.hc.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "连服务器失败:", err)
		return 1
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		fmt.Fprintln(os.Stderr, "服务器没开 OAuth（server.yaml 需要 oauth: 小节）")
		return 1
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "服务器拒绝了请求（%d）: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}
	var start struct {
		RequestID string `json:"request_id"`
		URL       string `json:"url"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &start); err != nil || start.URL == "" {
		fmt.Fprintln(os.Stderr, "服务器响应无法解析:", strings.TrimSpace(string(body)))
		return 1
	}
	fmt.Println("请在浏览器里打开下面的链接完成授权（链接", start.ExpiresIn, "秒内有效）：")
	fmt.Println()
	fmt.Println("   ", start.URL)
	fmt.Println()
	fmt.Println("正在等待授权结果…")

	// 轮询授权结果：首次立即探，之后每 2 秒一轮；Ctrl+C 随时退出（请求
	// 本身也挂同一个 ctx，不会卡在 15s 超时里），到 deadline 就停，
	// 不会越过界再多睡一轮。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	deadline := time.Now().Add(*wait)
	poll := time.NewTimer(0)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "已取消")
			return 1
		case <-poll.C:
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "等待授权超时（--wait 可调）")
			return 1
		}
		poll.Reset(2 * time.Second)

		r, err := http.NewRequestWithContext(ctx, http.MethodGet,
			env.base+"/oauth/result?r="+start.RequestID, nil)
		if err != nil {
			continue
		}
		r.Header.Set("X-Agent-Token", env.tok)
		resp, err := env.hc.Do(r)
		if err != nil {
			continue // 网络抖一下不算完，继续等到超时
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var res struct {
			Status   string `json:"status"`
			Reason   string `json:"reason"`
			Machine  string `json:"machine"`
			Password string `json:"password"`
			SSHAddr  string `json:"ssh_addr"`
			ExpireIn int    `json:"expire_in"`
			Uses     int    `json:"uses"`
		}
		if json.Unmarshal(raw, &res) != nil {
			continue
		}
		switch res.Status {
		case "pending", "":
			continue
		case "approved":
			fmt.Println()
			fmt.Println("授权成功，以下凭据有效期", res.ExpireIn/60, "分钟，可用", res.Uses, "次：")
			fmt.Println()
			fmt.Println("   SSH 登录名:", res.Machine, "（"+strings.Replace(res.Machine, "+", "/", 1)+" 写法同样有效）")
			fmt.Println("   SSH 密码:  ", res.Password)
			fmt.Println("   SSH 地址:  ", res.SSHAddr)
			fmt.Println()
			return 0
		case "failed":
			fmt.Fprintln(os.Stderr, "授权失败:", res.Reason)
			return 1
		default: // unknown / expired
			fmt.Fprintln(os.Stderr, "授权请求已失效，请重新发起")
			return 1
		}
	}
}
