package client

// token 换发的 agent 侧客户端：POST /token/refresh。鉴权 = 本机 agent
// token + 账号密码 + TOTP；服务器把新 token 经各目标机器现有的
// WebSocket 连接下推写进各自的 token 文件。

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/term"
)

// RefreshOpts 是一次换发请求的参数。
type RefreshOpts struct {
	Server     string   // ws(s):// 服务器地址（同 agent --server）
	Token      string   // 本机 agent token（X-Agent-Token）
	Insecure   bool     // 跳过 TLS 证书校验
	Machines   []string // 要换的机器名（不带账号前缀）；空且 !All 只换本机
	All        bool     // 换账号下全部机器
	AllowPlain bool     // 明文 ws:// + 非回环时仍要发密码必须显式开
}

// RefreshResult 是服务器对每台机器的回执。
type RefreshResult struct {
	Machine string `json:"machine"`
	Status  string `json:"status"` // ok / offline / no-file / timeout / not-found / error
	Detail  string `json:"detail"`
}

// RefreshURL 把 agent 连服务器用的 ws(s):// 地址换成 /token/refresh 的
// http(s):// 地址；别的 scheme 报错。
func RefreshURL(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	case "https", "http":
	default:
		return "", fmt.Errorf("server 应为 ws:// 或 wss://")
	}
	// 路径当前缀拼接（同 client.go 的 /agent）：子路径部署也能指对端点。
	u.Path = path.Join(u.Path, "/token/refresh")
	u.RawQuery = ""
	return u.String(), nil
}

// PlainCheck 明文 ws:// 且目标不是本机回环时必须显式 AllowPlain——
// 账号密码会走这条连接，不能裸奔出本机。
func PlainCheck(server string, allowPlain bool) error {
	if allowPlain {
		return nil
	}
	u, err := url.Parse(server)
	if err != nil {
		return err
	}
	if u.Scheme != "ws" {
		return nil
	}
	host := u.Hostname()
	if host == "" || host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("密码不能走明文 ws://，请用 wss:// 或确认内网后加 --allow-plain")
}

// secretReader 读密码/验证码：终端不回显，否则按行读；两次读共享一个
// bufio，不吞掉后面的输入。
type secretReader struct {
	in     io.Reader
	br     *bufio.Reader
	termFd int
}

func newSecretReader(in io.Reader) *secretReader {
	r := &secretReader{in: in, termFd: -1}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		r.termFd = int(f.Fd())
	}
	return r
}

func (r *secretReader) line(out io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(out, prompt)
	if r.termFd >= 0 {
		b, err := term.ReadPassword(r.termFd)
		_, _ = fmt.Fprintln(out)
		return string(b), err
	}
	if r.br == nil {
		r.br = bufio.NewReader(r.in)
	}
	line, err := r.br.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// TokenRefresh 是换发的核心流程：校验明文限制 → 问密码/TOTP → POST
// /token/refresh → 逐台打印结果。返回进程退出码：全 ok 0，部分失败 1，
// 参数/鉴权错误 2。in 用 strings.NewReader("密码\n验证码\n") 可无交互调用。
func TokenRefresh(opts RefreshOpts, in io.Reader, out io.Writer) int {
	if err := PlainCheck(opts.Server, opts.AllowPlain); err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 2
	}
	endpoint, err := RefreshURL(opts.Server)
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 2
	}
	r := newSecretReader(in)
	pw, err := r.line(out, "账号密码: ")
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 2
	}
	code, err := r.line(out, "TOTP 验证码（没绑直接回车）: ")
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 2
	}
	body, _ := json.Marshal(map[string]any{
		"password": pw,
		"totp":     code,
		"machines": opts.Machines,
		"all":      opts.All,
	})
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 2
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", opts.Token)
	hc := &http.Client{Timeout: 60 * time.Second}
	if opts.Insecure {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := hc.Do(req)
	if err != nil {
		_, _ = fmt.Fprintln(out, "请求失败: "+err.Error())
		return 1
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusTooManyRequests {
		_, _ = fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return 2
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(out, "服务器返回 %d: %s\n", resp.StatusCode, strings.TrimSpace(string(raw)))
		return 1
	}
	var parsed struct {
		Results []RefreshResult `json:"results"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		_, _ = fmt.Fprintln(out, "响应不是合法 JSON: "+err.Error())
		return 1
	}
	allOK := true
	for _, res := range parsed.Results {
		line := res.Machine + "  " + res.Status
		if res.Status == "ok" {
			line += "（新 token 已写入该机器的 token 文件）"
		} else if res.Detail != "" {
			line += "（" + res.Detail + "）"
		}
		_, _ = fmt.Fprintln(out, line)
		if res.Status != "ok" {
			allOK = false
		}
	}
	if allOK {
		return 0
	}
	return 1
}
