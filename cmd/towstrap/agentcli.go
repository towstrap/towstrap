package main

// 凭据类子命令（totp/passwd/oauth/token refresh）共用的引导：它们都要
// 读 agent.yaml → 合并旗标 → 定服务器 → 查明文 → 解析 agent token → 建
// HTTP client。以前每个命令各抄了一份，抄着抄着出了两处不一致：
// insecure 只认旗标不认配置文件、oauth/refresh 不探测默认配置目录——
// 统一收进这里。

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/towstrap/towstrap/internal/client"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/proto"
)

// credFlags 是凭据类子命令共用的一组旗标；命令自己的额外旗标
// （--password-stdin、--totp、--wait、--all…）照旧单独注册。
type credFlags struct {
	configPath, server, agentToken, tokenFile *string
	insecure, allowPlain                      *bool
}

func addCredFlags(fs *flag.FlagSet) credFlags {
	return credFlags{
		configPath: fs.String("config", "", ""),
		server:     fs.String("server", "", ""),
		agentToken: fs.String("agent-token", "", ""),
		tokenFile:  fs.String("agent-token-file", "", ""),
		insecure:   fs.Bool("insecure", false, ""),
		allowPlain: fs.Bool("allow-plain", false, ""),
	}
}

// agentCLIEnv 是引导完成后的运行环境。
type agentCLIEnv struct {
	cfg  config.Agent // 文件 + 显式旗标合并后的完整配置
	srv  string       // ws(s):// 最终服务器地址（含官方回落）
	base string       // srv 的 http(s):// 形态（端点路径前缀）
	tok  string       // 解析出的 agent token
	hc   *http.Client // 15s 超时；cfg.Insecure 为真时跳过证书校验
}

// loadAgentCLI 跑统一引导：--config 缺省时探测默认安装目录的 agent.yaml
// （装好的机器上零旗标能用；探测不到不报错，旗标/环境变量兜底；显式给
// 了 --config 就必须读得到）→ 合并旗标 → 服务器回落官方 → 明文检查 →
// 解析 token → 按合并后的 Insecure（配置文件和旗标都算数）建 client。
// 失败返回错误，调用方打印 + return 2。
func loadAgentCLI(fs *flag.FlagSet, f credFlags) (*agentCLIEnv, error) {
	path := *f.configPath
	if path == "" {
		if d := config.DefaultAgentPath(); fileExists(d) {
			path = d
		}
	}
	var file config.Agent
	if path != "" {
		var err error
		if file, err = config.LoadAgent(path); err != nil {
			return nil, err
		}
	}
	cfg := config.MergeAgent(file, config.VisitedFlags(fs))
	srv := cfg.Server
	if srv == "" {
		srv = proto.OfficialServer
	}
	// 密码/token 会走这个地址出去——明文出公网必须显式确认。
	if err := client.PlainCheck(srv, *f.allowPlain); err != nil {
		return nil, err
	}
	base, err := client.HTTPBase(srv)
	if err != nil {
		return nil, err
	}
	tok, _, _, err := resolveAgentToken(*f.agentToken, *f.tokenFile,
		os.Getenv("TOWSTRAP_AGENT_TOKEN"), cfg.AgentToken, cfg.AgentTokenFile)
	if err != nil {
		return nil, fmt.Errorf("读 agent token 失败（先在机器上 towstrap register 或用 --agent-token-file 指）：%w", err)
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	if cfg.Insecure {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return &agentCLIEnv{cfg: cfg, srv: srv, base: base, tok: tok, hc: hc}, nil
}
