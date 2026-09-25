package server

import (
	_ "embed"
	"html"
	"net"
	"net/http"
	"strings"

	"github.com/towstrap/towstrap/internal/version"
	"github.com/towstrap/towstrap/scripts"
)

//go:embed landing.html
var landingHTML []byte

// handleLanding 是 / 的产品落地页：介绍产品 + 给出 agent 一键安装命令。
// 地址字段全部按这台服务器的对外地址推导（public_url 优先，否则请求 Host），
// 和 /install.sh 同一套 installServerURL——页面上的命令所见即所得。
// 未匹配的路径照旧 404。
func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	server := s.installServerURL(r) // ws(s)://host[:port]
	base := server
	switch {
	case strings.HasPrefix(base, "wss://"):
		base = "https://" + base[len("wss://"):]
	case strings.HasPrefix(base, "ws://"):
		base = "http://" + base[len("ws://"):]
	}
	host := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	sshPort := s.sshPort()

	// 安装命令和这台服务器版本关联：明示 --version，让人知道装的是哪个
	// 版本；dev 版本不算 release，不加参数（脚本自己回落 latest）。
	verArg := ""
	if t := scripts.ReleaseTag(); t != "latest" {
		verArg = " --version " + t
	}

	// 管理员在 server.yaml 配的 agent_defaults 会烤进装好的 agent.yaml，
	// 页面上展示出来，装之前就能看到会写入什么。
	confBlock := ""
	if d := strings.TrimSpace(s.cfg.AgentDefaults); d != "" {
		confBlock = `<details class="conf"><summary>本服务器预设的 agent 工作配置（装完自动写进 agent.yaml）</summary>` +
			`<pre>` + html.EscapeString(d) + `</pre></details>`
	}

	page := strings.NewReplacer(
		"{{BASE}}", base,
		"{{SERVER}}", server,
		"{{HOST}}", host,
		"{{SSHPORT}}", sshPort,
		"{{VERSION}}", version.String(),
		"{{VERARG}}", verArg,
		"{{AGENTCONF_BLOCK}}", confBlock,
	).Replace(string(landingHTML))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache") // 地址随请求推导，别缓存
	_, _ = w.Write([]byte(page))
}
