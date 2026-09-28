package server

import (
	_ "embed"
	"html"
	"net"
	"net/http"
	"strings"

	"github.com/towstrap/towstrap/internal/proto"
	"github.com/towstrap/towstrap/internal/version"
	"github.com/towstrap/towstrap/scripts"
)

//go:embed landing.html
var landingHTML []byte

//go:embed landing_en.html
var landingEnHTML []byte

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

	en := wantsEnglish(r)
	pageSrc := landingHTML
	if en {
		pageSrc = landingEnHTML
	}

	// 管理员在 server.yaml 配的 agent_defaults 会烤进装好的 agent.yaml，
	// 页面上展示出来，装之前就能看到会写入什么。
	confBlock := ""
	if d := strings.TrimSpace(s.cfg.AgentDefaults); d != "" {
		summary := "本服务器预设的 agent 工作配置（装完自动写进 agent.yaml）"
		if en {
			summary = "Agent working config preset by this server (written into agent.yaml on install)"
		}
		confBlock = `<details class="conf"><summary>` + summary + `</summary>` +
			`<pre>` + html.EscapeString(d) + `</pre></details>`
	}

	// 开了自助注册：安装命令不带 --token，下面多一步 register；没开则
	// 保持管理员发 token 的传统流程。
	intro := `获取管理员签发的 agent token（<code>tsa-…</code>）后，选择任一方式安装：`
	copyBtn, regCmt := "复制",
		"# 安装后注册：交互输入账号名与密码，自动写入 token 与配置；一台机器仅允许注册一个账号"
	if en {
		intro = `After obtaining an agent token (<code>tsa-…</code>) issued by your admin, install via either:`
		copyBtn = "Copy"
		regCmt = "# Register after install: prompts for account name and password, writes the token and config; one account per machine"
	}
	shTok, psTok, regStep := " --token tsa-…", " -Token tsa-…", ""
	if s.cfg.Register {
		intro = "本服务器已开启自助注册——安装完成后执行 <code>towstrap register</code> 创建账号并获取 token，无需管理员签发："
		if en {
			intro = "Self-registration is enabled on this server — run <code>towstrap register</code> after install to create an account and get a token, no admin issuance needed:"
		}
		shTok, psTok = "", ""
		regStep = `<div class="cmt">` + regCmt + `</div>` +
			`<div class="cmdrow"><pre class="cmdline">towstrap register` + html.EscapeString(regServerArg(server)) +
			`</pre><button class="copy" type="button">` + copyBtn + `</button></div>`
	}

	page := strings.NewReplacer(
		"{{BASE}}", base,
		"{{SERVER}}", server,
		"{{HOST}}", host,
		"{{SSHPORT}}", sshPort,
		"{{VERSION}}", version.String(),
		"{{VERARG}}", verArg,
		"{{AGENTCONF_BLOCK}}", confBlock,
		"{{INTRO}}", intro,
		"{{SH_TOKEN_ARG}}", shTok,
		"{{PS_TOKEN_ARG}}", psTok,
		"{{REGISTER_STEP}}", regStep,
	).Replace(string(pageSrc))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache") // 地址随请求推导，别缓存
	_, _ = w.Write([]byte(page))
}

// wantsEnglish：?lang= 显式参数优先；否则看 Accept-Language 里 en
// 是否排在 zh 之前（或根本没要中文）。粗粒度判断对落地页够用——
// 页脚始终有手动切换链接。
func wantsEnglish(r *http.Request) bool {
	if l := r.URL.Query().Get("lang"); l != "" {
		return l == "en"
	}
	al := r.Header.Get("Accept-Language")
	ie, iz := strings.Index(al, "en"), strings.Index(al, "zh")
	return ie >= 0 && (iz < 0 || ie < iz)
}

// regServerArg：register 默认连官方服务器；页面所属服务器不是官方时
// 给一行 --server。
func regServerArg(server string) string {
	if server == proto.OfficialServer {
		return ""
	}
	return " --server " + server
}
