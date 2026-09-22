// Package harness 负责把随项目发布的 ws2ssh skill 装进本机各家
// AI 编码助手（harness）的 skills 目录，并生成它们的 MCP 配置片段。
package harness

import (
	"os"
	"path/filepath"
)

// Harness 是一家 AI 编码助手：DetectDir 存在就认为本机装了它，
// skill 装到 SkillsDir。两个路径都是绝对路径。
type Harness struct {
	Name      string
	DetectDir string
	SkillsDir string
}

// Table 返回支持的 harness 全表；home 是用户主目录，测试注入临时目录。
func Table(home string) []Harness {
	j := func(elem ...string) string {
		return filepath.Join(append([]string{home}, elem...)...)
	}
	// Codex 同时扫 ~/.codex/skills 和共享的 ~/.agents/skills，装两处会被列两遍，
	// 所以只装共享目录；Grok Build 扫 ~/.grok/skills、~/.agents/skills，并兼容
	// ~/.claude/skills、~/.cursor/skills（按名字去重），同样装共享目录就够。
	shared := j(".agents", "skills")
	return []Harness{
		{Name: "Claude Code", DetectDir: j(".claude"), SkillsDir: j(".claude", "skills")},
		{Name: "Codex", DetectDir: j(".codex"), SkillsDir: shared},
		{Name: "Grok Build", DetectDir: j(".grok"), SkillsDir: shared},
		{Name: "Cursor", DetectDir: j(".cursor"), SkillsDir: j(".cursor", "skills")},
		{Name: "Gemini CLI", DetectDir: j(".gemini"), SkillsDir: j(".gemini", "skills")},
		{Name: "OpenCode", DetectDir: j(".config", "opencode"), SkillsDir: j(".config", "opencode", "skills")},
		{Name: "GitHub Copilot CLI", DetectDir: j(".copilot"), SkillsDir: j(".copilot", "skills")},
		{Name: "Devin CLI", DetectDir: j(".config", "devin"), SkillsDir: j(".config", "devin", "skills")},
	}
}

// Detect 返回本机检测到的 harness（DetectDir 是存在的目录）。
func Detect(home string) []Harness {
	var out []Harness
	for _, h := range Table(home) {
		if st, err := os.Stat(h.DetectDir); err == nil && st.IsDir() {
			out = append(out, h)
		}
	}
	return out
}

// Target 是一个去重后的安装目标：共用一个 SkillsDir 的 harness 名字合并显示。
type Target struct {
	Names     string // 如 "Codex / Grok Build"
	SkillsDir string
}

// Targets 按 SkillsDir 路径去重（Codex 和 Grok 共用 ~/.agents/skills 只写一次）。
func Targets(hs []Harness) []Target {
	var out []Target
	idx := map[string]int{}
	for _, h := range hs {
		if i, ok := idx[h.SkillsDir]; ok {
			out[i].Names += " / " + h.Name
			continue
		}
		idx[h.SkillsDir] = len(out)
		out = append(out, Target{Names: h.Name, SkillsDir: h.SkillsDir})
	}
	return out
}
