// Package skills 把随仓库发布的 LLM skill 嵌进二进制，
// cmd/ws2ssh-mcp 的 connect 子命令用它把 skill 装进本机各家 AI 编码助手。
package skills

import "embed"

// SkillName 是 skill 的名字，也是安装目标里的子目录名（<skills目录>/ws2ssh/SKILL.md）。
const SkillName = "ws2ssh"

// FS 嵌着 skills/ 目录里的 skill 源文件。
//
//go:embed ws2ssh/SKILL.md
var FS embed.FS

// SkillMD 返回 SKILL.md 原文。编译期内嵌，读不到说明构建本身坏了。
func SkillMD() []byte {
	b, err := FS.ReadFile(SkillName + "/SKILL.md")
	if err != nil {
		panic(err)
	}
	return b
}
