package skills

import (
	"bytes"
	"testing"
)

func TestSkillMD(t *testing.T) {
	b := SkillMD()
	if len(b) == 0 {
		t.Fatal("SKILL.md 内嵌为空")
	}
	// 内嵌进来的必须是个像模像样的 skill 文件：有 name 和正文。
	if !bytes.Contains(b, []byte("name:")) || !bytes.Contains(b, []byte("towstrap")) {
		t.Fatal("SKILL.md 内容不像 skill 文件")
	}
}
