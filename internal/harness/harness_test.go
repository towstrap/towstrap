package harness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/towstrap/towstrap/internal/version"
	"github.com/towstrap/towstrap/skills"
)

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestTableAndDetect(t *testing.T) {
	home := t.TempDir()
	// 建三个检测目录；Codex 和 Grok 共用 ~/.agents/skills。
	for _, d := range []string{".claude", ".codex", ".grok"} {
		mkdir(t, filepath.Join(home, d))
	}
	got := Detect(home)
	if len(got) != 3 {
		t.Fatalf("Detect = %d 家，想要 3: %+v", len(got), got)
	}
	names := map[string]string{}
	for _, h := range got {
		names[h.Name] = h.SkillsDir
	}
	if names["Claude Code"] != filepath.Join(home, ".claude", "skills") {
		t.Fatalf("Claude 目标目录不对: %s", names["Claude Code"])
	}
	shared := filepath.Join(home, ".agents", "skills")
	if names["Codex"] != shared || names["Grok Build"] != shared {
		t.Fatalf("Codex/Grok 应共用 %s: %+v", shared, names)
	}
	// Targets 按目录去重，名字合并。
	targets := Targets(got)
	if len(targets) != 2 {
		t.Fatalf("Targets = %d，想要 2（共享目录去重）: %+v", len(targets), targets)
	}
	var joined string
	for _, tg := range targets {
		if tg.SkillsDir == shared {
			joined = tg.Names
		}
	}
	if joined != "Codex / Grok Build" {
		t.Fatalf("共享目录名字合并不对: %q", joined)
	}
	// 没建检测目录的不该出现。
	for _, h := range got {
		if h.Name == "Cursor" {
			t.Fatal("没建 ~/.cursor 却检出 Cursor")
		}
	}
}

func TestInstallFresh(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills")
	r := Install(dir, false, false, time.Now())
	if r.Status != StInstalled {
		t.Fatalf("Status = %v，想要 StInstalled: %s", r.Status, r.Detail)
	}
	got, err := os.ReadFile(filepath.Join(dir, "towstrap", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(skills.SkillMD()) {
		t.Fatal("SKILL.md 内容和内嵌的不一致")
	}
	st, _ := os.Stat(filepath.Join(dir, "towstrap", "SKILL.md"))
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("SKILL.md 权限 %v，想要 644", st.Mode().Perm())
	}
	var m manifest
	if err := json.Unmarshal(mustRead(filepath.Join(dir, "towstrap", ManifestName)), &m); err != nil {
		t.Fatalf("manifest 不是合法 JSON: %v", err)
	}
	if m.Version != version.String() || m.SHA256 != sha(got) || m.InstalledAt == "" {
		t.Fatalf("manifest 内容不对: %+v", m)
	}
}

func TestInstallCurrentThenUpgrade(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills")
	Install(dir, false, false, time.Now())
	before := mustRead(filepath.Join(dir, "towstrap", "SKILL.md"))

	// 同版本再装 → 已是最新，内容不动。
	r := Install(dir, false, false, time.Now().Add(time.Hour))
	if r.Status != StCurrent {
		t.Fatalf("重复装 Status = %v，想要 StCurrent", r.Status)
	}
	if string(mustRead(filepath.Join(dir, "towstrap", "SKILL.md"))) != string(before) {
		t.Fatal("已是最新却改了文件")
	}

	// 把 manifest 改成旧版本 → 再装是升级。
	mp := filepath.Join(dir, "towstrap", ManifestName)
	old := manifest{Version: "0.0.1", SHA256: sha(before), InstalledAt: "2000-01-01T00:00:00Z"}
	mb, _ := json.Marshal(old)
	if err := os.WriteFile(mp, mb, 0o644); err != nil {
		t.Fatal(err)
	}
	r = Install(dir, false, false, time.Now())
	if r.Status != StUpgraded || r.Detail != "0.0.1→"+version.String() {
		t.Fatalf("升级 Status/Detail = %v %q", r.Status, r.Detail)
	}
}

func TestInstallForeignAndForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills")
	mkdir(t, filepath.Join(dir, "towstrap"))
	mine := []byte("user's own skill")
	if err := os.WriteFile(filepath.Join(dir, "towstrap", "SKILL.md"), mine, 0o644); err != nil {
		t.Fatal(err)
	}
	r := Install(dir, false, false, time.Now())
	if r.Status != StSkippedForeign {
		t.Fatalf("无 manifest 的同名 skill Status = %v，想要 StSkippedForeign", r.Status)
	}
	if string(mustRead(filepath.Join(dir, "towstrap", "SKILL.md"))) != string(mine) {
		t.Fatal("跳过了却改了用户文件")
	}
	r = Install(dir, true, false, time.Now())
	if r.Status != StInstalled {
		t.Fatalf("--force Status = %v，想要 StInstalled", r.Status)
	}
	if string(mustRead(filepath.Join(dir, "towstrap", "SKILL.md"))) != string(skills.SkillMD()) {
		t.Fatal("--force 没覆盖成官方内容")
	}
}

func TestInstallOverwritesUserEdit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills")
	Install(dir, false, false, time.Now())
	// 用户装完后改了文件：磁盘 sha 和 manifest 记录不一致 → 升级并提示。
	sp := filepath.Join(dir, "towstrap", "SKILL.md")
	if err := os.WriteFile(sp, append(skills.SkillMD(), "user edit"...), 0o644); err != nil {
		t.Fatal(err)
	}
	r := Install(dir, false, false, time.Now())
	if r.Status != StUpgraded {
		t.Fatalf("Status = %v，想要 StUpgraded", r.Status)
	}
	if r.Detail == "" || !contains(r.Detail, "已覆盖你改过的内容") {
		t.Fatalf("Detail 没提覆盖用户改动: %q", r.Detail)
	}
	if string(mustRead(sp)) != string(skills.SkillMD()) {
		t.Fatal("没恢复成官方内容")
	}
}

func TestUninstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills")

	// 没装过。
	if r := Uninstall(dir, false, false); r.Status != StMissing {
		t.Fatalf("没装过 Status = %v，想要 StMissing", r.Status)
	}

	// 正常卸载。
	Install(dir, false, false, time.Now())
	if r := Uninstall(dir, false, false); r.Status != StUninstalled {
		t.Fatalf("卸载 Status = %v，想要 StUninstalled", r.Status)
	}
	if _, err := os.Stat(filepath.Join(dir, "towstrap")); !os.IsNotExist(err) {
		t.Fatal("卸载后目录还在")
	}

	// 用户改过 SKILL.md → 跳过；--force 才删。
	Install(dir, false, false, time.Now())
	sp := filepath.Join(dir, "towstrap", "SKILL.md")
	if err := os.WriteFile(sp, []byte("user edit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := Uninstall(dir, false, false); r.Status != StSkippedModified {
		t.Fatalf("改过的 Status = %v，想要 StSkippedModified", r.Status)
	}
	if _, err := os.Stat(sp); err != nil {
		t.Fatal("跳过了却删了文件")
	}
	if r := Uninstall(dir, true, false); r.Status != StUninstalled {
		t.Fatalf("--force Status = %v，想要 StUninstalled", r.Status)
	}

	// 用户自己放的（没有 manifest）→ 不动。
	mkdir(t, filepath.Join(dir, "towstrap"))
	if err := os.WriteFile(sp, []byte("user's own"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := Uninstall(dir, false, false); r.Status != StNotOurs {
		t.Fatalf("无 manifest Status = %v，想要 StNotOurs", r.Status)
	}
	if _, err := os.Stat(sp); err != nil {
		t.Fatal("不是本工具装的却被删了")
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills")
	r := Install(dir, false, true, time.Now())
	if r.Status != StInstalled || !r.DryRun {
		t.Fatalf("dry-run Status = %v DryRun=%v", r.Status, r.DryRun)
	}
	if _, err := os.Stat(filepath.Join(dir, "towstrap")); !os.IsNotExist(err) {
		t.Fatal("dry-run 写了文件")
	}
}

func TestRelativePathResolvesFromCwd(t *testing.T) {
	base := t.TempDir()
	mkdir(t, filepath.Join(base, "rel", "skills"))
	t.Chdir(base)
	r := Install(filepath.Join("rel", "skills"), false, false, time.Now())
	if r.Status != StInstalled {
		t.Fatalf("相对路径装失败: %v %s", r.Status, r.Detail)
	}
	if r.SkillsDir != filepath.Join(base, "rel", "skills") {
		t.Fatalf("SkillsDir = %q，想要按 cwd 解析的绝对路径", r.SkillsDir)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
