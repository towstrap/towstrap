package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"ws2ssh/internal/version"
	"ws2ssh/skills"
)

// ManifestName 是跟着 SKILL.md 一起写进目标目录的清单文件名，
// 用来区分「本工具装的」和用户自己放的同名 skill。
const ManifestName = ".ws2ssh-managed.json"

// manifest 记录这次安装来自哪个版本、SKILL.md 的指纹，卸载和升级时比对用。
type manifest struct {
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	InstalledAt string `json:"installed_at"`
}

// Status 是一次安装/卸载的结果。
type Status int

const (
	StInstalled       Status = iota // 新装
	StUpgraded                      // 覆盖升级（或覆盖了用户改过的内容）
	StCurrent                       // 已是最新，没动
	StSkippedForeign                // 有同名 skill 但不是本工具装的，跳过
	StSkippedModified               // 卸载时：用户改过 SKILL.md，跳过
	StNotOurs                       // 卸载时：没有 manifest，不是本工具装的
	StUninstalled                   // 已卸载
	StMissing                       // 卸载时：目标本来就不存在
	StFailed                        // 出错，Detail 是错误信息
)

// Result 是一个目标目录的安装/卸载结果。
type Result struct {
	SkillsDir string // 安装根目录（绝对路径）
	TargetDir string // <SkillsDir>/ws2ssh
	Status    Status
	Detail    string // 如 "0.2.0→0.3.0"、"已覆盖你改过的内容"、错误信息
	DryRun    bool
}

// StatusLine 是结果末尾那一列的中文描述。
func (r Result) StatusLine() string {
	pre := ""
	if r.DryRun {
		pre = "[演练] "
	}
	switch r.Status {
	case StInstalled:
		return pre + "已安装" + suffix(r.Detail)
	case StUpgraded:
		return pre + "已升级 " + r.Detail
	case StCurrent:
		return pre + "已是最新"
	case StSkippedForeign:
		return pre + "跳过：非本工具安装（--force 才覆盖）"
	case StSkippedModified:
		return pre + "跳过：你改过内容（--force 才删）"
	case StNotOurs:
		return pre + "跳过：不是本工具安装的，不动"
	case StUninstalled:
		return pre + "已卸载"
	case StMissing:
		return pre + "没装过"
	default:
		return pre + "失败：" + r.Detail
	}
}

func suffix(d string) string {
	if d == "" {
		return ""
	}
	return "（" + d + "）"
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func skillPath(skillsDir string) string {
	return filepath.Join(skillsDir, skills.SkillName, "SKILL.md")
}

func manifestPath(skillsDir string) string {
	return filepath.Join(skillsDir, skills.SkillName, ManifestName)
}

// Install 把官方 SKILL.md 和 manifest 写进 skillsDir/ws2ssh。
// skillsDir 可以是相对路径（按当前目录解析）。force 覆盖非本工具安装的同名
// skill；dryRun 只做判定不写文件。now 仅为了测试可注入。
func Install(skillsDir string, force, dryRun bool, now time.Time) Result {
	abs, err := filepath.Abs(skillsDir)
	if err != nil {
		abs = skillsDir
	}
	r := Result{SkillsDir: abs, TargetDir: filepath.Join(abs, skills.SkillName), DryRun: dryRun}

	want := skills.SkillMD()
	wantSHA := sha(want)
	existing, readErr := os.ReadFile(skillPath(abs))
	manBytes, manErr := os.ReadFile(manifestPath(abs))

	switch {
	case errors.Is(readErr, fs.ErrNotExist):
		// 没装过：直接写。
		r.Status = StInstalled
	case readErr != nil:
		r.Status, r.Detail = StFailed, readErr.Error()
		return r
	case errors.Is(manErr, fs.ErrNotExist) || parseManifest(manBytes) == nil:
		// 有 SKILL.md 但没有（或无法识别的）manifest：用户自己放的同名 skill。
		if !force {
			r.Status = StSkippedForeign
			return r
		}
		r.Status, r.Detail = StInstalled, "覆盖了非本工具安装的内容"
	case manErr != nil:
		r.Status, r.Detail = StFailed, manErr.Error()
		return r
	default:
		man := parseManifest(manBytes)
		if sha(existing) == wantSHA && man.Version == version.String() {
			r.Status = StCurrent
			return r
		}
		// 覆盖升级：官方内容优先。用户装完后改过文件（磁盘 sha 和 manifest
		// 记录的不一致）时提示一句。
		r.Status = StUpgraded
		r.Detail = man.Version + "→" + version.String()
		if sha(existing) != man.SHA256 {
			r.Detail += "（已覆盖你改过的内容）"
		}
	}
	if dryRun {
		return r
	}
	if err := writeAll(abs, want, wantSHA, now); err != nil {
		r.Status, r.Detail = StFailed, err.Error()
	}
	return r
}

func parseManifest(b []byte) *manifest {
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil || m.SHA256 == "" {
		return nil
	}
	return &m
}

// writeAll 建目录并原子写 SKILL.md + manifest。
func writeAll(skillsDir string, want []byte, wantSHA string, now time.Time) error {
	dir := filepath.Join(skillsDir, skills.SkillName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeAtomic(skillPath(skillsDir), want); err != nil {
		return err
	}
	mb, err := json.MarshalIndent(manifest{
		Version:     version.String(),
		SHA256:      wantSHA,
		InstalledAt: now.UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(manifestPath(skillsDir), append(mb, '\n'))
}

// writeAtomic 同目录临时文件 + rename，失败不留半成品。
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // rename 成功后这是 no-op
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Uninstall 删除 skillsDir/ws2ssh。只删本工具装且内容没被改过的；
// 用户改过要 --force，不是本工具装的不动。dryRun 只判定不删。
func Uninstall(skillsDir string, force, dryRun bool) Result {
	abs, err := filepath.Abs(skillsDir)
	if err != nil {
		abs = skillsDir
	}
	r := Result{SkillsDir: abs, TargetDir: filepath.Join(abs, skills.SkillName), DryRun: dryRun}

	manBytes, manErr := os.ReadFile(manifestPath(abs))
	existing, readErr := os.ReadFile(skillPath(abs))
	switch {
	case errors.Is(manErr, fs.ErrNotExist) && errors.Is(readErr, fs.ErrNotExist):
		r.Status = StMissing
		return r
	case errors.Is(manErr, fs.ErrNotExist) || parseManifest(manBytes) == nil:
		// 有 SKILL.md 但没有 manifest：不是我们装的，不动。
		r.Status = StNotOurs
		return r
	case manErr != nil:
		r.Status, r.Detail = StFailed, manErr.Error()
		return r
	}
	man := parseManifest(manBytes)
	if readErr == nil && sha(existing) != man.SHA256 && !force {
		r.Status = StSkippedModified
		return r
	}
	if dryRun {
		r.Status = StUninstalled
		return r
	}
	if err := os.RemoveAll(r.TargetDir); err != nil {
		r.Status, r.Detail = StFailed, err.Error()
		return r
	}
	r.Status = StUninstalled
	return r
}

// Installed 报告 skillsDir 下的安装状态，给 connect list 用：
// present=有 ws2ssh/ 目录，ours=是本工具装的（manifest 可读），ver=装的版本。
func Installed(skillsDir string) (present, ours bool, ver string) {
	if _, err := os.Stat(filepath.Join(skillsDir, skills.SkillName)); err != nil {
		return false, false, ""
	}
	if man := parseManifest(mustRead(manifestPath(skillsDir))); man != nil {
		return true, true, man.Version
	}
	return true, false, ""
}

func mustRead(p string) []byte {
	b, _ := os.ReadFile(p)
	return b
}

// Tilde 把绝对路径里的 home 前缀显示成 ~，仅用于输出。
func Tilde(home, path string) string {
	if home != "" && path == home {
		return "~"
	}
	if home != "" && len(path) > len(home) && path[:len(home)] == home && path[len(home)] == os.PathSeparator {
		return "~" + path[len(home):]
	}
	return path
}

// CheckDir 报告目录是否存在，给 connect list 的检测列用。
func CheckDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
