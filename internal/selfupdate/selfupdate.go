// Package selfupdate 提供 towstrap / towstrap-server 的手工自升级：
// update 子命令触发，从 GitHub releases 拉本平台的二进制，核 SHA256SUMS
// 后原子替换自己的可执行文件。不做后台自动升级——什么时候换由人决定。
package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/towstrap/towstrap/internal/version"
)

// releases 固定指向官方仓库——升级源不接受配置，防止配置文件被改后
// 从攻击者控制的仓库拉"新版"。信任边界和 install.sh 一致：HTTPS +
// SHA256SUMS（sums 和二进制同出一个 Release，校验挡的是传输/镜像损坏）。
// var 只为测试能指向 httptest，外部别改。
var releases = "https://github.com/towstrap/towstrap/releases"

// tagRe 允许 v0.3.3 / 0.3.3 / v0.4.0-rc.1 这类 tag。旗标传进来的串会拼进
// URL，先过一遍防止怪字符拼出意外路径。
var tagRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)

type Opts struct {
	Product string    // "towstrap" / "towstrap-server"——决定资产名和服务名
	Tag     string    // 指定版本（"v0.3.3" 或 "0.3.3"）；空 = latest
	Check   bool      // 只查版本不下载
	Out     io.Writer // 输出；nil 用 os.Stdout
}

func (o Opts) out() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return os.Stdout
}

// headClient 不跟跳转：LatestTag 要自己拿 /latest 的 302 Location。
// dlClient 跟跳转：release 资产会 302 到 CDN，必须跟着走。
var (
	headClient = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	dlClient = &http.Client{Timeout: 5 * time.Minute}
)

// Run 执行自升级：查版本 → 下载 → 校验 → 原子替换 → 重启受管服务。
func Run(o Opts) error {
	out := o.out()
	asset := o.Product + "-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}

	tag := strings.TrimSpace(o.Tag)
	if tag == "" {
		fmt.Fprintln(out, ">> 查询最新版本…")
		t, err := LatestTag()
		if err != nil {
			return fmt.Errorf("查最新版本失败：%w（要离线升级可用 --version vX.Y.Z 直给）", err)
		}
		tag = t
	}
	if !tagRe.MatchString(tag) {
		return fmt.Errorf("版本号 %q 不对——要 v0.3.3 这种", tag)
	}
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	target := strings.TrimPrefix(tag, "v")
	cur := version.String()

	fmt.Fprintf(out, "当前：%s → 目标：%s\n", cur, tag)
	switch {
	case !version.LessThan(cur, target) && !version.LessThan(target, cur):
		fmt.Fprintln(out, "已是该版本，无需升级")
		return nil
	case version.LessThan(target, cur):
		fmt.Fprintln(out, ">> 注意：目标版本低于当前，是降级操作")
	}
	if o.Check {
		fmt.Fprintln(out, "（--check 只查不装）")
		return nil
	}

	exe, err := selfPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	// 目录写不进就别下了——落到一半的升级比不升更糟。
	if probe, err := os.CreateTemp(dir, ".towstrap-up-*"); err != nil {
		return fmt.Errorf("%s 写不进去：%w——root 装的请 sudo %s update", dir, err, o.Product)
	} else {
		probe.Close()
		os.Remove(probe.Name())
	}

	base := releases + "/download/" + tag
	fmt.Fprintf(out, ">> 下载 %s（%s）\n", asset, tag)
	tmpBin := filepath.Join(dir, ".towstrap-new-"+asset)
	if err := download(base+"/"+asset, tmpBin); err != nil {
		return fmt.Errorf("下载失败：%w", err)
	}
	defer os.Remove(tmpBin)

	sums, err := fetchString(base + "/SHA256SUMS")
	if err != nil {
		return fmt.Errorf("拉不到 SHA256SUMS，校验过不了就不装：%w", err)
	}
	if err := verifySHA256(tmpBin, sums, asset); err != nil {
		return err
	}
	fmt.Fprintln(out, ">> SHA256 校验通过")
	if err := os.Chmod(tmpBin, 0o755); err != nil {
		return err
	}

	if err := replace(exe, tmpBin); err != nil {
		return fmt.Errorf("替换 %s 失败：%w", exe, err)
	}
	fmt.Fprintf(out, ">> 已更新 %s → %s\n", exe, tag)

	restartManaged(o.Product, out)
	return nil
}

// LatestTag 拿最新 release tag：/releases/latest 恒 302 到 /tag/vX.Y.Z，
// 不用 GitHub API（省得吃 rate limit）。
func LatestTag() (string, error) {
	req, err := http.NewRequest(http.MethodHead, releases+"/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "towstrap-update")
	resp, err := headClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	i := strings.LastIndex(loc, "/tag/")
	if i < 0 {
		return "", fmt.Errorf("latest 跳到的地址看不懂：%s", loc)
	}
	return loc[i+len("/tag/"):], nil
}

// selfPath 返回当前可执行文件的真实路径（解开 mirror→towstrap 这类软链，
// 替换的是本体不是链接）。var 只为测试替换路径指向临时文件。
var selfPath = func() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return filepath.Abs(exe)
}

func download(url, dst string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "towstrap-update")
	resp, err := dlClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s → HTTP %d（版本写错？tag 列表见 releases 页）", url, resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, cpErr := io.Copy(f, resp.Body)
	clErr := f.Close()
	if cpErr != nil {
		return cpErr
	}
	return clErr
}

func fetchString(url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "towstrap-update")
	resp, err := dlClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), err
}

// verifySHA256 在 SHA256SUMS 里找 asset 那一行，核对文件哈希。
// 找不到行 = 校验不过（和 install.sh 同一口径）。
func verifySHA256(path, sums, asset string) error {
	var want string
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == asset {
			want = f[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("SHA256SUMS 里没有 %s 这一行", asset)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return fmt.Errorf("SHA256 校验失败（%s 和发布清单对不上）", asset)
	}
	return nil
}

// replace 原子换二进制：先把旧的挪成 .old（运行中的进程也能挪），再把
// 新文件挪进原名。任何一步失败都回滚，不留没有可执行文件的窗口。
// .old 清不掉（Windows 上运行中的映像删不了）就留着说明，不影响功能。
func replace(exe, newBin string) error {
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(newBin, exe); err != nil {
		_ = os.Rename(old, exe) // 回滚
		return err
	}
	_ = os.Remove(old)
	return nil
}

// restartManaged 升级后把受管服务拉起来跑新版。只碰我们认识的托管形态
// （systemd 单元 / schtasks 计划任务）；手工跑的不替用户做决定。
func restartManaged(product string, out io.Writer) {
	switch runtime.GOOS {
	case "linux":
		// 系统单元（root 装）和用户单元（普通用户装）都试一下。
		if os.Geteuid() == 0 && systemctlActive("", product) {
			if err := exec.Command("systemctl", "restart", product).Run(); err == nil {
				fmt.Fprintf(out, ">> 服务 %s 已重启，新版本生效\n", product)
			} else {
				fmt.Fprintf(out, ">> systemctl restart %s 失败，手工重启生效\n", product)
			}
			return
		}
		if systemctlActive("--user", product) {
			if err := exec.Command("systemctl", "--user", "restart", product).Run(); err == nil {
				fmt.Fprintf(out, ">> 用户级服务 %s 已重启，新版本生效\n", product)
				return
			}
		}
		fmt.Fprintf(out, ">> 若 %s 以服务在跑，重启服务后新版本生效\n", product)
	case "windows":
		// install.ps1 建议的自启形态是名为 towstrap 的计划任务。
		if exec.Command("schtasks", "/query", "/tn", product).Run() == nil {
			_ = exec.Command("schtasks", "/end", "/tn", product).Run()
			if err := exec.Command("schtasks", "/run", "/tn", product).Run(); err == nil {
				fmt.Fprintf(out, ">> 计划任务 %s 已重启，新版本生效\n", product)
				return
			}
		}
		fmt.Fprintln(out, ">> 重启运行中的 towstrap 后新版本生效")
	default: // darwin 等：没有托管形态
		fmt.Fprintln(out, ">> 重启运行中的进程后新版本生效")
	}
}

func systemctlActive(scope, unit string) bool {
	args := []string{}
	if scope != "" {
		args = append(args, scope)
	}
	args = append(args, "is-active", "--quiet", unit)
	return exec.Command("systemctl", args...).Run() == nil
}
