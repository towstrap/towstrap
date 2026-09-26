package selfupdate

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/towstrap/towstrap/internal/version"
)

// withFakeReleases 把下载源和自身路径都指向测试替身，结束后恢复。
func withFakeReleases(t *testing.T, handler http.Handler) (exe string, out *strings.Builder) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	oldRel, oldSelf := releases, selfPath
	releases = ts.URL
	dir := t.TempDir()
	exe = filepath.Join(dir, "towstrap")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	selfPath = func() (string, error) { return exe, nil }
	out = &strings.Builder{}
	t.Cleanup(func() { releases, selfPath = oldRel, oldSelf })
	return exe, out
}

func TestVerifySHA256(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bin")
	os.WriteFile(f, []byte("hello"), 0o600)
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte("hello")))

	if err := verifySHA256(f, sum+"  towstrap-linux-amd64\n", "towstrap-linux-amd64"); err != nil {
		t.Fatalf("该过的没过: %v", err)
	}
	if err := verifySHA256(f, sum+"  towstrap-linux-amd64\n", "towstrap-windows-amd64.exe"); err == nil {
		t.Fatal("清单里没有的行居然过了")
	}
	os.WriteFile(f, []byte("tampered"), 0o600)
	if err := verifySHA256(f, sum+"  towstrap-linux-amd64\n", "towstrap-linux-amd64"); err == nil {
		t.Fatal("哈希对不上居然过了")
	}
}

func TestLatestTag(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("LatestTag 应该用 HEAD，来了 %s", r.Method)
		}
		w.Header().Set("Location", ts.URL+"/releases/tag/v9.9.9")
		w.WriteHeader(http.StatusFound)
	}))
	defer ts.Close()
	old := releases
	releases = ts.URL
	defer func() { releases = old }()

	tag, err := LatestTag()
	if err != nil || tag != "v9.9.9" {
		t.Fatalf("LatestTag = %q, %v", tag, err)
	}
}

// 全流程：下载真二进制、核 SHA256、替换自身文件；替换后旧文件进 .old 备份位。
func TestRun_ReplacesSelf(t *testing.T) {
	asset := "towstrap-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	newBin := []byte("#!/bin/sh\n# new-binary\n")
	sum := fmt.Sprintf("%x", sha256.Sum256(newBin))
	tag := "v99.0.0"

	mux := http.NewServeMux()
	mux.HandleFunc("/download/"+tag+"/"+asset, func(w http.ResponseWriter, r *http.Request) {
		w.Write(newBin)
	})
	mux.HandleFunc("/download/"+tag+"/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", sum, asset)
	})
	exe, out := withFakeReleases(t, mux)

	if err := Run(Opts{Product: "towstrap", Tag: tag, Out: out}); err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	got, err := os.ReadFile(exe)
	if err != nil || string(got) != string(newBin) {
		t.Fatalf("exe 没被换成新二进制: %v %q", err, got)
	}
	if !strings.Contains(out.String(), "SHA256 校验通过") {
		t.Fatalf("输出缺校验行:\n%s", out)
	}
}

// 校验失败不碰原文件。
func TestRun_BadSumKeepsOld(t *testing.T) {
	asset := "towstrap-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/download/v99.0.0/"+asset, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("evil"))
	})
	mux.HandleFunc("/download/v99.0.0/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%064x  %s\n", sha256.Sum256([]byte("not-evil")), asset)
	})
	exe, out := withFakeReleases(t, mux)

	err := Run(Opts{Product: "towstrap", Tag: "v99.0.0", Out: out})
	if err == nil || !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("该因校验失败报错: %v", err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-binary" {
		t.Fatal("校验失败不该动原二进制")
	}
}

// --check 只查不装，文件不动。
func TestRun_CheckOnly(t *testing.T) {
	tag := "v99.0.0"
	mux := http.NewServeMux() // 不该有下载请求打到这
	exe, out := withFakeReleases(t, mux)
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/releases/tag/"+tag)
		w.WriteHeader(http.StatusFound)
	})

	if err := Run(Opts{Product: "towstrap", Check: true, Out: out}); err != nil {
		t.Fatalf("Run --check: %v", err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-binary" {
		t.Fatal("--check 不该动文件")
	}
	if !strings.Contains(out.String(), tag) {
		t.Fatalf("--check 没打出目标版本:\n%s", out)
	}
}

// 已是最新直接收工，不发下载请求。
func TestRun_AlreadyLatest(t *testing.T) {
	cur := strings.TrimSpace(strings.SplitN(version.String(), " ", 2)[0])
	tag := "v" + cur
	if version.Version == "dev" || !tagRe.MatchString(tag) {
		t.Skip("开发版本不好构造同版本场景")
	}
	hit := false
	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/releases/tag/"+tag)
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { hit = true })
	_, out := withFakeReleases(t, mux)

	if err := Run(Opts{Product: "towstrap", Out: out}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hit {
		t.Fatal("同版本不该有下载请求")
	}
	if !strings.Contains(out.String(), "无需升级") {
		t.Fatalf("输出不对:\n%s", out)
	}
}
