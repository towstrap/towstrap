package server

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCertGeneratesAndReuses(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cert, key, err := ensureCert(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if cert != certPath || key != keyPath {
		t.Fatalf("%q %q", cert, key)
	}
	first, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", st.Mode().Perm())
	}

	// 第二次应复用已生成的文件
	if _, _, err := ensureCert(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(certPath)
	if string(first) != string(second) {
		t.Fatal("证书不应被重复生成")
	}

	// 生成的证书能被 TLS 加载，是服务器证书
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Certificate) != 1 {
		t.Fatalf("cert chain len = %d", len(pair.Certificate))
	}
}

func TestEnsureCertDefaults(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	cert, key, err := ensureCert("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cert != "tls_cert.pem" || key != "tls_key.pem" {
		t.Fatalf("%q %q", cert, key)
	}
	if !fileOK("tls_cert.pem") || !fileOK("tls_key.pem") {
		t.Fatal("默认路径的证书没有生成")
	}
}
