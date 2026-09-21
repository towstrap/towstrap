package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ensureCert 返回可用的证书和私钥路径。
// 两个文件都在就直接用（正式证书或上次生成的自签证书）；
// 否则生成一张自签证书写进去。自签证书浏览器会告警，
// agent 连它要配 insecure，正式对外请用 Let's Encrypt 等签发的证书。
func ensureCert(certPath, keyPath string) (string, string, error) {
	if certPath == "" {
		certPath = "tls_cert.pem"
	}
	if keyPath == "" {
		keyPath = "tls_key.pem"
	}
	if fileOK(certPath) && fileOK(keyPath) {
		return certPath, keyPath, nil
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ws2ssh"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, interfaceIPs()...)

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeCertFiles(certPath, certPEM, 0o644, keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	slog.Info("generated self-signed certificate", "cert", certPath, "key", keyPath)
	return certPath, keyPath, nil
}

func writeCertFiles(certPath string, certPEM []byte, certMode os.FileMode, keyPath string, keyPEM []byte, keyMode os.FileMode) error {
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{certPath, certPEM, certMode},
		{keyPath, keyPEM, keyMode},
	}
	for _, f := range files {
		if dir := filepath.Dir(f.path); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
		}
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

func interfaceIPs() []net.IP {
	var ips []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}
			if v4 := ipNet.IP.To4(); v4 != nil {
				ips = append(ips, v4)
			}
		}
	}
	return ips
}

func fileOK(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
