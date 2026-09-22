package e2e

import (
	"fmt"
	"path/filepath"
	"testing"

	"ws2ssh/internal/client"
	"ws2ssh/internal/server"
)

// TLS 模式：自签证书自动生成，agent 用 wss:// --insecure 连上，SSH 照常。
func TestTLSWSSAgent(t *testing.T) {
	dir := t.TempDir()
	srv, httpPort, sshPort, users := startServerOpt(t, server.Config{
		TLS:      true,
		CertPath: filepath.Join(dir, "cert.pem"),
		KeyPath:  filepath.Join(dir, "key.pem"),
	})
	acct, err := users.Add("tlsuser", "tlspw12345", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_ = client.ConnectOnce(client.Config{
			ID:         "tls-host",
			Server:     fmt.Sprintf("https://127.0.0.1:%d", httpPort), // https:// 自动转 wss://
			AgentToken: acct.Machines[0].Token,
			Shell:      "/bin/bash",
			Insecure:   true,
			Quiet:      true,
			AuditLog:   filepath.Join(dir, "audit.log"),
		})
	}()
	waitAgent(t, srv.Hub, "tlsuser+default")
	sshEcho(t, sshPort, "tlsuser", "tlspw12345", "echo hello-tls")
}
