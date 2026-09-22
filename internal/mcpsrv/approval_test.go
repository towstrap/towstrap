package mcpsrv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSettleStaleID 对不存在（已超时/已处理）的 id 调 approve/deny 要报错，
// 且不能在目录里留下永远没人清的 .approved/.denied 文件。
func TestSettleStaleID(t *testing.T) {
	dir := t.TempDir()
	if _, err := ApprovePending(dir, "dead01", false); err == nil {
		t.Fatal("不存在的 id 应报错")
	}
	if _, err := DenyPending(dir, "dead01", false); err == nil {
		t.Fatal("不存在的 id 应报错")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("目录里不该留下表态文件: %v", ents)
	}
}

// TestSettleWritesMarker 请求还在时，approve/deny 写对应的表态文件。
func TestSettleWritesMarker(t *testing.T) {
	dir := t.TempDir()
	pf, _ := json.Marshal(pendingFile{ID: "abc123", Machine: "m", Kind: "command", Detail: "ls", Created: time.Now()})
	if err := os.WriteFile(filepath.Join(dir, "abc123.json"), pf, 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := ApprovePending(dir, "abc123", false); err != nil || n != 1 {
		t.Fatalf("ApprovePending: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "abc123.approved")); err != nil {
		t.Fatal("应有 .approved 文件")
	}
	if n, err := DenyPending(dir, "abc123", false); err != nil || n != 1 {
		t.Fatalf("DenyPending: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "abc123.denied")); err != nil {
		t.Fatal("应有 .denied 文件")
	}
	// --all 对空目录报错
	if _, err := ApprovePending(t.TempDir(), "", true); err == nil {
		t.Fatal("--all 且无待批请求应报错")
	}
}
