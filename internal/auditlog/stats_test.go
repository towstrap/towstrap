package auditlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestScanBasic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	writeLines(t, p, []string{
		`2026-09-29T10:00:00Z AUTH-OK user=alice ip=1.2.3.4`,
		`2026-09-29T10:00:05Z AUTH-FAIL user=bob ip=1.2.3.5`,
		`2026-09-29T10:01:00Z SESSION-START user=alice from=1.2.3.4 id=s1 mode=exec`,
		`2026-09-29T10:11:00Z SESSION-END user=alice from=1.2.3.4 id=s1 code=0`,
		`2026-09-29T10:02:00Z SESSION-START user=bob from=1.2.3.5 id=s2 mode=shell`,
		`2026-09-29T09:00:00Z AGENT-CONNECT id=alice+office ip=5.6.7.8 version=1.0`,
		`2026-09-29T11:00:00Z AGENT-DISCONNECT id=alice+office ip=5.6.7.8`,
	})
	st, err := Scan(p, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Sessions != 2 || st.SessionsDone != 1 || st.SessionsOpen() != 1 {
		t.Fatalf("sessions: %+v open=%d", st, st.SessionsOpen())
	}
	if st.SessionDur != 10*time.Minute {
		t.Fatalf("dur=%v", st.SessionDur)
	}
	if st.SessionUsers["alice"].Count != 1 || st.SessionUsers["alice"].Dur != 10*time.Minute {
		t.Fatalf("alice: %+v", st.SessionUsers["alice"])
	}
	if st.SessionUsers["bob"].Count != 1 || st.SessionUsers["bob"].Dur != 0 {
		t.Fatalf("bob: %+v", st.SessionUsers["bob"])
	}
	if st.AgentConnects != 1 || st.AgentsLive() != 0 || st.AgentOnline != 2*time.Hour {
		t.Fatalf("agents: %+v live=%d", st, st.AgentsLive())
	}
	if st.AuthOK != 1 || st.AuthFail != 1 {
		t.Fatalf("auth: %+v", st)
	}
	if st.Events["SESSION-START"] != 2 || st.Events["AUTH-OK"] != 1 {
		t.Fatalf("events: %+v", st.Events)
	}
}

func TestScanRotationPairing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	// START 落在旧轮转文件，END 在当前文件——跨文件配对。
	writeLines(t, p+".1", []string{
		`2026-09-29T09:00:00Z SESSION-START user=alice id=s1 mode=exec`,
	})
	writeLines(t, p, []string{
		`2026-09-29T09:30:00Z SESSION-END id=s1 code=0`,
	})
	st, err := Scan(p, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if st.SessionsDone != 1 || st.SessionDur != 30*time.Minute {
		t.Fatalf("dur=%v done=%d", st.SessionDur, st.SessionsDone)
	}
}

func TestScanSinceWindow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	writeLines(t, p, []string{
		`2026-09-20T10:00:00Z SESSION-START user=alice id=s1 mode=exec`,
		`2026-09-20T10:10:00Z SESSION-END id=s1`,
		`2026-09-29T10:00:00Z SESSION-START user=bob id=s2 mode=exec`,
	})
	st, err := Scan(p, time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if st.Sessions != 1 || st.SessionsDone != 0 {
		t.Fatalf("window: %+v", st)
	}
}

func TestScanQuotedValues(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	writeLines(t, p, []string{
		`2026-09-29T10:00:00Z MCP-ASK id=ap-1 machine="alice+office desk" detail="echo a=b"`,
		`2026-09-29T10:00:01Z SESSION-START user=alice id=s1 mode=exec`,
	})
	st, err := Scan(p, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Events["MCP-ASK"] != 1 || st.Sessions != 1 || st.SessionsOpen() != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestScanMissingFile(t *testing.T) {
	st, err := Scan(filepath.Join(t.TempDir(), "nope.log"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Sessions != 0 || len(st.Events) != 0 {
		t.Fatalf("%+v", st)
	}
	if _, err := Scan("", time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestScanBadLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	writeLines(t, p, []string{
		`garbage line without timestamp`,
		`2026-09-29T10:00:00Z`, // 只有时间没有事件
		`2026-09-29T10:00:01Z SESSION-START user=alice id=s1`,
	})
	st, err := Scan(p, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Sessions != 1 {
		t.Fatalf("%+v", st)
	}
}
