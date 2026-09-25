//go:build !windows

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSink 测试用的接入方出口：攒输出和退出码。
type fakeSink struct {
	mu    sync.Mutex
	data  []byte
	exits []int
	err   error // 非空时 SendData 返回它（模拟接入方死掉）
}

func (f *fakeSink) SendData(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.data = append(f.data, b...)
	return nil
}

func (f *fakeSink) SendExit(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exits = append(f.exits, code)
}

func (f *fakeSink) Drop(string) {}

func (f *fakeSink) has(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Contains(string(f.data), sub)
}

func (f *fakeSink) exitCodes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.exits...)
}

func waitCond(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("没等到: %s", what)
}

// TestMirrorFanout 多接入扇出 + 重放：s1 先接入看到输出，s2 后接入靠重放
// 补齐之前的输出，之后实时输出两边都收到；s1 脱离后不再收新输出。
func TestMirrorFanout(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	tu, created, err := m.open("w1", "cat", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("第一次 open 应是新建")
	}
	s1 := &fakeSink{}
	if err := tu.attach("s1", s1, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := tu.write([]byte("hello-one\n")); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 5*time.Second, "s1 收到回显", func() bool { return s1.has("hello-one") })

	s2 := &fakeSink{}
	if err := tu.attach("s2", s2, 0, 0); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 2*time.Second, "s2 接入时重放出之前的输出", func() bool { return s2.has("hello-one") })
	if err := tu.write([]byte("hello-two\n")); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 5*time.Second, "s1/s2 都收到新输出", func() bool {
		return s1.has("hello-two") && s2.has("hello-two")
	})

	// s1 脱离：进程活着，s2 继续收，s1 停在原处
	tu.detach("s1")
	if err := tu.write([]byte("hello-three\n")); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 5*time.Second, "s2 收到 s1 脱离后的输出", func() bool { return s2.has("hello-three") })
	if s1.has("hello-three") {
		t.Fatal("s1 已脱离不应再收输出")
	}

	// 同名再 open 是接入不是新建
	tu2, created, err := m.open("w1", "ignored-cmd", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if created || tu2 != tu {
		t.Fatal("同名 open 应接入已有镜像")
	}
	if !m.kill("w1") {
		t.Fatal("kill 应成功")
	}
	waitCond(t, 5*time.Second, "s2 收到退出通知", func() bool { return len(s2.exitCodes()) > 0 })
}

// TestMirrorNaturalExit 进程自己退出：接入方收到退出码，登记处把它摘掉。
func TestMirrorNaturalExit(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	tu, _, err := m.open("bye", "sleep 0.2; exit 7", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSink{}
	if err := tu.attach("s", s, 0, 0); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 5*time.Second, "退出码 7", func() bool {
		for _, c := range s.exitCodes() {
			if c == 7 {
				return true
			}
		}
		return false
	})
	waitCond(t, 2*time.Second, "登记处摘掉 bye", func() bool { return m.get("bye") == nil })
	// 名字空出来后同名 open 是全新创建
	tu2, created, err := m.open("bye", "cat", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if !created || tu2 == tu {
		t.Fatal("退出后同名应是新镜像")
	}
	m.kill("bye")
}

// TestMirrorValidation 名字不合法直接拒；到上限也拒（不真起进程，直接塞满表）。
func TestMirrorValidation(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	for _, bad := range []string{"", "a/b", "a b", "中文", strings.Repeat("x", 65)} {
		if _, _, err := m.open(bad, "cat", "", 80, 24); err == nil {
			t.Fatalf("名字 %q 应被拒", bad)
		}
	}
	for i := 0; i < maxMirrors; i++ {
		m.mirrors[string(rune('a'+i%26))+string(rune('a'+i/26))] = &mirror{}
	}
	if _, _, err := m.open("overflow", "cat", "", 80, 24); err == nil {
		t.Fatal("超过上限应被拒")
	}
}

// TestMirrorReplayCap 输出留档有上限：超出后只留尾部，新接入方拿到的是尾部。
func TestMirrorReplayCap(t *testing.T) {
	tu := &mirror{name: "x", atts: make(map[string]*mirrorAtt)}
	chunk := make([]byte, mirrorReplayBytes)
	for i := range chunk {
		chunk[i] = 'a' + byte(i%26)
	}
	tu.broadcast(chunk)
	tu.broadcast([]byte("TAIL-MARKER"))
	tu.mu.Lock()
	n := len(tu.buf)
	tu.mu.Unlock()
	if n != mirrorReplayBytes {
		t.Fatalf("留档应封顶 %d，实际 %d", mirrorReplayBytes, n)
	}
	s := &fakeSink{}
	if err := tu.attach("s", s, 0, 0); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 2*time.Second, "重放发完", func() bool { return s.has("TAIL-MARKER") })
	s.mu.Lock()
	got := s.data
	s.mu.Unlock()
	if len(got) != mirrorReplayBytes || !strings.HasSuffix(string(got), "TAIL-MARKER") {
		t.Fatalf("重放应是留档尾部 %d 字节且以标记结尾，实际 %d", mirrorReplayBytes, len(got))
	}
}

// TestMirrorReplayBoundary 留档按字节截断，截断点可能落在转义序列中间——
// 那截序列尾巴会被接入方的终端打成可见文字（乱码）。截断必须避开序列
// 中间：从被截到的那条序列的开头截，整条保住。
func TestMirrorReplayBoundary(t *testing.T) {
	tu := &mirror{name: "x", atts: make(map[string]*mirrorAtt)}
	// 序列在留档最前面、padding 塞满：截断点落在 \x1b[?1049h 的中间
	b := append([]byte("\x1b[?1049h"), bytes.Repeat([]byte("x"), mirrorReplayBytes-4)...)
	tu.broadcast(b)
	s := &fakeSink{}
	if err := tu.attach("s", s, 0, 0); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 2*time.Second, "重放发出", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.data) > 0
	})
	s.mu.Lock()
	got := append([]byte(nil), s.data...)
	s.mu.Unlock()
	if !bytes.HasPrefix(got, []byte("\x1b[?1049h")) {
		t.Fatalf("重放从半截序列开头（会被打成可见文字）: %q", got[:min(16, len(got))])
	}
}

// TestMirrorReplayStripsQueries 历史输出里的终端查询序列（DSR/DA/模式询问/
// OSC 询问/DCS 请求）不进重放：回放了它们，新接入方的终端会把应答打进
// 共享 PTY 的输入——别的接入方就看到一串幽灵输入/乱码。
func TestMirrorReplayStripsQueries(t *testing.T) {
	tu := &mirror{name: "x", atts: make(map[string]*mirrorAtt)}
	tu.broadcast([]byte("out\x1b[6nmore\x1b[c C\x1b]10;?\x07D\x1bP$qxy\x1b\\E\x1b[?1049$pF"))
	s := &fakeSink{}
	if err := tu.attach("s", s, 0, 0); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 2*time.Second, "重放发完", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.data) > 0
	})
	s.mu.Lock()
	got := string(s.data)
	s.mu.Unlock()
	for _, q := range []string{"\x1b[6n", "\x1b[c", "\x1b]10;?", "$q", "\x1b[?1049$p"} {
		if strings.Contains(got, q) {
			t.Fatalf("重放里不该有终端查询序列 %q: %q", q, got)
		}
	}
	for _, keep := range []string{"out", "more", "C", "D", "E", "F"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("重放丢了正常内容 %q: %q", keep, got)
		}
	}
}

// TestStripTermQueries 单元层：各类查询序列被剥、正常序列和文本原样过。
func TestStripTermQueries(t *testing.T) {
	in := "a\x1b[5n" + "b\x1b[6n" + "c\x1b[c" + "d\x1b[>0c" + "e\x1b[=c" +
		"f\x1b]4;0;?\x07" + "g\x1b]10;?\x1b\\" + "h\x1b]52;;?\x07" +
		"i\x1bP$qx\x1b\\" + "j\x1bP+q7473\x1b\\" + "k\x1bZ" +
		"l\x1b[?1049$p" + "m\x1b[?u" + "n\x1b[?25u"
	out := stripTermQueries([]byte(in))
	if out := string(out); out != "abcdefghijklmn" {
		t.Fatalf("查询序列应全剥掉: %q", out)
	}
	// 不是查询的序列原样保留
	keep := "\x1b[1;1H\x1b[?1049h\x1b[0m\x1b]8;;https://x\x07link\x1b]8;;\x07\x1b[>1u\x1b[2J"
	if out := string(stripTermQueries([]byte(keep))); out != keep {
		t.Fatalf("正常序列被动了: %q", out)
	}
	// 混在文本里
	mixed := "前\x1b[6n后\x1b[?1049h文"
	if out := string(stripTermQueries([]byte(mixed))); out != "前后\x1b[?1049h文" {
		t.Fatalf("混合内容剥错: %q", out)
	}
}

// blockSink 模拟卡死的接入方（手机断网、ssh 客户端被挂起）：SendData
// 永远不返回，直到 Drop 被调用。
type blockSink struct {
	release chan struct{}
	once    sync.Once
	dropped chan struct{}
}

func newBlockSink() *blockSink {
	return &blockSink{release: make(chan struct{}), dropped: make(chan struct{})}
}
func (b *blockSink) SendData([]byte) error { <-b.release; return errDropped }
func (b *blockSink) SendExit(int)          {}
func (b *blockSink) Drop(string) {
	b.once.Do(func() { close(b.dropped); close(b.release) })
}

// TestMirrorSlowSinkIsolated 一个接入方卡死不能拖垮别人：其他接入照常收
// 输出，登记处（ls/open）照常响应；积压超限的卡死接入被踢掉。
func TestMirrorSlowSinkIsolated(t *testing.T) {
	old := mirrorAttQueue
	mirrorAttQueue = 8
	defer func() { mirrorAttQueue = old }()

	m := newMirrorManager("/bin/sh")
	tu, _, err := m.open("slow", "cat", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer m.kill("slow")
	stuck := newBlockSink()
	if err := tu.attach("stuck", stuck, 0, 0); err != nil {
		t.Fatal(err)
	}
	ok := &fakeSink{}
	if err := tu.attach("ok", ok, 0, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if err := tu.write([]byte("line-" + strings.Repeat("x", i) + "\n")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitCond(t, 5*time.Second, "正常接入方收到输出", func() bool { return ok.has("line-" + strings.Repeat("x", 49)) })
	done := make(chan struct{})
	go func() { m.list(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("一个接入卡死把登记处也卡住了")
	}
	select {
	case <-stuck.dropped:
	case <-time.After(5 * time.Second):
		t.Fatal("积压超限的卡死接入应被踢掉")
	}
}

// TestMirrorExitWithBackgroundJob 主进程退出但后台任务（忽略挂断信号）还攥着
// 终端：镜像也要按主进程退出结束，不能一直挂在登记处里。Linux 上后台任务
// 会让读端永远等不到 EOF；macOS 会强制收回终端，这条在 mac 上本来就过。
func TestMirrorExitWithBackgroundJob(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	tu, _, err := m.open("bg", "trap '' HUP; sleep 30 & exit 3", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSink{}
	if err := tu.attach("s", s, 0, 0); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 5*time.Second, "退出码 3", func() bool {
		c := s.exitCodes()
		return len(c) > 0 && c[0] == 3
	})
	waitCond(t, 2*time.Second, "登记处摘掉 bg", func() bool { return m.get("bg") == nil })
}

// TestMirrorDetachRestoresSize 手机（小屏）接入后脱离：尺寸退回桌面那边的。
func TestMirrorDetachRestoresSize(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	tu, _, err := m.open("sz", "cat", "", 120, 40)
	if err != nil {
		t.Fatal(err)
	}
	defer m.kill("sz")
	if err := tu.attach("desk", &fakeSink{}, 120, 40); err != nil {
		t.Fatal(err)
	}
	if err := tu.attach("phone", &fakeSink{}, 60, 20); err != nil {
		t.Fatal(err)
	}
	if i := tu.info(); i.Cols != 60 || i.Rows != 20 {
		t.Fatalf("手机接入后应是 60x20，实际 %dx%d", i.Cols, i.Rows)
	}
	tu.resize("desk", 130, 45) // 桌面那边拖了下窗口
	tu.resize("phone", 61, 21) // 手机更晚动过
	tu.detach("phone")
	if i := tu.info(); i.Cols != 130 || i.Rows != 45 {
		t.Fatalf("手机脱离后应退回桌面的 130x45，实际 %dx%d", i.Cols, i.Rows)
	}
}

// TestMirrorKillWithStubbornChild kill 时里面有忽略挂断信号的后台任务攥着
// 终端：也要能终结，不能卡在读端上。
func TestMirrorKillWithStubbornChild(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	tu, _, err := m.open("stub", "trap '' HUP; sleep 30 & cat", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSink{}
	if err := tu.attach("s", s, 100, 30); err != nil { // 带尺寸：走一次 resize
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	m.kill("stub")
	waitCond(t, 5*time.Second, "kill 后收到退出", func() bool { return len(s.exitCodes()) > 0 })
	waitCond(t, 2*time.Second, "登记处摘掉 stub", func() bool { return m.get("stub") == nil })
}

// TestMirrorIdleSweep 闲置超时的镜像被终结并从登记处摘掉；有活动的留下；
// 还接着的接入方收到退出通知。
func TestMirrorIdleSweep(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	m.idleTTL = 200 * time.Millisecond
	old, _, err := m.open("old", "cat", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSink{}
	if err := old.attach("s", s, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.open("fresh", "cat", "", 80, 24); err != nil {
		t.Fatal(err)
	}
	defer m.kill("fresh")
	old.mu.Lock()
	old.lastIO = time.Now().Add(-time.Hour)
	old.mu.Unlock()

	m.sweepIdle()
	waitCond(t, 5*time.Second, "闲置镜像被摘掉", func() bool { return m.get("old") == nil })
	waitCond(t, 5*time.Second, "接入方收到退出", func() bool { return len(s.exitCodes()) > 0 })
	if m.get("fresh") == nil {
		t.Fatal("有活动的镜像不该被扫掉")
	}
	// 再扫一轮：不 panic、不误伤
	m.sweepIdle()
	if m.get("fresh") == nil {
		t.Fatal("重复清扫误伤了新镜像")
	}
}

// TestMirrorIdleInputCounts 敲键也算活动：程序不回显的输入同样刷新 lastIO，
// 不会被误当成闲置杀掉。
func TestMirrorIdleInputCounts(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	m.idleTTL = 300 * time.Millisecond
	tu, _, err := m.open("typing", "cat", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer m.kill("typing")
	tu.mu.Lock()
	tu.lastIO = time.Now().Add(-time.Hour)
	tu.mu.Unlock()
	if err := tu.write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	m.sweepIdle()
	if m.get("typing") == nil {
		t.Fatal("刚敲过键的镜像不应被扫掉")
	}
}

// TestMirrorIdleDisabled idleTTL=0 不启用清扫：再老也不杀。
func TestMirrorIdleDisabled(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	tu, _, err := m.open("keep", "cat", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer m.kill("keep")
	tu.mu.Lock()
	tu.lastIO = time.Now().Add(-24 * time.Hour)
	tu.mu.Unlock()
	m.sweepIdle()
	if m.get("keep") == nil {
		t.Fatal("idleTTL=0 时不应清扫")
	}
}

// TestMirrorAttachExited 已退出的镜像不再接受接入。
func TestMirrorAttachExited(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	tu := &mirror{name: "dead", m: m, atts: make(map[string]*mirrorAtt)}
	tu.exited = true
	if err := tu.attach("s", &fakeSink{}, 0, 0); err == nil {
		t.Fatal("已退出的镜像应拒绝接入")
	}
}

// TestMirrorSock 本机 socket 全流程：ls → attach(cat) → 输入回显 → detach →
// 再接入 → kill。serveMirrorConn 跑在 net.Pipe 上，不走文件系统。
func TestMirrorSock(t *testing.T) {
	m := newMirrorManager("/bin/sh")
	cli, srv := net.Pipe()
	defer cli.Close()
	go serveMirrorConn(srv, m, nil)
	dec := json.NewDecoder(cli)
	enc := json.NewEncoder(cli)

	// ls：空的
	if err := enc.Encode(mirrorSockMsg{Op: "ls"}); err != nil {
		t.Fatal(err)
	}
	var m1 mirrorSockMsg
	if err := dec.Decode(&m1); err != nil {
		t.Fatal(err)
	}
	if !m1.OK || len(m1.Mirrors) != 0 {
		t.Fatalf("初始 ls 应为空: %+v", m1)
	}
	_ = cli.Close()

	// attach：新建名为 work 的 cat
	cli, srv = net.Pipe()
	defer cli.Close()
	go serveMirrorConn(srv, m, nil)
	dec = json.NewDecoder(cli)
	enc = json.NewEncoder(cli)
	if err := enc.Encode(mirrorSockMsg{Op: "attach", Name: "work", Cmd: "cat", Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	var ack mirrorSockMsg
	if err := dec.Decode(&ack); err != nil {
		t.Fatal(err)
	}
	if !ack.OK || !ack.Created {
		t.Fatalf("attach 应答不对: %+v", ack)
	}
	// 输入一行 → cat（和 PTY 回显）把它送回来
	if err := enc.Encode(mirrorSockMsg{D: base64.StdEncoding.EncodeToString([]byte("sock-hi\n"))}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	got := ""
	for time.Now().Before(deadline) && !strings.Contains(got, "sock-hi") {
		_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
		var dm mirrorSockMsg
		if err := dec.Decode(&dm); err != nil {
			t.Fatalf("读输出失败: %v（已收到 %q）", err, got)
		}
		if dm.D != "" {
			b, _ := base64.StdEncoding.DecodeString(dm.D)
			got += string(b)
		}
	}
	if !strings.Contains(got, "sock-hi") {
		t.Fatalf("应收到回显，实际 %q", got)
	}

	// detach：服务端断连，镜像活着
	if err := enc.Encode(mirrorSockMsg{Op: "detach"}); err != nil {
		t.Fatal(err)
	}
	waitCond(t, 2*time.Second, "detach 后连接关闭", func() bool {
		var x mirrorSockMsg
		return dec.Decode(&x) != nil
	})
	if tu := m.get("work"); tu == nil || tu.isExited() {
		t.Fatal("detach 不应杀掉镜像")
	}

	// kill
	cli2, srv2 := net.Pipe()
	defer cli2.Close()
	go serveMirrorConn(srv2, m, nil)
	dec2 := json.NewDecoder(cli2)
	enc2 := json.NewEncoder(cli2)
	if err := enc2.Encode(mirrorSockMsg{Op: "kill", Name: "work"}); err != nil {
		t.Fatal(err)
	}
	var k mirrorSockMsg
	if err := dec2.Decode(&k); err != nil {
		t.Fatal(err)
	}
	if !k.OK {
		t.Fatalf("kill 应答不对: %+v", k)
	}
	waitCond(t, 2*time.Second, "work 被摘", func() bool { return m.get("work") == nil })

	// 再 ls 空了
	cli3, srv3 := net.Pipe()
	defer cli3.Close()
	go serveMirrorConn(srv3, m, nil)
	if err := json.NewEncoder(cli3).Encode(mirrorSockMsg{Op: "ls"}); err != nil {
		t.Fatal(err)
	}
	var m2 mirrorSockMsg
	if err := json.NewDecoder(cli3).Decode(&m2); err != nil {
		t.Fatal(err)
	}
	if len(m2.Mirrors) != 0 {
		t.Fatalf("kill 后 ls 应为空: %+v", m2.Mirrors)
	}
}
