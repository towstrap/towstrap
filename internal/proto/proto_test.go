package proto

import (
	"bytes"
	"testing"
)

func TestValidName(t *testing.T) {
	for _, ok := range []string{"office", "home-1", "a.b_c", "AbC123"} {
		if !ValidName(ok) {
			t.Errorf("%q 应合法", ok)
		}
	}
	for _, bad := range []string{"", "a b", "a/b", "名字"} {
		if ValidName(bad) {
			t.Errorf("%q 应不合法", bad)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	if got := SanitizeName("我的 Mac Book"); got != "Mac-Book" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizeName("office"); got != "office" {
		t.Fatalf("got %q", got)
	}
}

func TestDataRoundtrip(t *testing.T) {
	payload := []byte("hello\x00world")
	m := EncodeData("s1", payload)
	if m.T != TypeData || m.ID != "s1" {
		t.Fatalf("%#v", m)
	}
	got, err := m.Payload()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestFromField(t *testing.T) {
	m := Msg{T: TypeOpen, ID: "s1", Cols: 80, Rows: 24, From: "alice@1.2.3.4"}
	got, err := Decode(m.Bytes())
	if err != nil || got.From != "alice@1.2.3.4" {
		t.Fatalf("%#v err=%v", got, err)
	}
	// 没有来源时不应在 JSON 里占字段
	raw := Msg{T: TypeHello, Name: "box"}.Bytes()
	if bytes.Contains(raw, []byte(`"from"`)) {
		t.Fatalf("空 from 不应出现在 JSON 里: %s", raw)
	}
}

func TestDecode(t *testing.T) {
	m, err := Decode([]byte(`{"t":"hello","name":"office"}`))
	if err != nil || m.T != TypeHello || m.Name != "office" {
		t.Fatalf("%#v err=%v", m, err)
	}
}

func TestNewFieldsRoundtrip(t *testing.T) {
	open := Msg{T: TypeOpen, ID: "s1", Pty: true, Cmd: "go test ./..."}
	got, err := Decode(open.Bytes())
	if err != nil || !got.Pty || got.Cmd != "go test ./..." {
		t.Fatalf("%#v err=%v", got, err)
	}
	// close 带退出码
	cl := Msg{T: TypeClose, ID: "s1", Code: 3}
	got, err = Decode(cl.Bytes())
	if err != nil || got.Code != 3 {
		t.Fatalf("%#v err=%v", got, err)
	}
	// 没用到时不占 JSON 字段
	raw := Msg{T: TypeOpen, ID: "s1"}.Bytes()
	for _, k := range []string{`"cmd"`, `"pty"`, `"s"`, `"code"`} {
		if bytes.Contains(raw, []byte(k)) {
			t.Fatalf("零值字段 %s 不应出现在 JSON 里: %s", k, raw)
		}
	}
}

func TestEncodeStream(t *testing.T) {
	payload := []byte("stderr bytes")
	m := EncodeStream("s1", "e", payload)
	if m.T != TypeData || m.S != "e" {
		t.Fatalf("%#v", m)
	}
	got, err := m.Payload()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("got %q err=%v", got, err)
	}
	// EncodeData 是 stdout 流
	if EncodeData("s1", payload).S != "" {
		t.Fatal("EncodeData 不应带流标记")
	}
}
