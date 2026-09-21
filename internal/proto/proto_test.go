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
