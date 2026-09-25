package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/towstrap/towstrap/internal/proto"
)

var errNotHello = errors.New("not hello")

func helloServer(t *testing.T, timeout time.Duration, got chan<- error) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		m, err := readAgentHello(c, timeout)
		if err != nil {
			got <- err
			return
		}
		if m.T != proto.TypeHello {
			got <- errNotHello
			return
		}
		got <- nil
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialWS(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(strings.Replace(srv.URL, "http", "ws", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestReadAgentHelloTimeout(t *testing.T) {
	got := make(chan error, 1)
	srv := helloServer(t, 50*time.Millisecond, got)
	_ = dialWS(t, srv)
	start := time.Now()
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("沉默连接不应读出 hello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("沉默连接未在限期内返回")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("返回太晚: %v", time.Since(start))
	}
}

func TestReadAgentHelloOK(t *testing.T) {
	got := make(chan error, 1)
	srv := helloServer(t, 3*time.Second, got)
	conn := dialWS(t, srv)
	if err := conn.WriteMessage(websocket.TextMessage, proto.Msg{T: proto.TypeHello, Name: "x"}.Bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("正常 hello 不应报错: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没等到 hello 处理结果")
	}
}
