package internet

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/reality"
)

// 转发链出口(可信来源 + TOA 钩子)上的 REALITY 入站:REALITY 剥掉 PROXY 头那层后断言原始连接能 CloseWrite,
// v1.3.7 的 clientAddrConn 不带这个方法,来自链上服务器的第一条连接就让整个进程 panic。
func TestClientAddrConnRealityServerNoPanic(t *testing.T) {
	RegisterClientAddrHook(&fakeAddrHook{})
	defer RegisterClientAddrHook(nil)

	// REALITY 的回落目标
	dest, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	go func() {
		if c, err := dest.Accept(); err == nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
	}()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := &proxyproto.Listener{Listener: wrapClientAddrListener(raw, parseTrustedSources([]string{"127.0.0.1"}))}
	defer pl.Close()

	go func() {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			return
		}
		c.Write([]byte("not a tls client hello"))
		c.(*net.TCPConn).CloseWrite()
		io.Copy(io.Discard, c)
		c.Close()
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if pc, ok := conn.(*proxyproto.Conn); !ok {
		t.Fatalf("want *proxyproto.Conn, got %T", conn)
	} else if _, ok := pc.Raw().(*clientAddrConn); !ok {
		t.Fatalf("want clientAddrConn under proxyproto, got %T", pc.Raw())
	}

	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cfg := &reality.Config{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        dest.Addr().String(),
		ServerNames: map[string]bool{"example.com": true},
		PrivateKey:  key,
		ShortIds:    map[[8]byte]bool{{}: true},
		MaxTimeDiff: time.Minute,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := reality.Server(ctx, conn, cfg); err == nil {
		t.Fatal("non-TLS client should fail REALITY auth")
	}
}

func TestClientAddrConnHalfCloseAndUnwrap(t *testing.T) {
	RegisterClientAddrHook(&fakeAddrHook{})
	defer RegisterClientAddrHook(nil)
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	l := wrapClientAddrListener(raw, parseTrustedSources([]string{"127.0.0.1"}))
	defer l.Close()

	cli := make(chan net.Conn, 1)
	go func() { c, _ := net.Dial("tcp", raw.Addr().String()); cli <- c }()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer := <-cli
	defer peer.Close()

	if _, ok := UnwrapClientAddrConn(c).(*net.TCPConn); !ok {
		t.Fatalf("UnwrapClientAddrConn: want *net.TCPConn, got %T", UnwrapClientAddrConn(c))
	}
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("clientAddrConn must expose CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("peer should see EOF after CloseWrite, got n=%d err=%v", n, err)
	}
}
