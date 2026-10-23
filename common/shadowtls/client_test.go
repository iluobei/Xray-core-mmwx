package shadowtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// dialShadowTLS 失败时关掉底层连接(与调用方 snell 出站的行为一致),服务端那头的转发随之结束。
func dialShadowTLS(t *testing.T, addr, password string) (net.Conn, error) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Client(ctx, raw, &ClientConfig{Password: password, ServerName: "handshake.test"})
	if err != nil {
		raw.Close()
		return nil, err
	}
	t.Cleanup(func() { raw.Close() })
	return c, nil
}

// 正式客户端 ↔ 服务端:经一次真实 TLS 1.3 握手(握手服务器会在握手后发 NewSessionTicket,
// 即客户端要丢弃的残帧)后双向收发,大包跨多帧。
func TestClientRoundTrip(t *testing.T) {
	hsAddr, _ := startHandshakeServer(t)
	addr, errs := startServer(t, &Config{Password: testPassword, Handshake: hsAddr, Strict: true})

	c, err := dialShadowTLS(t, addr, testPassword)
	if err != nil {
		t.Fatalf("握手失败: %v", err)
	}
	for i, size := range []int{1, 1000, 40000, 200000} {
		msg := make([]byte, size)
		_, _ = rand.Read(msg)
		go func() { _, _ = c.Write(msg) }()
		if i == 0 {
			if err := <-errs; err != nil {
				t.Fatalf("服务端 Accept: %v", err)
			}
		}
		got := make([]byte, size)
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("读回显(%d): %v", size, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("回显内容不对(%d 字节)", size)
		}
	}
}

// 密码不对:服务端认不出、整条转给握手服务器(ErrFallback);客户端握手虽然能完成,但收不到标记,拒绝继续。
func TestClientWrongPassword(t *testing.T) {
	hsAddr, _ := startHandshakeServer(t)
	addr, errs := startServer(t, &Config{Password: testPassword, Handshake: hsAddr, Strict: true})
	_, err := dialShadowTLS(t, addr, "wrong-password")
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("密码错误应拒绝,得到 %v", err)
	}
	if err := <-errs; err != ErrFallback {
		t.Fatalf("服务端应返回 ErrFallback,得到 %v", err)
	}
}

// 直连握手服务器(中间人把连接劫持到真网站的情形):握手成功但没有标记,客户端必须拒绝。
func TestClientRejectsUnmarkedServer(t *testing.T) {
	hsAddr, _ := startHandshakeServer(t)
	if _, err := dialShadowTLS(t, hsAddr, testPassword); err == nil {
		t.Fatal("对面不是 ShadowTLS 服务端时不应认证成功")
	}
}

// 握手服务器只讲 TLS 1.2:服务端非 strict 会放行,但客户端坚持 TLS 1.3。
func TestClientRequiresTLS13(t *testing.T) {
	hsAddr := startTLS12HandshakeServer(t)
	addr, _ := startServer(t, &Config{Password: testPassword, Handshake: hsAddr, Strict: false})
	_, err := dialShadowTLS(t, addr, testPassword)
	if err == nil || !strings.Contains(err.Error(), "TLS 1.3") {
		t.Fatalf("TLS 1.2 握手服务器应被拒绝,得到 %v", err)
	}
}

// 切换后服务端发来被篡改的帧:客户端校验失败。
func TestClientDetectsTamperedRecord(t *testing.T) {
	hsAddr, _ := startHandshakeServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		inner, err := Accept(context.Background(), raw, &Config{Password: testPassword, Handshake: hsAddr, Strict: true})
		if err != nil {
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(inner, buf); err != nil {
			return
		}
		_, _ = inner.Write(buf) // 一帧正常的
		// 再绕过封装直接写一帧标记错误的
		_, _ = raw.Write([]byte{typeApplicationData, 0x03, 0x03, 0, hmacLen + 3, 1, 2, 3, 4, 'b', 'a', 'd'})
		time.Sleep(2 * time.Second)
	}()

	c, err := dialShadowTLS(t, ln.Addr().String(), testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "hello" {
		t.Fatalf("正常帧: %q %v", got, err)
	}
	if _, err := c.Read(got); err == nil || !strings.Contains(err.Error(), "bad record mac") {
		t.Fatalf("篡改的帧应被拒绝,得到 %v", err)
	}
}

func startTLS12HandshakeServer(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "handshake.test"},
		DNSNames:     []string{"handshake.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}
