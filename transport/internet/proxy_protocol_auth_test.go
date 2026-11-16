package internet

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/ppauth"
)

// 可信来源(本机)发来的头:签名有效才采信,没签名 / 签错当成没头,连接都不断、后面的数据照常收到。
func TestTrustedSourcesRequireSignature(t *testing.T) {
	k, _ := ppauth.NewKey(1)
	wrong, _ := ppauth.NewKey(1)
	sockopt := &SocketConfig{
		TrustedProxyProtocolSources:     []string{"127.0.0.1"},
		TrustedProxyProtocolAuthContext: "c13:p42210",
		TrustedProxyProtocolAuthKeys:    []string{k.String()},
	}
	l, err := (&DefaultListener{}).Listen(context.Background(), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, sockopt)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	send := func(sign *ppauth.Key, withHeader bool) (net.Addr, string) {
		t.Helper()
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if withHeader {
			h := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 51000}, l.Addr())
			if sign != nil {
				if err := ppauth.Sign(h, *sign, "c13:p42210", time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.WriteTo(c); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.Write([]byte("hello\n")); err != nil {
			t.Fatal(err)
		}
		s, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		_ = s.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, err := bufio.NewReader(s).ReadString('\n')
		if err != nil {
			t.Fatalf("连接应照常读到数据: %v", err)
		}
		if _, ok := s.(*proxyproto.Conn); !ok {
			t.Fatalf("连接类型应仍是 *proxyproto.Conn,得到 %T", s)
		}
		return s.RemoteAddr(), line
	}

	if addr, line := send(&k, true); addr.String() != "203.0.113.9:51000" || line != "hello\n" {
		t.Fatalf("有效签名应采信: %v %q", addr, line)
	}
	for name, key := range map[string]*ppauth.Key{"没签名": nil, "签错": &wrong} {
		addr, line := send(key, true)
		if host, _, _ := net.SplitHostPort(addr.String()); host != "127.0.0.1" || line != "hello\n" {
			t.Fatalf("%s的头应被忽略、按真实来源: %v %q", name, addr, line)
		}
	}
	if addr, line := send(nil, false); addr.(*net.TCPAddr).IP.String() != "127.0.0.1" || line != "hello\n" {
		t.Fatalf("没头的连接照常: %v %q", addr, line)
	}
}

// 没配密钥:行为与以前完全一样(可信来源的头直接采信)。
func TestTrustedSourcesWithoutKeysUnchanged(t *testing.T) {
	if proxyProtocolAuthFor(&SocketConfig{TrustedProxyProtocolSources: []string{"127.0.0.1"}}) != nil {
		t.Fatal("没配密钥不该挂验签")
	}
	k, _ := ppauth.NewKey(1)
	for _, so := range []*SocketConfig{
		{AcceptProxyProtocol: true, TrustedProxyProtocolAuthKeys: []string{k.String()}},
		{TrustedProxyProtocolToaOnly: true, TrustedProxyProtocolSources: []string{"127.0.0.1"}, TrustedProxyProtocolAuthKeys: []string{k.String()}},
	} {
		if proxyProtocolAuthFor(so) != nil {
			t.Fatalf("老语义 accept_proxy_protocol / 只认 TOA 不该验签: %+v", so)
		}
	}
}
