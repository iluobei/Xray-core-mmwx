package internet

import (
	"net"
	"strings"
	"testing"

	"github.com/pires/go-proxyproto"
)

// 「偷自己 tunnel 模式」下 443 上的 dokodemo 把流量转到本机内部端口,
// 内部端口看到的源地址因此变成 127.0.0.1 —— 流量明细里的连接 IP 全错,
// 而 agent 的 IP 上限判定用的是同一个源 IP,ip_limit 跟着静默失效。
//
// 直接开 accept_proxy_protocol 能拿回真实 IP,但它是 proxyproto.REQUIRE:
// 不带 PROXY 头的连接一律拒 —— 仍在直连内部端口的老订阅会被全部打断。
//
// 宽容模式解决这个:本机来的有头就用、没头也放行;外部来的一律忽略其头
// (否则任何人都能伪造源 IP 绕过 IP 上限)。
func TestProxyProtocolPolicy(t *testing.T) {
	cases := []struct {
		name              string
		accept, trustLoop bool
		upstream          net.Addr
		want              proxyproto.Policy
		wantEnabled       bool
	}{
		{"两个都关 → 完全不启用", false, false, tcpAddr("1.2.3.4"), 0, false},

		{"只开 accept:本机 → REQUIRE(维持原语义)", true, false, tcpAddr("127.0.0.1"), proxyproto.REQUIRE, true},
		{"只开 accept:外部 → REQUIRE(CDN 场景就是靠它挡直连)", true, false, tcpAddr("1.2.3.4"), proxyproto.REQUIRE, true},

		{"宽容模式:本机 → USE(有头就用,没头也放行)", false, true, tcpAddr("127.0.0.1"), proxyproto.USE, true},
		{"宽容模式:IPv6 本机 → USE", false, true, tcpAddr("::1"), proxyproto.USE, true},
		{"宽容模式:4in6 本机 → USE", false, true, tcpAddr("::ffff:127.0.0.1"), proxyproto.USE, true},
		// 这一条是安全要害:外部连接若能让 PROXY 头生效,任何人都能伪造源 IP,
		// IP 上限、封禁、风控全部可被绕过。
		{"宽容模式:外部 → IGNORE(绝不采信外部的头)", false, true, tcpAddr("1.2.3.4"), proxyproto.IGNORE, true},
		{"宽容模式:内网非本机 → IGNORE", false, true, tcpAddr("192.168.1.5"), proxyproto.IGNORE, true},

		// 两个都开时以严格的为准:显式配了 accept 就是要 REQUIRE 的语义。
		{"两个都开:外部 → REQUIRE", true, true, tcpAddr("1.2.3.4"), proxyproto.REQUIRE, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fn, enabled := proxyProtocolPolicyFor(&SocketConfig{
				AcceptProxyProtocol:        c.accept,
				TrustLoopbackProxyProtocol: c.trustLoop,
			})
			if enabled != c.wantEnabled {
				t.Fatalf("enabled = %v, 期望 %v", enabled, c.wantEnabled)
			}
			if !enabled {
				return
			}
			got, err := fn(c.upstream)
			if err != nil {
				t.Fatalf("policy 返回错误: %v", err)
			}
			if got != c.want {
				t.Errorf("policy = %v, 期望 %v", got, c.want)
			}
		})
	}
}

// upstream 拿不到(nil / 非 TCP)时不能当成本机 —— 那等于给伪造开了口子。
func TestProxyProtocolPolicyUnknownUpstreamIsNotLoopback(t *testing.T) {
	fn, enabled := proxyProtocolPolicyFor(&SocketConfig{TrustLoopbackProxyProtocol: true})
	if !enabled {
		t.Fatal("宽容模式应启用")
	}
	for _, addr := range []net.Addr{nil, &net.UnixAddr{Name: "/tmp/x", Net: "unix"}} {
		got, _ := fn(addr)
		if got != proxyproto.IGNORE {
			t.Errorf("upstream=%v 应按外部处理(IGNORE),得到 %v", addr, got)
		}
	}
}

func tcpAddr(ip string) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345}
}

// 宽容模式必须真的放行「没有 PROXY 头」的本机连接 —— 这是它与 REQUIRE 的全部区别,
// 也是老订阅直连内部端口不被打断的依据。这里跑真实的 listener,不是只测策略函数。
func TestTolerantModeAcceptsBothHeaderedAndPlain(t *testing.T) {
	fn, enabled := proxyProtocolPolicyFor(&SocketConfig{TrustLoopbackProxyProtocol: true})
	if !enabled {
		t.Fatal("宽容模式应启用")
	}
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &proxyproto.Listener{Listener: base, Policy: fn}
	defer l.Close()

	type result struct {
		remote string
		err    error
	}
	accepted := make(chan result, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, aerr := l.Accept()
			if aerr != nil {
				accepted <- result{err: aerr}
				continue
			}
			buf := make([]byte, 4)
			_, rerr := c.Read(buf) // 触发头解析
			accepted <- result{remote: c.RemoteAddr().String(), err: rerr}
			c.Close()
		}
	}()

	// ① 带 PROXY v1 头(模拟 tunnel 那一跳):真实客户端 IP 必须被还原
	c1, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c1.Write([]byte("PROXY TCP4 203.0.113.7 10.0.0.1 56324 443\r\nping"))
	r1 := <-accepted
	if r1.err != nil {
		t.Fatalf("带头的连接被拒了: %v", r1.err)
	}
	if !strings.HasPrefix(r1.remote, "203.0.113.7:") {
		t.Errorf("没还原出真实客户端 IP,得到 %q", r1.remote)
	}
	c1.Close()

	// ② 不带头(老订阅直连):必须照常放行,而不是像 REQUIRE 那样被拒
	c2, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c2.Write([]byte("ping"))
	r2 := <-accepted
	if r2.err != nil {
		t.Fatalf("不带头的连接被拒了 —— 这正是 REQUIRE 打断老客户端的原因: %v", r2.err)
	}
	if !strings.HasPrefix(r2.remote, "127.0.0.1:") {
		t.Errorf("不带头时应保留真实 socket 地址,得到 %q", r2.remote)
	}
	c2.Close()
}
