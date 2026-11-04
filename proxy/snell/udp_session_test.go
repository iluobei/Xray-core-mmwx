// udp_session_test.go:钉住入站的 UDP 会话(命令 0x06)。
//
// 原先两件事不对:
//  1. 会话里所有数据报都被发往第一个数据报的目标,后面数据报自带的地址被忽略(不是 full-cone);
//  2. 目标是域名时应答回不来:出站把来源还原成了域名,而 snell 的回包地址只能写 IP,
//     编码失败 → 丢包,整个会话随即被取消。
//
// 出站那一侧的行为(逐包目标、把首个目标的来源还原成域名)是 freedom 的,拿假的分发器演不像,
// 所以这里起一个进程内的真实例:真的分发器 + freedom,目标是本机的 UDP 回显。
package snell

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/freedom"
	"google.golang.org/protobuf/proto"
)

// freedomDispatcher 起一个只有「分发器 + freedom 出站」的实例,返回它的分发器。
func freedomDispatcher(t *testing.T) routing.Dispatcher {
	t.Helper()
	cfgBytes, err := proto.Marshal(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	instance, err := core.StartInstance("protobuf", cfgBytes)
	if err != nil {
		t.Fatalf("start instance: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
}

// udpEcho 在 127.0.0.1 的随机端口上起一个回显,回的是 "<tag>:<收到的内容>" ——
// 数据报到底进了哪个目标,看前缀就知道。
func udpEcho(t *testing.T, tag string) xnet.Port {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte(tag+":"), b[:n]...), from)
		}
	}()
	return xnet.Port(pc.LocalAddr().(*net.UDPAddr).Port)
}

// openUDP 发 UDP 请求并读回 ReplyTunnel。
func (c *reuseClient) openUDP() {
	c.t.Helper()
	if err := (request{command: commandUDP}).writeTo(c.w); err != nil {
		c.t.Fatalf("发 UDP 请求: %v", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := readServerReply(c.r); err != nil {
		c.t.Fatalf("读 ReplyTunnel: %v", err)
	}
}

func (c *reuseClient) sendDatagram(dest xnet.Destination, payload string) {
	c.t.Helper()
	w := &udpPacketWriter{writer: c.w}
	if err := w.writePacket([]byte(payload), dest); err != nil {
		c.t.Fatalf("发数据报到 %v: %v", dest, err)
	}
}

// expectDatagram:下一个回包的来源与内容都得对上。
func (c *reuseClient) expectDatagram(source xnet.Destination, payload string) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	record, err := c.r.nextRecord()
	if err != nil {
		c.t.Fatalf("等来自 %v 的回包 %q: %v", source, payload, err)
	}
	got, body, err := readUDPResponseAddress(record)
	if err != nil {
		c.t.Fatalf("回包地址解不出来: %v", err)
	}
	if got != source || string(body) != payload {
		c.t.Fatalf("回包对不上: 要 %v %q, 得到 %v %q", source, payload, got, body)
	}
}

func localUDP(port xnet.Port) xnet.Destination {
	return xnet.UDPDestination(xnet.LocalHostIP, port)
}

func localhostUDP(port xnet.Port) xnet.Destination {
	return xnet.UDPDestination(xnet.DomainAddress("localhost"), port)
}

// 域名目标的回显要回得来,来源写的是对端的 IP:port(snell 的回包地址只有 IP 两种)。
func TestSnellUDPDomainTarget(t *testing.T) {
	d := freedomDispatcher(t)
	port := udpEcho(t, "a")

	for _, v := range reuseVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			addr, _ := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), d)
			c := v.dial(t, addr)
			c.openUDP()

			for _, payload := range []string{"one", "two"} {
				c.sendDatagram(localhostUDP(port), payload)
				c.expectDatagram(localUDP(port), "a:"+payload)
			}
		})
	}
}

// full-cone:同一个会话里的数据报各走各的目标(IP 与域名混着来),回包带的是各自目标的来源。
func TestSnellUDPFullCone(t *testing.T) {
	d := freedomDispatcher(t)
	portA, portB := udpEcho(t, "a"), udpEcho(t, "b")

	// 会话的第一个目标是 IP 还是域名,出站一侧的行为不一样(域名的会被还原),两种开头都要过。
	orders := []struct {
		name   string
		a, b   xnet.Destination
		domain string
	}{
		{name: "ip-first", a: localUDP(portA), b: localhostUDP(portB)},
		{name: "domain-first", a: localhostUDP(portA), b: localUDP(portB)},
	}

	for _, v := range reuseVariants {
		for _, o := range orders {
			t.Run(v.name+"/"+o.name, func(t *testing.T) {
				t.Parallel()
				addr, _ := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), d)
				c := v.dial(t, addr)
				c.openUDP()

				for _, payload := range []string{"one", "two", "three"} {
					c.sendDatagram(o.a, payload)
					c.expectDatagram(localUDP(portA), "a:"+payload)
					c.sendDatagram(o.b, payload)
					c.expectDatagram(localUDP(portB), "b:"+payload)
				}
			})
		}
	}
}

// 一个目标解析不了,只丢这一个数据报,会话照常。
func TestSnellUDPBadTargetKeepsSession(t *testing.T) {
	d := freedomDispatcher(t)
	port := udpEcho(t, "a")
	// 标签超过 63 字节不是合法域名,解析器不查网络、当场报错。
	bad := xnet.UDPDestination(xnet.DomainAddress(strings.Repeat("x", 64)+".invalid"), 9)

	for _, v := range reuseVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			addr, _ := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), d)
			c := v.dial(t, addr)
			c.openUDP()

			c.sendDatagram(localUDP(port), "before")
			c.expectDatagram(localUDP(port), "a:before")
			c.sendDatagram(bad, "lost")
			c.sendDatagram(localUDP(port), "after")
			c.expectDatagram(localUDP(port), "a:after")
		})
	}
}
