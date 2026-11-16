package internet

import (
	"net"
	"net/netip"

	"github.com/pires/go-proxyproto"
)

// PROXY protocol 的接收策略。
//
// accept_proxy_protocol 一直是 proxyproto.REQUIRE:不带 PROXY 头的连接一律拒。
// 放在 CDN / nginx 后面时这正合适 —— 顺带把直连也挡了。
//
// 但「偷自己 tunnel 模式」不是那个场景:443 上的 dokodemo 把流量转到本机内部端口,
// 内部端口因此只看得到 127.0.0.1(流量明细里的连接 IP 全错,agent 的 IP 上限判定
// 用的是同一个源地址,ip_limit 跟着静默失效)。而那个内部端口同时还可能被老订阅直连,
// 用 REQUIRE 会把他们全部打断。
//
// trust_loopback_proxy_protocol 就是为这个场景加的宽容模式:
//   - 本机来的连接:有 PROXY 头就用(拿回真实客户端 IP),没有也照常放行;
//   - 外部来的连接:一律忽略其 PROXY 头。
//
// 最后这条是安全要害。内部端口是监听在 0.0.0.0 上的,如果外部连接的 PROXY 头也生效,
// 任何人都能自称来自任意 IP —— IP 上限、封禁、风控就全都可以绕过。
// 所以「信任」必须以来源是本机为前提,而这个前提由内核保证,伪造不了。

// trusted_proxy_protocol_sources 是同一个宽容模式,只是「可信」从本机扩展到一组指定来源:
// 转发链出口的前一跳是链上自己的服务器(公网地址),由它们在连接开头补 PROXY 头带来客户端真实 IP。
// 列表里的来源有头就用、没头放行;列表外的来源头被读掉并忽略 —— 与上面同一条安全要害。
//
// 判断来源用的是连接的 RemoteAddr:宿主钩子(client_addr_hook.go)查到 TOA 时它已经是真实客户端地址,
// 不在列表里,头就被忽略 —— 带 TOA 的连接以 TOA 为准。
//
// trusted_proxy_protocol_toa_only:转发链入口走内核转发(TOA)时,客户端发的字节原样到出口,客户端自己写的
// PROXY 头也跟着过来;连接若没带上 TOA(插不进去、被线路剥掉),来源就是上一跳,头会被当成可信的。
// 这种出口所有来源的头都读掉忽略,真实地址只从 TOA 来。

// proxyProtocolPolicyFor 返回该 socket 配置对应的策略函数;enabled=false 表示压根不用包装。
func proxyProtocolPolicyFor(sockopt *SocketConfig) (func(net.Addr) (proxyproto.Policy, error), bool) {
	if sockopt == nil {
		return nil, false
	}
	trusted := parseTrustedSources(sockopt.TrustedProxyProtocolSources)
	if !sockopt.AcceptProxyProtocol && !sockopt.TrustLoopbackProxyProtocol && len(trusted) == 0 {
		return nil, false
	}
	// 显式配了 accept_proxy_protocol 就按它的老语义来(REQUIRE),
	// 免得升级后原有部署的行为悄悄变松。
	if sockopt.AcceptProxyProtocol {
		return func(net.Addr) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil }, true
	}
	if sockopt.TrustedProxyProtocolToaOnly {
		return func(net.Addr) (proxyproto.Policy, error) { return proxyproto.IGNORE, nil }, true
	}
	loopback := sockopt.TrustLoopbackProxyProtocol
	return func(upstream net.Addr) (proxyproto.Policy, error) {
		if loopback && isLoopbackAddr(upstream) {
			return proxyproto.USE, nil
		}
		if a, ok := tcpAddrIP(upstream); ok {
			for _, p := range trusted {
				if p.Contains(a) {
					return proxyproto.USE, nil
				}
			}
		}
		return proxyproto.IGNORE, nil
	}, true
}

// parseTrustedSources 把「IP 或 CIDR」列表解析成前缀;写错的项直接跳过(只会少信任,不会多信任)。
func parseTrustedSources(list []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// tcpAddrIP 取连接来源的 IP(IPv4-mapped 的 v6 地址还原成 v4,与列表里写的 v4 地址能对上)。
func tcpAddrIP(addr net.Addr) (netip.Addr, bool) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp == nil || tcp.IP == nil {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// isLoopbackAddr 这个来源是不是本机。拿不到 IP(nil、unix socket 等)一律当**不是** ——
// 判错方向只有一个是危险的:把外部当本机就等于给伪造源 IP 开了口子。
func isLoopbackAddr(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp == nil || tcp.IP == nil {
		return false
	}
	a, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return false
	}
	return a.Unmap().IsLoopback()
}
