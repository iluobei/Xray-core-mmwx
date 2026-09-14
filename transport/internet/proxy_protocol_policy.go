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

// proxyProtocolPolicyFor 返回该 socket 配置对应的策略函数;enabled=false 表示压根不用包装。
func proxyProtocolPolicyFor(sockopt *SocketConfig) (func(net.Addr) (proxyproto.Policy, error), bool) {
	if sockopt == nil || (!sockopt.AcceptProxyProtocol && !sockopt.TrustLoopbackProxyProtocol) {
		return nil, false
	}
	// 显式配了 accept_proxy_protocol 就按它的老语义来(REQUIRE),
	// 免得升级后原有部署的行为悄悄变松。
	if sockopt.AcceptProxyProtocol {
		return func(net.Addr) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil }, true
	}
	return func(upstream net.Addr) (proxyproto.Policy, error) {
		if isLoopbackAddr(upstream) {
			return proxyproto.USE, nil
		}
		return proxyproto.IGNORE, nil
	}, true
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
