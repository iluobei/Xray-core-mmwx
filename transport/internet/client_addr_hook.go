package internet

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// 宿主(mmw-agent)提供「内核侧拿到的真实客户端地址」的钩子 —— 目前用于 TOA:
// 转发链入口用 eBPF 在完成握手的 ACK 上插标准 TOA 选项(kind 254,端口 + IPv4),
// 中间跳走内核 nft 转发、选项原样带过来,出口 agent 的 cgroup sock_ops 在连接建立时读出并按
// (对端 IP, 对端端口, 本地端口) 存起来。xray 这边只管两件事:
//   - 配了 trustedProxyProtocolSources 的监听开始 / 结束时告诉宿主(端口 + 可信来源),宿主据此决定读哪些端口、信哪些来源;
//   - 接受连接后按连接查一次,查到就把 RemoteAddr 换成真实客户端。
//
// 安全前提与 PROXY 头一样:只有来自可信来源(链上服务器)的连接才会被换地址 —— 宿主那边的 eBPF 只采信可信来源,
// 这里查表时也只对可信来源的连接查。

// ClientAddrHook 由宿主实现;nil = 不启用。
type ClientAddrHook interface {
	// ListenTrusted 一个配了可信来源的 TCP 监听开始(port 为本地端口)。
	ListenTrusted(port int, trusted []netip.Prefix)
	// CloseTrusted 该监听关闭。
	CloseTrusted(port int)
	// Resolve 按连接查真实客户端地址;查不到返回 false。查到后宿主可以删掉记录(每条连接只查一次)。
	Resolve(remote, local *net.TCPAddr) (*net.TCPAddr, bool)
}

var clientAddrHook atomic.Value // holds clientAddrHookBox

type clientAddrHookBox struct{ h ClientAddrHook }

// RegisterClientAddrHook 宿主启动时调用一次。
func RegisterClientAddrHook(h ClientAddrHook) {
	clientAddrHook.Store(clientAddrHookBox{h: h})
}

func currentClientAddrHook() ClientAddrHook {
	b, _ := clientAddrHook.Load().(clientAddrHookBox)
	return b.h
}

// wrapClientAddrListener 给配了可信来源的 TCP 监听套一层;没有钩子或不是 TCP 时原样返回。
// 套在 PROXY 头那层的里面:连接带了 PROXY 头仍以头为准,没带头时 RemoteAddr 才回落到这里查到的 TOA 地址。
func wrapClientAddrListener(l net.Listener, trusted []netip.Prefix) net.Listener {
	h := currentClientAddrHook()
	if h == nil || len(trusted) == 0 {
		return l
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok || addr == nil {
		return l
	}
	h.ListenTrusted(addr.Port, trusted)
	return &clientAddrListener{Listener: l, hook: h, port: addr.Port, trusted: trusted}
}

type clientAddrListener struct {
	net.Listener
	hook    ClientAddrHook
	port    int
	trusted []netip.Prefix
	once    sync.Once
}

func (l *clientAddrListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	ra, ok1 := c.RemoteAddr().(*net.TCPAddr)
	la, ok2 := c.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 || !l.isTrusted(ra) {
		return c, nil
	}
	return &clientAddrConn{Conn: c, hook: l.hook, raw: ra, local: la, born: time.Now()}, nil
}

func (l *clientAddrListener) Close() error {
	l.once.Do(func() { l.hook.CloseTrusted(l.port) })
	return l.Listener.Close()
}

func (l *clientAddrListener) isTrusted(ra *net.TCPAddr) bool {
	a, ok := tcpAddrIP(ra)
	if !ok {
		return false
	}
	for _, p := range l.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientAddrConn 第一次取 RemoteAddr 时才查(不阻塞 accept 循环)。
// 查不到时先回原始地址,连接建立后的极短时间内再取会重查一次:accept 偶尔比内核那边写表早一点点返回。
type clientAddrConn struct {
	net.Conn
	hook  ClientAddrHook
	raw   *net.TCPAddr
	local *net.TCPAddr
	born  time.Time

	mu       sync.Mutex
	resolved net.Addr
	done     bool
}

func (c *clientAddrConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return c.resolved
	}
	if a, ok := c.hook.Resolve(c.raw, c.local); ok {
		c.resolved, c.done = a, true
		return a
	}
	if time.Since(c.born) > 200*time.Millisecond {
		c.resolved, c.done = c.raw, true
	}
	return c.raw
}
