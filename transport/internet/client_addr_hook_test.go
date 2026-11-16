package internet

import (
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/pires/go-proxyproto"
)

type fakeAddrHook struct {
	mu      sync.Mutex
	listen  map[int][]netip.Prefix
	closed  []int
	answer  *net.TCPAddr
	queried int
}

func (f *fakeAddrHook) ListenTrusted(port int, trusted []netip.Prefix) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listen == nil {
		f.listen = map[int][]netip.Prefix{}
	}
	f.listen[port] = trusted
}

func (f *fakeAddrHook) CloseTrusted(port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, port)
}

func (f *fakeAddrHook) Resolve(remote, local *net.TCPAddr) (*net.TCPAddr, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queried++
	if f.answer == nil {
		return nil, false
	}
	return f.answer, true
}

func TestClientAddrListenerResolvesTrustedOnly(t *testing.T) {
	hook := &fakeAddrHook{answer: &net.TCPAddr{IP: net.ParseIP("42.120.103.239"), Port: 58733}}
	RegisterClientAddrHook(hook)
	defer RegisterClientAddrHook(nil)

	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := raw.Addr().(*net.TCPAddr).Port

	// 可信来源是本机:连接的 RemoteAddr 换成钩子给的地址
	l := wrapClientAddrListener(raw, parseTrustedSources([]string{"127.0.0.1"}))
	if got := hook.listen[port]; len(got) != 1 {
		t.Fatalf("ListenTrusted 没被调用:%v", hook.listen)
	}
	go func() {
		c, err := net.Dial("tcp4", raw.Addr().String())
		if err == nil {
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RemoteAddr().String(); got != "42.120.103.239:58733" {
		t.Fatalf("RemoteAddr = %s", got)
	}
	_ = c.RemoteAddr()
	if hook.queried != 1 {
		t.Fatalf("查到之后不该再查:queried=%d", hook.queried)
	}
	c.Close()
	l.Close()
	if len(hook.closed) != 1 || hook.closed[0] != port {
		t.Fatalf("CloseTrusted = %v", hook.closed)
	}

	// 来源不在可信列表:不查、不换
	raw2, _ := net.Listen("tcp4", "127.0.0.1:0")
	l2 := wrapClientAddrListener(raw2, parseTrustedSources([]string{"10.0.0.0/8"}))
	go func() {
		c, err := net.Dial("tcp4", raw2.Addr().String())
		if err == nil {
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	c2, err := l2.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if ra := c2.RemoteAddr().(*net.TCPAddr); !ra.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("不可信来源不该换地址:%s", ra)
	}
	c2.Close()
	l2.Close()
}

func TestClientAddrListenerNoHook(t *testing.T) {
	RegisterClientAddrHook(nil)
	raw, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer raw.Close()
	if l := wrapClientAddrListener(raw, parseTrustedSources([]string{"127.0.0.1"})); l != raw {
		t.Fatal("没有钩子时应原样返回")
	}
}

// 只认 TOA 的出口:任何来源的 PROXY 头都忽略(读掉),包括可信来源。
func TestProxyProtocolPolicyTOAOnly(t *testing.T) {
	trusted := []string{"192.0.2.1"}
	from := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 4000}
	f, ok := proxyProtocolPolicyFor(&SocketConfig{TrustedProxyProtocolSources: trusted})
	if !ok {
		t.Fatal("配了可信来源应启用")
	}
	if p, _ := f(from); p != proxyproto.USE {
		t.Fatalf("可信来源平时用头:%v", p)
	}
	f, ok = proxyProtocolPolicyFor(&SocketConfig{TrustedProxyProtocolSources: trusted, TrustedProxyProtocolToaOnly: true})
	if !ok {
		t.Fatal("只认 TOA 时仍要包装(要把头读掉)")
	}
	if p, _ := f(from); p != proxyproto.IGNORE {
		t.Fatalf("只认 TOA 时可信来源的头也忽略:%v", p)
	}
}
