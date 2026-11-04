// reuse_test.go:钉住入站上「一条流怎么开头、怎么结束」以及 ConnectV2 的连接复用。
//
// 原先几件事都不对:
//  1. 目标先关连接时,服务端既不发结束 record(零长度 record)、也不关 TCP,客户端等不到下行结束,
//     靠「连接关闭」表示响应结束的流量会一直挂到某一头超时;
//  2. ConnectV2(命令 5)的连接从不复用,每个请求结束就关 TCP;
//  3. 应答(ReplyTunnel)在分发之后立刻就回,目标连不上时只能先说「通了」再关连接。
//
// 这里的客户端是直接拿本包的 record 读写器拼的(不经出站),线上每一步收到了什么、连接本身是
// 开着还是被关了,都能逐项断言。
package snell

import (
	"bufio"
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

const (
	reuseEmail = "reuse@x"
	reusePSK   = "reuse-test-psk-0123456789" // v6 要求 12..255 字节
)

// reuseVariant 是入站的一种形态。三个版本、v4 的两种 obfs、v6 的三种 mode 走的 record 读写器
// 各不相同,结束 record 与复用在每一种上都要成立。
type reuseVariant struct {
	name    string
	version uint32
	obfs    obfsMode
	v6Mode  Mode
}

var reuseVariants = []reuseVariant{
	{name: "v4", version: 4},
	{name: "v4+obfs-http", version: 4, obfs: obfsModeHTTP},
	{name: "v4+obfs-tls", version: 4, obfs: obfsModeTLS},
	{name: "v5", version: 5},
	{name: "v6-default", version: 6, v6Mode: ModeDefault},
	{name: "v6-unshaped", version: 6, v6Mode: ModeUnshaped},
	{name: "v6-unsafe-raw", version: 6, v6Mode: ModeUnsafeRaw},
}

var reuseCommands = []struct {
	name    string
	command byte
}{
	{"connect", commandConnect},
	{"connect-v2", commandConnectV2},
}

// timeoutPolicy 是只改超时的 policy.Manager。默认的 UplinkOnly / DownlinkOnly 都是 1 秒:
// 测「不靠超时也结束了」要把它拉长,测「超时兜底」要把它压短。
type timeoutPolicy struct {
	policy.DefaultManager
	timeouts policy.Timeout
}

func (p timeoutPolicy) ForLevel(uint32) policy.Session {
	s := policy.SessionDefault()
	s.Timeouts = p.timeouts
	return s
}

func (v reuseVariant) obfsConfig() obfsConfig {
	return obfsConfig{mode: v.obfs, host: "www.bing.com"}
}

func (v reuseVariant) newServer(timeouts policy.Timeout, extra ...*protocol.MemoryUser) *Server {
	return &Server{
		policyManager: timeoutPolicy{timeouts: timeouts},
		users:         append([]*protocol.MemoryUser{snellUser(reuseEmail, reusePSK, v.version)}, extra...),
		obfs:          v.obfsConfig(),
		version:       v.version,
		v6Mode:        v.v6Mode,
	}
}

// serveSnell 在本机随机端口上跑起 srv(走 Process),目标由 dispatcher 扮演。accepted 是服务端
// 一共接了多少条 TCP 连接 ——「N 个请求只用 1 条连接」看的就是它。
func serveSnell(t *testing.T, srv *Server, dispatcher routing.Dispatcher) (addr string, accepted *atomic.Int32) {
	t.Helper()
	return serveSnellSniffing(t, srv, dispatcher, session.SniffingRequest{})
}

// serveSnellSniffing 同 serveSnell,另外给入站配上嗅探设置。每条连接的 ctx 照 tcpWorker 的样子搭:
// 带一份 Outbound、一份 Content(嗅探设置就在它上面),Process 返回就 cancel。
func serveSnellSniffing(t *testing.T, srv *Server, dispatcher routing.Dispatcher, sniffing session.SniffingRequest) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	accepted = new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				cctx, ccancel := context.WithCancel(ctx)
				defer ccancel()
				cctx = session.ContextWithOutbounds(cctx, []*session.Outbound{{}})
				cctx = session.ContextWithInbound(cctx, &session.Inbound{
					Source: xnet.DestinationFromAddr(c.RemoteAddr()),
				})
				cctx = session.ContextWithContent(cctx, &session.Content{SniffingRequest: sniffing})
				_ = srv.Process(cctx, xnet.Network_TCP, c, dispatcher)
			}()
		}
	}()
	return ln.Addr().String(), accepted
}

// byeTarget 是「读到一行就回一行、然后关连接」的目标;Dispatch 一次就是一条新的目标连接。
// 回的是 "bye <收到的那一行>",连续几个请求各自的响应有没有串,一眼可见。
type byeTarget struct {
	// resetUplink:回完就把上行也掐掉 —— 出站那一侧在它自己的 UplinkOnly 到点后就是这么收场的,
	// 此后入站再往 link 里写会失败。false = 目标只关了自己的写方向,上行照收到底。
	resetUplink bool
	// keepOpen:回完不关,像 keep-alive 的目标那样等对端先走。
	keepOpen bool

	mu    sync.Mutex
	dests []string
	ctxs  []context.Context
}

func (d *byeTarget) Type() interface{} { return routing.DispatcherType() }
func (d *byeTarget) Start() error      { return nil }
func (d *byeTarget) Close() error      { return nil }

func (d *byeTarget) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return nil
}

func (d *byeTarget) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.mu.Lock()
	d.dests = append(d.dests, dest.String())
	d.ctxs = append(d.ctxs, ctx)
	d.mu.Unlock()

	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	go func() {
		up := bufio.NewReader(&buf.BufferedReader{Reader: upR})
		line, err := up.ReadString('\n')
		if err != nil {
			downW.Interrupt()
			return
		}
		downWrite(downW, "bye "+line)
		if d.keepOpen {
			_, _ = io.Copy(io.Discard, up)
			return
		}
		_ = downW.Close()
		if d.resetUplink {
			upR.Interrupt()
			return
		}
		_, _ = io.Copy(io.Discard, up)
	}()
	return &transport.Link{Reader: downR, Writer: upW}, nil
}

// dispatched 返回到目前为止每次 Dispatch 的目标与 ctx(按先后)。
func (d *byeTarget) dispatched() ([]string, []context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dests...), append([]context.Context(nil), d.ctxs...)
}

func downWrite(down *pipe.Writer, data string) {
	b := buf.New()
	_, _ = b.WriteString(data)
	_ = down.WriteMultiBuffer(buf.MultiBuffer{b})
}

// funcTarget 是由一个函数扮演的目标:每次 Dispatch 起一条新的「目标连接」,up 是客户端发来的数据,
// down 是回给客户端的那一头(Close = 目标正常关连接,Interrupt = 出站失败)。
type funcTarget func(up io.Reader, down *pipe.Writer)

func (funcTarget) Type() interface{} { return routing.DispatcherType() }
func (funcTarget) Start() error      { return nil }
func (funcTarget) Close() error      { return nil }

func (funcTarget) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return nil
}

func (f funcTarget) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	go f(&buf.BufferedReader{Reader: upR}, downW)
	return &transport.Link{Reader: downR, Writer: upW}, nil
}

var (
	// silentTarget 收下所有上行,但一个字节也不回、也不关。
	silentTarget = funcTarget(func(up io.Reader, _ *pipe.Writer) { _, _ = io.Copy(io.Discard, up) })
	// emptyTarget 一个字节不发就正常关连接。
	emptyTarget = funcTarget(func(_ io.Reader, down *pipe.Writer) { _ = down.Close() })
	// failedTarget 是没连上的目标:出站还没交出任何数据就失败了。
	failedTarget = funcTarget(func(_ io.Reader, down *pipe.Writer) { down.Interrupt() })
	// brokenTarget 发了一段数据之后断掉(目标 RST 之类)。断之前停一下,让客户端先把那段数据读走 ——
	// 之后线上再出现的任何字节,测试都看得见。
	brokenTarget = funcTarget(func(_ io.Reader, down *pipe.Writer) {
		downWrite(down, "partial\n")
		time.Sleep(200 * time.Millisecond)
		down.Interrupt()
	})
)

// reuseClient 是一条到入站的客户端连接。conn 是裸 TCP,用来看连接本身是开着还是被关了;
// w / r 是其上的 record 读写器(v4/v5 中间还隔着一层 obfs)。
type reuseClient struct {
	t    *testing.T
	conn net.Conn
	w    snellWriter
	r    snellReader
	// replyPending:请求发出去了,应答还没读。服务端等出站有了数据才回应答,所以它留到读下行时再读。
	replyPending bool
}

func (v reuseVariant) dial(t *testing.T, addr string) *reuseClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	c := &reuseClient{t: t, conn: conn}
	psk := []byte(reusePSK)
	if v.version == 6 {
		var profile *Profile
		if v.v6Mode == ModeDefault {
			profile = NewProfile(psk)
		}
		w, err := newV6Writer(conn, v.v6Mode, psk, profile)
		if err != nil {
			t.Fatalf("v6 writer: %v", err)
		}
		c.w, c.r = w, newV6Reader(conn, v.v6Mode, psk, profile)
		return c
	}
	oconn := v.obfsConfig().clientConn(conn)
	c.w, c.r = newRecordWriter(oconn, psk), newRecordReader(oconn, psk)
	return c
}

// open 发一个请求。同一条连接上可以先后 open 多次(复用)。
func (c *reuseClient) open(command byte, dest xnet.Destination) {
	c.t.Helper()
	var req bytes.Buffer
	if err := (request{command: command, destination: dest}).writeTo(&req); err != nil {
		c.t.Fatalf("编码请求: %v", err)
	}
	if _, err := c.w.Write(req.Bytes()); err != nil {
		c.t.Fatalf("发请求: %v", err)
	}
	c.replyPending = true
}

// reply 读掉还没读的 ReplyTunnel(读超时由调用方先设好)。
func (c *reuseClient) reply() {
	c.t.Helper()
	if !c.replyPending {
		return
	}
	if err := readServerReply(c.r); err != nil {
		c.t.Fatalf("读 ReplyTunnel: %v", err)
	}
	c.replyPending = false
}

func (c *reuseClient) send(s string) {
	c.t.Helper()
	if _, err := c.w.Write([]byte(s)); err != nil {
		c.t.Fatalf("发 %q: %v", s, err)
	}
}

func (c *reuseClient) expect(want string) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.reply()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c.r, got); err != nil {
		c.t.Fatalf("等 %q: 已读到 %q, err=%v", want, got, err)
	}
	if string(got) != want {
		c.t.Fatalf("响应对不上: 要 %q, 得到 %q", want, got)
	}
}

// end 结束客户端这一半(发零长度 record)。
func (c *reuseClient) end() {
	c.t.Helper()
	if err := c.w.writeZeroChunk(); err != nil {
		c.t.Fatalf("发结束 record: %v", err)
	}
}

// expectEnd:下行必须在 within 之内结束,而且得是「再没有数据」的干净结束。
func (c *reuseClient) expectEnd(within time.Duration) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(within))
	c.reply()
	var b [1]byte
	if n, err := c.r.Read(b[:]); n != 0 || err != io.EOF {
		c.t.Fatalf("%v 之内没等到下行结束: n=%d err=%v", within, n, err)
	}
}

// expectOpen:连接本身还开着 —— 服务端没关它,线上也没有多出来的字节。
// 紧跟在 expectEnd 之后用,就是在断言「下行是靠结束 record 结束的,不是靠关 TCP」。
func (c *reuseClient) expectOpen() {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var b [1]byte
	if n, err := c.conn.Read(b[:]); n != 0 || !goerrors.Is(err, os.ErrDeadlineExceeded) {
		c.t.Fatalf("连接应当还开着、且没有多余的数据: n=%d err=%v", n, err)
	}
}

// expectClosed:服务端必须在 within 之内关掉连接,关之前不再发任何字节。
func (c *reuseClient) expectClosed(within time.Duration) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(within))
	var b [1]byte
	n, err := c.conn.Read(b[:])
	if n != 0 || err == nil || goerrors.Is(err, os.ErrDeadlineExceeded) {
		c.t.Fatalf("%v 之内服务端应当关掉连接(且不再发数据): n=%d err=%v", within, n, err)
	}
}

func siteDest(i int) xnet.Destination {
	return xnet.TCPDestination(xnet.DomainAddress(fmt.Sprintf("site%d.example", i)), xnet.Port(8000+i))
}

// 回归:目标先关连接,客户端必须在 2 秒内看到下行结束。
func TestSnellTargetCloseEndsDownlink(t *testing.T) {
	// UplinkOnly 拉到 30 秒:下行结束必须是目标 EOF 当场带出来的,不能是哪个超时到点顺带关出来的。
	timeouts := policy.SessionDefault().Timeouts
	timeouts.UplinkOnly = 30 * time.Second

	for _, v := range reuseVariants {
		for _, cmd := range reuseCommands {
			t.Run(v.name+"/"+cmd.name, func(t *testing.T) {
				t.Parallel()
				addr, _ := serveSnell(t, v.newServer(timeouts), &byeTarget{})
				c := v.dial(t, addr)

				c.open(cmd.command, testDest)
				c.send("hi\n")
				c.expect("bye hi\n")
				c.expectEnd(2 * time.Second)
				// 半关闭:下行结束了,客户端这一半还没有,轮不到服务端关连接。
				c.expectOpen()

				// 客户端也结束之后:命令 1 的连接到此为止;命令 5 的留着等下一个请求。
				c.end()
				if cmd.command == commandConnect {
					c.expectClosed(2 * time.Second)
				} else {
					c.expectOpen()
				}
			})
		}
	}
}

// 复用:连续 N 个 ConnectV2 请求只用 1 条连接,各自的目标与响应互不串。
func TestSnellReuseSequentialRequests(t *testing.T) {
	const requests = 6

	for _, v := range reuseVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			target := &byeTarget{}
			addr, accepted := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), target)
			c := v.dial(t, addr)

			var want []string
			for i := 0; i < requests; i++ {
				want = append(want, siteDest(i).String())
				c.open(commandConnectV2, siteDest(i))
				c.send(fmt.Sprintf("req %d\n", i))
				c.expect(fmt.Sprintf("bye req %d\n", i))
				c.expectEnd(2 * time.Second)
				c.end()
			}

			if n := accepted.Load(); n != 1 {
				t.Fatalf("%d 个请求用了 %d 条连接,应当只用 1 条", requests, n)
			}
			if got, _ := target.dispatched(); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("分发出去的目标不对:\n 要 %v\n 得 %v", want, got)
			}
		})
	}
}

// 复用的另一个方向:客户端先结束自己那一半,目标随后才关。
func TestSnellReuseClientEndsFirst(t *testing.T) {
	for _, v := range reuseVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			// 回显管道:服务端关掉 link.Writer(= 客户端结束)之后,link.Reader 读完余下的就 EOF。
			addr, accepted := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), echoDispatcher{})
			c := v.dial(t, addr)

			for i := 0; i < 3; i++ {
				c.open(commandConnectV2, testDest)
				c.send(fmt.Sprintf("ping %d\n", i))
				c.expect(fmt.Sprintf("ping %d\n", i))
				c.end()
				c.expectEnd(2 * time.Second)
			}
			if n := accepted.Load(); n != 1 {
				t.Fatalf("3 个请求用了 %d 条连接,应当只用 1 条", n)
			}
		})
	}
}

// 目标先关,客户端却迟迟不结束自己那一半(应用还攥着半关闭的连接),或者在出站收场之后还在发数据。
// 这条流在服务端到此为止,但连接得留着:客户端已经读到结束 record、把连接当成可复用的了,这时关掉
// 等于在它池里留一条死连接。它后面发来的数据读掉丢弃,等到它的结束 record,下一个请求照常跑。
func TestSnellReuseSurvivesLateClientEnd(t *testing.T) {
	cases := []struct {
		name        string
		uplinkOnly  time.Duration
		resetUplink bool
		wait        time.Duration
	}{
		{name: "uplink-only-expired", uplinkOnly: 100 * time.Millisecond, wait: 500 * time.Millisecond},
		{name: "outbound-gone", uplinkOnly: 30 * time.Second, resetUplink: true},
	}

	for _, v := range reuseVariants {
		for _, tc := range cases {
			t.Run(v.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				timeouts := policy.SessionDefault().Timeouts
				timeouts.UplinkOnly = tc.uplinkOnly
				target := &byeTarget{resetUplink: tc.resetUplink}
				addr, accepted := serveSnell(t, v.newServer(timeouts), target)
				c := v.dial(t, addr)

				c.open(commandConnectV2, siteDest(0))
				c.send("first\n")
				c.expect("bye first\n")
				c.expectEnd(2 * time.Second)

				time.Sleep(tc.wait)
				c.expectOpen()
				c.send("late\n") // 目标已经不在了,只能丢
				c.send("later still\n")
				c.end()

				c.open(commandConnectV2, siteDest(1))
				c.send("second\n")
				c.expect("bye second\n")
				c.expectEnd(2 * time.Second)
				c.end()

				if n := accepted.Load(); n != 1 {
					t.Fatalf("用了 %d 条连接,应当只用 1 条", n)
				}
				if got, _ := target.dispatched(); len(got) != 2 {
					t.Fatalf("应当分发 2 次,实际 %v", got)
				}
			})
		}
	}
}

// 迟到的数据不能无止境地陪着读:超过上限就断开。
func TestSnellReuseDrainIsBounded(t *testing.T) {
	timeouts := policy.SessionDefault().Timeouts
	timeouts.UplinkOnly = 30 * time.Second
	v := reuseVariants[0]
	addr, _ := serveSnell(t, v.newServer(timeouts), &byeTarget{resetUplink: true})
	c := v.dial(t, addr)

	c.open(commandConnectV2, testDest)
	c.send("first\n")
	c.expect("bye first\n")
	c.expectEnd(2 * time.Second)

	// 服务端断开之后这边的写迟早会失败,所以写放到一边去做,只看连接有没有被关掉。
	go func() {
		chunk := bytes.Repeat([]byte{'x'}, maxPayloadLen)
		for sent := 0; sent < 4*drainLimit; sent += len(chunk) {
			if _, err := c.w.Write(chunk); err != nil {
				return
			}
		}
	}()
	c.expectClosed(5 * time.Second)
}

// 下行结束之后的超时兜底(与 xray 其它协议一致),别挂住:客户端什么都不做的话,再等它 UplinkOnly,
// 到点关连接。(命令 5 的连接见上,留着等结束 record。)
func TestSnellUplinkOnlyTimesOut(t *testing.T) {
	timeouts := policy.SessionDefault().Timeouts
	timeouts.UplinkOnly = 200 * time.Millisecond

	for _, v := range reuseVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			addr, _ := serveSnell(t, v.newServer(timeouts), &byeTarget{})
			c := v.dial(t, addr)

			c.open(commandConnect, testDest)
			c.send("hi\n")
			c.expect("bye hi\n")
			c.expectEnd(2 * time.Second)
			c.expectClosed(2 * time.Second)
		})
	}
}

// 客户端先结束、目标还开着(keep-alive 的目标,或者干脆不回):xray 不把半关闭传给目标,这样的流
// 都是等 DownlinkOnly 到点收场的 —— 算正常结束,必须发结束 record 并把连接留下。这时关 TCP 的话,
// 正等着结束 record 的客户端分不清两者,会把死连接放回池里。
func TestSnellClientEndsFirstTargetStaysOpen(t *testing.T) {
	timeouts := policy.SessionDefault().Timeouts
	timeouts.DownlinkOnly = 100 * time.Millisecond

	targets := []struct {
		name     string
		target   func() routing.Dispatcher
		response string
	}{
		{name: "keep-alive", target: func() routing.Dispatcher { return &byeTarget{keepOpen: true} }, response: "bye hi\n"},
		// 不回的目标:应答要等收场时才来,和结束 record 一起。
		{name: "silent", target: func() routing.Dispatcher { return silentTarget }},
	}

	for _, v := range reuseVariants {
		for _, tc := range targets {
			t.Run(v.name+"/"+tc.name+"/connect-v2", func(t *testing.T) {
				t.Parallel()
				addr, accepted := serveSnell(t, v.newServer(timeouts), tc.target())
				c := v.dial(t, addr)

				for i := 0; i < 4; i++ {
					c.open(commandConnectV2, testDest)
					c.send("hi\n")
					if tc.response != "" {
						c.expect(tc.response)
					}
					c.end()
					c.expectEnd(2 * time.Second)
					c.expectOpen()
				}
				if n := accepted.Load(); n != 1 {
					t.Fatalf("4 个请求用了 %d 条连接,应当只用 1 条", n)
				}
			})
			t.Run(v.name+"/"+tc.name+"/connect", func(t *testing.T) {
				t.Parallel()
				addr, _ := serveSnell(t, v.newServer(timeouts), tc.target())
				c := v.dial(t, addr)

				c.open(commandConnect, testDest)
				c.send("hi\n")
				if tc.response != "" {
					c.expect(tc.response)
				}
				c.end()
				c.expectEnd(2 * time.Second)
				c.expectClosed(2 * time.Second)
			})
		}
	}
}

// 同一件事,换成真的分发器 + freedom + 一个 keep-alive 的 TCP 目标:入站与出站各有一个 DownlinkOnly
// 定时器、几乎同时到点,两条收场路径在赛跑 —— 不管哪边先到,结果都得是「结束 record + 连接留下」。
func TestSnellClientEndsFirstThroughFreedom(t *testing.T) {
	d := freedomDispatcher(t)
	dest := tcpKeepAlive(t)

	for _, v := range reuseVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			addr, accepted := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), d)
			c := v.dial(t, addr)

			for i := 0; i < 4; i++ {
				c.open(commandConnectV2, dest)
				c.send(fmt.Sprintf("req %d\n", i))
				c.expect(fmt.Sprintf("ok req %d\n", i))
				c.end()
				c.expectEnd(3 * time.Second)
				c.expectOpen()
			}
			if n := accepted.Load(); n != 1 {
				t.Fatalf("4 个请求用了 %d 条连接,应当只用 1 条", n)
			}
		})
	}
}

// tcpKeepAlive 起一个 keep-alive 的 TCP 目标:每读到一行回一行 "ok <那一行>",连接留着等对端先关。
func tcpKeepAlive(t *testing.T) xnet.Destination {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if _, err := c.Write([]byte("ok " + line)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return xnet.DestinationFromAddr(ln.Addr())
}

// 应答等出站交出第一批数据才回,并且和这批数据在同一个 record 里。
func TestSnellReplyWaitsForTarget(t *testing.T) {
	for _, v := range reuseVariants {
		for _, cmd := range reuseCommands {
			t.Run(v.name+"/"+cmd.name, func(t *testing.T) {
				t.Parallel()
				addr, _ := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), &byeTarget{})
				c := v.dial(t, addr)

				c.open(cmd.command, testDest)
				c.expectOpen() // 目标还没出声,服务端一个字节都不该发

				c.send("hi\n")
				_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				record, err := c.r.nextRecord()
				if err != nil {
					t.Fatalf("读第一个 record: %v", err)
				}
				if want := string([]byte{replyTunnel}) + "bye hi\n"; string(record) != want {
					t.Fatalf("第一个 record 应当是 ReplyTunnel 加第一批数据 %q, 得到 %q", want, record)
				}
			})
		}
	}
}

// 目标没连上:回 ReplyError(0x02 | code | 文案长度 | 文案),然后关连接 —— 不能先说隧道通了。
func TestSnellReplyErrorWhenTargetFails(t *testing.T) {
	for _, v := range reuseVariants {
		for _, cmd := range reuseCommands {
			t.Run(v.name+"/"+cmd.name, func(t *testing.T) {
				t.Parallel()
				addr, _ := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), failedTarget)
				c := v.dial(t, addr)

				c.open(cmd.command, testDest)
				c.send("hi\n")
				_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				record, err := c.r.nextRecord()
				if err != nil {
					t.Fatalf("读错误应答: %v", err)
				}
				want := string([]byte{replyError, replyErrorCode, byte(len(replyErrorMessage))}) + replyErrorMessage
				if string(record) != want {
					t.Fatalf("应当收到 ReplyError %q, 得到 %q", want, record)
				}
				c.expectClosed(2 * time.Second)
			})
		}
	}
}

// 目标连上了、一个字节没发就正常关:这是一条空的流,不是失败 —— ReplyTunnel 加结束 record,连接照常复用。
func TestSnellEmptyResponse(t *testing.T) {
	for _, v := range reuseVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			addr, accepted := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), emptyTarget)
			c := v.dial(t, addr)

			for i := 0; i < 3; i++ {
				c.open(commandConnectV2, testDest)
				c.expectEnd(2 * time.Second)
				c.end()
			}
			c.expectOpen()
			if n := accepted.Load(); n != 1 {
				t.Fatalf("3 个请求用了 %d 条连接,应当只用 1 条", n)
			}
		})
	}
}

// 响应发到一半目标断了:只能关连接,不能补结束 record —— 那是把截断的响应说成完整的。
func TestSnellBrokenTargetClosesConnection(t *testing.T) {
	for _, v := range reuseVariants {
		for _, cmd := range reuseCommands {
			t.Run(v.name+"/"+cmd.name, func(t *testing.T) {
				t.Parallel()
				addr, _ := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), brokenTarget)
				c := v.dial(t, addr)

				c.open(cmd.command, testDest)
				c.expect("partial\n")
				c.expectClosed(2 * time.Second)
			})
		}
	}
}

// 整条流空闲到点(两头都还开着):关连接,不回 ReplyError —— 目标并没有失败,只是没人说话。
func TestSnellIdleStreamClosesWithoutReply(t *testing.T) {
	timeouts := policy.SessionDefault().Timeouts
	timeouts.ConnectionIdle = 300 * time.Millisecond
	v := reuseVariants[0]
	addr, _ := serveSnell(t, v.newServer(timeouts), silentTarget)
	c := v.dial(t, addr)

	c.open(commandConnectV2, testDest)
	c.send("hi\n")
	c.expectClosed(3 * time.Second)
}

// 复用连接上的后续请求不再握手 —— 被删掉的用户不能靠池里的连接继续用。
func TestSnellReuseRefusesRemovedUser(t *testing.T) {
	for _, v := range reuseVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			target := &byeTarget{}
			// 多配一个用户:RemoveUser 不肯删最后一个。
			srv := v.newServer(policy.SessionDefault().Timeouts, snellUser("spare@x", "spare-psk-0123456789", v.version))
			addr, _ := serveSnell(t, srv, target)
			c := v.dial(t, addr)

			c.open(commandConnectV2, siteDest(0))
			c.send("first\n")
			c.expect("bye first\n")
			c.expectEnd(2 * time.Second)
			c.end()
			c.expectOpen()

			// v6 unsafe-raw 线上没有密钥,连接一律算在第一个用户头上 —— 删的也就是它。
			if err := srv.RemoveUser(context.Background(), reuseEmail); err != nil {
				t.Fatalf("RemoveUser: %v", err)
			}

			c.open(commandConnectV2, siteDest(1))
			c.expectClosed(2 * time.Second)
			if got, _ := target.dispatched(); len(got) != 1 {
				t.Fatalf("用户已删,第二个请求不该分发出去: %v", got)
			}
		})
	}
}

// 空闲的复用连接到 ConnectionIdle 关掉,不会一直占着。
func TestSnellReuseIdleTimeout(t *testing.T) {
	timeouts := policy.SessionDefault().Timeouts
	timeouts.ConnectionIdle = 500 * time.Millisecond
	v := reuseVariants[0]
	addr, _ := serveSnell(t, v.newServer(timeouts), &byeTarget{})
	c := v.dial(t, addr)

	c.open(commandConnectV2, testDest)
	c.send("hi\n")
	c.expect("bye hi\n")
	c.expectEnd(2 * time.Second)
	c.end()

	c.expectOpen()
	c.expectClosed(3 * time.Second)
}

// 每条流要有它自己的 Outbound / Content —— 分发器把目标、嗅探结果、RouteTarget 写在上面,共用一份的话
// 上一个请求的结果会漏给下一个请求的路由。流结束后分发用的 ctx 还得 cancel(出站一侧、在线 IP 记账
// 都挂在它上面),而此时连接本身还活着。
func TestSnellReuseIsolatesStreams(t *testing.T) {
	v := reuseVariants[0]
	target := &byeTarget{}
	addr, _ := serveSnellSniffing(t, v.newServer(policy.SessionDefault().Timeouts), target,
		session.SniffingRequest{Enabled: true, RouteOnly: true})
	c := v.dial(t, addr)

	for i := 0; i < 2; i++ {
		c.open(commandConnectV2, siteDest(i))
		c.send("hi\n")
		c.expect("bye hi\n")
		c.expectEnd(2 * time.Second)
		c.end()
	}
	c.expectOpen()

	_, ctxs := target.dispatched()
	if len(ctxs) != 2 {
		t.Fatalf("应当分发 2 次,实际 %d 次", len(ctxs))
	}
	var outbounds [2]*session.Outbound
	var contents [2]*session.Content
	for i, ctx := range ctxs {
		obs := session.OutboundsFromContext(ctx)
		if len(obs) == 0 {
			t.Fatalf("第 %d 条流的 ctx 里没有 Outbound", i)
		}
		outbounds[i], contents[i] = obs[len(obs)-1], session.ContentFromContext(ctx)
		if contents[i] == nil || !contents[i].SniffingRequest.Enabled || !contents[i].SniffingRequest.RouteOnly {
			t.Fatalf("第 %d 条流丢了入站的嗅探配置: %+v", i, contents[i])
		}
		if inbound := session.InboundFromContext(ctx); inbound == nil || inbound.User == nil || inbound.User.Email != reuseEmail {
			t.Fatalf("第 %d 条流没有带上用户: %+v", i, inbound)
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
			t.Fatalf("第 %d 条流已经结束,它的 ctx 却没有 cancel", i)
		}
	}
	if outbounds[0] == outbounds[1] {
		t.Fatal("两条流共用了同一个 session.Outbound")
	}
	if contents[0] == contents[1] {
		t.Fatal("两条流共用了同一个 session.Content")
	}
}

// tcpDialer 是出站用的拨号器:直接连到给定地址。
type tcpDialer struct{}

func (tcpDialer) Dial(_ context.Context, dest xnet.Destination) (stat.Connection, error) {
	return net.Dial("tcp", dest.NetAddr())
}
func (tcpDialer) DestIpAddress() net.IP                                 { return nil }
func (tcpDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func (v reuseVariant) newClient(serverAddr string) *Client {
	psk := []byte(reusePSK)
	c := &Client{
		server: protocol.NewServerSpec(xnet.DestinationFromAddr(mustTCPAddr(serverAddr)),
			snellUser(reuseEmail, reusePSK, v.version)),
		policyManager: policy.DefaultManager{},
		obfs:          v.obfsConfig(),
		version:       v.version,
		v6Mode:        v.v6Mode,
	}
	if v.version == 6 && v.v6Mode == ModeDefault {
		c.profile = NewProfile(psk)
	}
	return c
}

func mustTCPAddr(addr string) *net.TCPAddr {
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		panic(err)
	}
	return a
}

// 端到端:本仓库自己的 snell 出站 → 入站 → 目标先关,而本地应用发完一行之后既不再发、也不关连接。
// 出站的 Process 必须在 2 秒内返回(默认策略 UplinkOnly = 1 秒)—— socks 这类入站用 DispatchLink
// 直连出站,应用何时看到 EOF 全看它何时返回。入站不发结束 record、或者出站不缩短定时器,都会挂在这里。
func TestSnellOutboundEndsAfterTargetClose(t *testing.T) {
	for _, v := range reuseVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			addr, _ := serveSnell(t, v.newServer(policy.SessionDefault().Timeouts), &byeTarget{})

			appR, appW := pipe.New(pipe.WithoutSizeLimit())   // 应用 → 出站
			respR, respW := pipe.New(pipe.WithoutSizeLimit()) // 出站 → 应用
			line := buf.New()
			_, _ = line.WriteString("hi\n")
			if err := appW.WriteMultiBuffer(buf.MultiBuffer{line}); err != nil {
				t.Fatalf("应用写入: %v", err)
			}

			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: testDest}})
			done := make(chan error, 1)
			go func() {
				done <- v.newClient(addr).Process(ctx, &transport.Link{Reader: appR, Writer: respW}, tcpDialer{})
			}()

			got := make([]byte, len("bye hi\n"))
			if _, err := io.ReadFull(&buf.BufferedReader{Reader: respR}, got); err != nil || string(got) != "bye hi\n" {
				t.Fatalf("应用应当收到 %q: 得到 %q, err=%v", "bye hi\n", got, err)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("目标关连接 2 秒后出站仍未返回 —— 应用还在等一个不会来的 EOF")
			}
		})
	}
}
