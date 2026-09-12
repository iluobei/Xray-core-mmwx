package anytls

import (
	"bytes"
	"context"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	xsession "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// onlineDispatcher 忠实复刻 app/dispatcher/default.go 的 online-IP 追踪:Dispatch 时按 ctx 里的
// inbound Source 做 AddIP,并 context.AfterFunc(ctx, RemoveIP)。用真实 stats.OnlineMap,
// 从而真机同款地验证「流关闭 → 在线 IP 清零」。
type onlineDispatcher struct {
	link *transport.Link
	om   *stats.OnlineMap
}

func (*onlineDispatcher) Type() interface{} { return nil }
func (*onlineDispatcher) Start() error      { return nil }
func (*onlineDispatcher) Close() error      { return nil }
func (d *onlineDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if inb := xsession.InboundFromContext(ctx); inb != nil {
		userIP := inb.Source.Address.String()
		d.om.AddIP(userIP)
		context.AfterFunc(ctx, func() { d.om.RemoveIP(userIP) })
	}
	return d.link, nil
}
func (d *onlineDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return nil
}

// TestOnlineMapClearsOnStreamClose:真 OnlineMap + 真 anytls 服务端会话。开流后在线 IP=1,
// 关流后必须清零。修复前(RemoveIP 绑会话 ctx)会一直是 1,直到整个会话关闭(#731)。
func TestOnlineMapClearsOnStreamClose(t *testing.T) {
	om := stats.NewOnlineMap()
	disp := &onlineDispatcher{
		link: &transport.Link{Reader: &blockingReader{done: make(chan struct{})}, Writer: nopWriter{}},
		om:   om,
	}
	s := newTestServerSession(disp)
	st := &stream{sid: 1}
	s.streams[1] = st

	// 与真实 inbound worker 一致:ctx 携带客户端源地址。
	ctx := xsession.ContextWithInbound(context.Background(), &xsession.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.9"), 12345),
	})

	if err := s.handleNewStream(ctx, st, synBody(t, "1.1.1.1:443")); err != nil {
		t.Fatalf("handleNewStream: %v", err)
	}
	if got := om.Count(); got != 1 {
		t.Fatalf("流打开后在线 IP 应为 1,实际 %d", got)
	}

	// 客户端断开该流 → RemoveIP 经 AfterFunc 异步触发,轮询等待归零。
	s.finishStream(1, nil)
	deadline := time.Now().Add(2 * time.Second)
	for om.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := om.Count(); got != 0 {
		t.Fatalf("关流后在线 IP 应清零,实际 %d —— 在线连接泄漏(#731)", got)
	}
}

// capturingDispatcher 记录每次 Dispatch 收到的 ctx —— dispatcher 正是对这个 ctx 注册 online-IP 的
// RemoveIP(context.AfterFunc)。ctx 被取消 = RemoveIP 会触发。
type capturingDispatcher struct {
	link *transport.Link
	ctx  context.Context
}

func (*capturingDispatcher) Type() interface{} { return nil }
func (*capturingDispatcher) Start() error      { return nil }
func (*capturingDispatcher) Close() error      { return nil }
func (d *capturingDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	d.ctx = ctx
	return d.link, nil
}
func (d *capturingDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return nil
}

// blockingReader 阻塞到 Close 被调用(模拟一条一直开着、没有下行数据的流),
// 让 pumpDownlink 不会立刻因 EOF 退出,从而由我们主动决定「流何时关闭」。
type blockingReader struct{ done chan struct{} }

func (r *blockingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.done
	return nil, buf.ErrReadTimeout
}
func (r *blockingReader) Close() error {
	select {
	case <-r.done:
	default:
		close(r.done)
	}
	return nil
}

type nopWriter struct{}

func (nopWriter) WriteMultiBuffer(mb buf.MultiBuffer) error { buf.ReleaseMulti(mb); return nil }

func newTestServerSession(disp routing.Dispatcher) *session {
	s := &session{
		dispatcher: disp,
		streams:    make(map[uint32]*stream),
		bw:         buf.NewBufferedWriter(buf.NewWriter(&bytes.Buffer{})),
	}
	s.fw = newFrameWriter(s.bw)
	return s
}

func synBody(t *testing.T, dest string) *buf.BufferedReader {
	t.Helper()
	var b bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&b, M.ParseSocksaddr(dest)); err != nil {
		t.Fatalf("encode dest: %v", err)
	}
	return &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(b.Bytes()))}
}

// #731:anytls 每条流必须用「随流关闭而取消」的 dispatch ctx,否则在线 IP 直到整个会话
// (客户端连接池可能长期保活)关闭才清,表现为「断连后面板仍记录连接」。
// 这里验证:handleNewStream 分发后 ctx 处于活动态;调 finishStream 关流后该 ctx 被取消。
func TestStreamCtxCancelledOnFinishStream(t *testing.T) {
	disp := &capturingDispatcher{link: &transport.Link{Reader: &blockingReader{done: make(chan struct{})}, Writer: nopWriter{}}}
	s := newTestServerSession(disp)

	st := &stream{sid: 1}
	s.streams[1] = st

	if err := s.handleNewStream(context.Background(), st, synBody(t, "1.1.1.1:443")); err != nil {
		t.Fatalf("handleNewStream: %v", err)
	}
	if disp.ctx == nil {
		t.Fatal("dispatcher 未收到 ctx")
	}
	select {
	case <-disp.ctx.Done():
		t.Fatal("流仍打开,dispatch ctx 不应已取消")
	default:
	}

	// 客户端 FIN / 逻辑断开 → finishStream → st.close → 取消该流 ctx。
	s.finishStream(1, nil)

	select {
	case <-disp.ctx.Done():
		// 期望:ctx 已取消 → dispatcher 的 RemoveIP 会触发 → OnlineMap 清理。
	case <-time.After(2 * time.Second):
		t.Fatal("关流后 dispatch ctx 仍未取消 —— 在线 IP 会泄漏(#731)")
	}
}

// 验证另一条关闭路径:下行泵结束(目标侧关闭 → pumpDownlink 退出)也取消该流 dispatch ctx。
// 用 eofReader(udp_test.go 内,同包)让 pumpDownlink 立刻因 EOF 退出、走 defer。
func TestStreamCtxCancelledWhenDownlinkEnds(t *testing.T) {
	disp := &capturingDispatcher{link: &transport.Link{Reader: eofReader{}, Writer: nopWriter{}}}
	s := newTestServerSession(disp)
	st := &stream{sid: 7}
	s.streams[7] = st

	if err := s.handleNewStream(context.Background(), st, synBody(t, "2.2.2.2:8443")); err != nil {
		t.Fatalf("handleNewStream: %v", err)
	}

	select {
	case <-disp.ctx.Done():
		// pumpDownlink 读到 EOF → defer → st.cancel → ctx 取消。
	case <-time.After(2 * time.Second):
		t.Fatal("下行结束后 dispatch ctx 仍未取消 —— 在线 IP 会泄漏(#731)")
	}
}
