package outbound

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport"
)

// closeCountingHandler 实现 outbound.Handler,只为记录 Close 被调用过几次。
type closeCountingHandler struct {
	tag    string
	closed atomic.Int32
}

func (h *closeCountingHandler) Tag() string                                        { return h.tag }
func (h *closeCountingHandler) Dispatch(ctx context.Context, link *transport.Link) {}
func (h *closeCountingHandler) SenderSettings() *serial.TypedMessage               { return nil }
func (h *closeCountingHandler) ProxySettings() *serial.TypedMessage                { return nil }
func (h *closeCountingHandler) Start() error                                       { return nil }
func (h *closeCountingHandler) Close() error                                       { h.closed.Add(1); return nil }

// 移除出站必须 Close 它,否则它持有的资源不释放。
//
// WireGuard 出站自带 gvisor 协议栈 + UDP bind:不 Close 就一直占着端口 ——
// 面板上把出站删了、xray 也重载了,端口仍被占用,只有整个进程重启才放开(用户实报)。
// 入站 manager 一直是 Close 的(app/proxyman/inbound/inbound.go:82),出站这边漏了。
func TestRemoveHandlerClosesIt(t *testing.T) {
	m, err := New(context.Background(), nil)
	if err != nil {
		t.Fatalf("建 manager: %v", err)
	}
	mgr := m
	h := &closeCountingHandler{tag: "wg-peer"}
	if err := mgr.AddHandler(context.Background(), h); err != nil {
		t.Fatalf("加出站: %v", err)
	}
	if err := mgr.RemoveHandler(context.Background(), "wg-peer"); err != nil {
		t.Fatalf("移除出站: %v", err)
	}
	if got := h.closed.Load(); got != 1 {
		t.Errorf("移除后 Close 应被调用 1 次,实际 %d —— "+
			"不 Close 的话 WireGuard 出站的 UDP bind 一直占着端口,只有重启进程才释放", got)
	}
}

// 移除不存在的 tag 不该 panic,也不该误关别人。
func TestRemoveHandlerUnknownTagIsSafe(t *testing.T) {
	mgr, _ := New(context.Background(), nil)
	keep := &closeCountingHandler{tag: "keep"}
	_ = mgr.AddHandler(context.Background(), keep)
	if err := mgr.RemoveHandler(context.Background(), "nope"); err != nil {
		t.Fatalf("移除不存在的 tag 不该报错: %v", err)
	}
	if got := keep.closed.Load(); got != 0 {
		t.Errorf("不该动到别的出站,keep 被 Close 了 %d 次", got)
	}
}
