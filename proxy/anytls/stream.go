package anytls

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

type stream struct {
	sid  uint32
	link *transport.Link

	// cancel 取消本条流专属的 dispatch ctx。dispatcher 在 Dispatch 时对该 ctx 注册了
	// online-IP 的 RemoveIP(AfterFunc),所以流结束时必须调它,否则在线 IP 直到整个
	// anytls 会话(可能被客户端连接池长期保活)关闭才清 —— 表现为「断连后面板仍记录连接」(#731)。
	// context.CancelFunc 幂等,可从 close()/pumpDownlink 多处安全调用。
	cancel context.CancelFunc

	done     chan struct{}
	doneOnce sync.Once
	errMu    sync.Mutex
	err      error
	dieHook  func()

	isUDP     bool
	udpTarget *xnet.Destination

	// udpPipe 为 true 时走 canonical full-cone 路径:PSH 帧体喂进 uplink pipe,由 handleUDPStream
	// 逐包解目标写进单条 freedom link;fork 自身客户端(client=xray)不置此位,仍走 raw 透传。
	udpPipe      bool
	uplinkR      *io.PipeReader
	uplinkW      *io.PipeWriter
	uotConnected bool
	uotDest      xnet.Destination
}

func newStream(sid uint32, link *transport.Link) *stream {
	return &stream{
		sid:  sid,
		link: link,
		done: make(chan struct{}),
	}
}

func (st *stream) close(err error) {
	// 流结束即取消其 dispatch ctx → 触发 dispatcher 注册的 RemoveIP,让在线 IP 按活跃流实时清理(#731)。
	if st.cancel != nil {
		st.cancel()
	}
	// 关闭 uplink pipe 两端:让 handleUDPStream 的读循环拿到 EOF/ErrClosedPipe 退出,
	// 并解阻塞可能卡在 feedUDPUplink 写入的 readLoop。io.Pipe 的 Close 幂等,可重复调用。
	if st.uplinkW != nil {
		st.uplinkW.Close()
	}
	if st.uplinkR != nil {
		st.uplinkR.Close()
	}
	if st.done == nil {
		if st.link != nil {
			common.Close(st.link.Reader)
			common.Close(st.link.Writer)
		}
		return
	}
	st.doneOnce.Do(func() {
		st.errMu.Lock()
		st.err = err
		st.errMu.Unlock()
		if st.link != nil {
			common.Close(st.link.Reader)
			common.Close(st.link.Writer)
		}
		close(st.done)
		if st.dieHook != nil {
			st.dieHook()
		}
	})
}

func (st *stream) result() error {
	st.errMu.Lock()
	defer st.errMu.Unlock()
	return st.err
}
