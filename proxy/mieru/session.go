// session.go:一条 mieru 逻辑会话(一个 socks5 目标)。多个会话按 sessionID 多路复用在一条 TCP
// underlay 上,共享该方向的段写出器(lockedWriter,mutex 保护 nonce 递增顺序)。
// 每会话:client→target 由读循环把 dataClientToServer 段的 payload 写入 link.Writer;
// target→client 由 pump goroutine 读 link.Reader,分片(≤32768)成 dataServerToClient 段发出。
package mieru

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
)

const (
	maxFragmentLen = 32768 // 规范:TCP 单片最大 32768 字节
	defaultWindow  = 4096  // 我方向对端广告的接收窗口(单位:段)
)

// lockedWriter 是一条 underlay 连接**一个方向**的段写出器,mutex 串行化以保证 nonce 递增与线序一致。
type lockedWriter struct {
	mu sync.Mutex
	w  *segmentWriter
}

func (lw *lockedWriter) write(meta, payload []byte) error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.write(meta, payload)
}

type serverSession struct {
	id     uint32
	link   *transport.Link
	writer *lockedWriter
	outSeq atomic.Uint32
	// rcvNext 是「我方期望收到的下一个客户端 seq」,也就是要捎带回去的累积确认。
	// 出站段必须带上它:官方客户端(enfein/mieru,mihomo 用的就是这个库)按
	// inflight = sndNext - sndUnack 做流控,sndUnack 只由对端捎带的 unackSeq 推进。
	// 这里恒为 0 的话,客户端会认为一个段都没被确认,发满一个窗口(defaultWindow 段)
	// 之后就永久阻塞 —— TCP 层一切正常、无 RST 无丢包,应用层却再不产出数据。
	// 小载荷填不满窗口所以能通,HTTPS 这类大载荷必现(#673)。
	rcvNext atomic.Uint32
	cancel  context.CancelFunc
	closed  atomic.Bool
}

// nextSeq 取本会话下一个出站 seq(会话内单调递增;pump 与建链控制段可能并发,故用原子)。
func (ss *serverSession) nextSeq() uint32 { return ss.outSeq.Add(1) - 1 }

// noteClientSeq 记下刚收到的客户端段序号,推进累积确认水位。
//
// underlay 是 TCP,段必然按序不丢,所以 rcvNext 就是 seq+1。仍然用模运算比较而不是
// 直接赋值:重复/乱序段(理论上不该出现)不能让水位倒退 —— 倒退会让客户端把已经
// 确认过的段重新算进 inflight,窗口再次卡死。
func (ss *serverSession) noteClientSeq(seq uint32) {
	next := seq + 1 // 依赖 uint32 自然回绕
	for {
		cur := ss.rcvNext.Load()
		if int32(next-cur) <= 0 {
			return // 不比当前新
		}
		if ss.rcvNext.CompareAndSwap(cur, next) {
			return
		}
	}
}

// writeControl 发一个会话控制段(openSessionResponse / closeSessionResponse)。
func (ss *serverSession) writeControl(protoType uint8) error {
	meta := sessionMeta{protocolType: protoType, sessionID: ss.id, seq: ss.nextSeq()}.encode()
	return ss.writer.write(meta, nil)
}

// writeData 把 payload 分片成 dataServerToClient 段发出。
func (ss *serverSession) writeData(payload []byte) error {
	for len(payload) > 0 {
		n := len(payload)
		if n > maxFragmentLen {
			n = maxFragmentLen
		}
		chunk := payload[:n]
		meta := dataMeta{
			protocolType: protoDataServerToClient,
			sessionID:    ss.id,
			seq:          ss.nextSeq(),
			unackSeq:     ss.rcvNext.Load(),
			window:       defaultWindow,
			payloadLen:   uint16(len(chunk)),
		}.encode()
		if err := ss.writer.write(meta, chunk); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

// pump 读落地响应(link.Reader),编成 dataServerToClient 段回给客户端;结束时通知客户端关闭会话。
func (ss *serverSession) pump() {
	reader := ss.link.Reader
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			break
		}
		for _, b := range mb {
			if b.Len() > 0 {
				if werr := ss.writeData(b.Bytes()); werr != nil {
					buf.ReleaseMulti(mb)
					ss.closeAndNotify()
					return
				}
			}
		}
		buf.ReleaseMulti(mb)
	}
	ss.closeAndNotify()
}

// closeAndNotify 关闭本地 link 并向客户端发 closeSessionRequest(幂等)。
func (ss *serverSession) closeAndNotify() {
	if ss.closed.Swap(true) {
		return
	}
	_ = ss.writeControl(protoCloseSessionRequest)
	ss.interrupt()
}

// interrupt 断开本地 link(不再向客户端发关闭段)。
func (ss *serverSession) interrupt() {
	ss.closed.Store(true)
	if ss.cancel != nil {
		ss.cancel()
	}
	common.Interrupt(ss.link.Reader)
	common.Interrupt(ss.link.Writer)
}

// feed 把客户端来的数据写入落地 link。
func (ss *serverSession) feed(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	return ss.link.Writer.WriteMultiBuffer(bytesToMultiBuffer(payload))
}

// bytesToMultiBuffer 把字节切片切成若干 buf.Buffer。
func bytesToMultiBuffer(b []byte) buf.MultiBuffer {
	var mb buf.MultiBuffer
	for len(b) > 0 {
		buffer := buf.New()
		n, _ := buffer.Write(b)
		b = b[n:]
		mb = append(mb, buffer)
	}
	return mb
}
