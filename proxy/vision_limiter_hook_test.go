package proxy

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

// sinkConn 吞掉所有写入、读即 EOF,只用来给 Vision 读写器一个可替换的底层 conn。
type sinkConn struct{}

func (sinkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (sinkConn) Write(b []byte) (int, error)      { return len(b), nil }
func (sinkConn) Close() error                     { return nil }
func (sinkConn) LocalAddr() stdnet.Addr           { return nil }
func (sinkConn) RemoteAddr() stdnet.Addr          { return nil }
func (sinkConn) SetDeadline(time.Time) error      { return nil }
func (sinkConn) SetReadDeadline(time.Time) error  { return nil }
func (sinkConn) SetWriteDeadline(time.Time) error { return nil }

// onceReader 第一次返回给定的 MultiBuffer,之后 EOF。
type onceReader struct{ mb buf.MultiBuffer }

func (r *onceReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.mb == nil {
		return nil, io.EOF
	}
	mb := r.mb
	r.mb = nil
	return mb, nil
}

// recordVisionHook 安装一个记录调用的钩子,测试结束时恢复原钩子。
func recordVisionHook(t *testing.T) *[]string {
	t.Helper()
	prev := visionLimiterHook
	t.Cleanup(func() { visionLimiterHook = prev })
	var calls []string
	SetVisionLimiterHook(func(email string, rawConn stdnet.Conn) stdnet.Conn {
		calls = append(calls, email)
		return sinkConn{}
	})
	return &calls
}

func ctxWithInboundUser(email string) context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{
		User: &protocol.MemoryUser{Email: email},
	})
}

// 钩子只能包 vless 入站面向客户端的那条连接。出站侧(vless-vision 出站连落地)的读写器
// 拿到的 ctx 里同样有入站用户 email;过去也被包,于是非 vision 入站经 vision 出站时,
// dispatcher 的 RateWriter 和钩子扣的是同一个 bucket,实际速率只剩一半。
func TestVisionWriterHookOnlyOnClientSide(t *testing.T) {
	for _, tc := range []struct {
		name     string
		isUplink bool
		wantWrap bool
	}{
		{"inbound-writer-to-client", false, true},
		{"outbound-writer-to-server", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := recordVisionHook(t)
			state := NewTrafficState(make([]byte, 16))
			state.NumberOfPacketToFilter = 0
			if tc.isUplink {
				state.Outbound.IsPadding = false
				state.Outbound.UplinkWriterDirectCopy = true
			} else {
				state.Inbound.IsPadding = false
				state.Inbound.DownlinkWriterDirectCopy = true
			}
			w := NewVisionWriter(buf.Discard, state, tc.isUplink, ctxWithInboundUser("alice"), sinkConn{}, nil, nil)

			b := buf.New()
			b.WriteString("payload")
			if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				t.Fatalf("WriteMultiBuffer: %v", err)
			}
			if gotWrap := len(*calls) == 1 && (*calls)[0] == "alice"; gotWrap != tc.wantWrap || len(*calls) > 1 {
				t.Fatalf("hook calls = %q, want wrapped=%v", *calls, tc.wantWrap)
			}
		})
	}
}

func TestVisionReaderHookOnlyOnClientSide(t *testing.T) {
	for _, tc := range []struct {
		name     string
		isUplink bool
		wantWrap bool
	}{
		{"inbound-reader-from-client", true, true},
		{"outbound-reader-from-server", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := recordVisionHook(t)
			uuid := []byte("0123456789abcdef")
			state := NewTrafficState(uuid)
			ctx := ctxWithInboundUser("alice")

			// 对端发来一个带 CommandPaddingDirect 的 vision 块:读完即切换到 direct copy,
			// 这正是钩子被调用的时刻。
			content := buf.New()
			content.WriteString("hello")
			once := append([]byte(nil), uuid...)
			padded := XtlsPadding(content, CommandPaddingDirect, &once, false, ctx, []uint32{900, 500, 900, 256})

			r := NewVisionReader(&onceReader{mb: buf.MultiBuffer{padded}}, state, tc.isUplink, ctx, sinkConn{},
				bytes.NewReader(nil), new(bytes.Buffer), nil)
			mb, err := r.ReadMultiBuffer()
			if err != nil {
				t.Fatalf("ReadMultiBuffer: %v", err)
			}
			if got := mb.String(); got != "hello" {
				t.Fatalf("content = %q, want hello", got)
			}
			switched := state.Inbound.UplinkReaderDirectCopy
			if !tc.isUplink {
				switched = state.Outbound.DownlinkReaderDirectCopy
			}
			if !switched {
				t.Fatal("reader did not switch to direct copy; test setup is wrong")
			}
			if gotWrap := len(*calls) == 1 && (*calls)[0] == "alice"; gotWrap != tc.wantWrap || len(*calls) > 1 {
				t.Fatalf("hook calls = %q, want wrapped=%v", *calls, tc.wantWrap)
			}
		})
	}
}
