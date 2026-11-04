package anytls

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
)

// 客户端可以把「目标地址 + 首包」合在新流的第一个 PSH 帧里(Surge 的 UDP 就这么发:
// 地址 + UoT 请求 + 第一个包)。从前服务端只读地址、不管帧长,同一帧剩下的字节被当成下一帧的帧头,
// 整条会话错帧、UDP 收不到回应。这里验证:首帧按帧长整帧读完,地址后的数据进这条流,下一帧不受影响。
func TestFirstFrameMergedUoT(t *testing.T) {
	capCh := make(chan captured, 4)
	s := newTestServerSession(fakeDispatcher{link: &transport.Link{Reader: eofReader{}, Writer: &captureWriter{ch: capCh}}})
	st := &stream{sid: 1}
	s.streams[1] = st

	var frame bytes.Buffer
	M.SocksaddrSerializer.WriteAddrPort(&frame, uot.RequestDestination(uot.Version))
	uot.WriteRequest(&frame, uot.Request{IsConnect: false, Destination: M.ParseSocksaddr("3.22.142.132:3478")})
	uot.AddrParser.WriteAddrPort(&frame, M.ParseSocksaddr("3.22.142.132:3478"))
	binary.Write(&frame, binary.BigEndian, uint16(5))
	frame.WriteString("stun!")
	length := frame.Len()
	frame.WriteString("NEXT") // 下一帧的开头,不能被这一帧吃掉

	br := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(frame.Bytes()))}
	if err := s.handleNewStream(context.Background(), st, br, length); err != nil {
		t.Fatalf("handleNewStream: %v", err)
	}
	select {
	case c := <-capCh:
		if c.dest != "3.22.142.132:3478" || c.payload != "stun!" {
			t.Fatalf("首帧里的 UDP 包解错了: %+v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("首帧里的 UDP 包没有发出去")
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "NEXT" {
		t.Fatalf("读多了 / 读少了,下一帧剩下 %q", rest)
	}
	st.up.closeWrite()
}

// TCP 新流:地址后面紧跟的首包同样要进这条流,发给目标。
func TestFirstFrameMergedTCP(t *testing.T) {
	capCh := make(chan captured, 4)
	s := newTestServerSession(fakeDispatcher{link: &transport.Link{Reader: &blockingReader{done: make(chan struct{})}, Writer: &captureWriter{ch: capCh}}})
	st := &stream{sid: 3}
	s.streams[3] = st

	var frame bytes.Buffer
	M.SocksaddrSerializer.WriteAddrPort(&frame, M.ParseSocksaddr("1.1.1.1:443"))
	frame.WriteString("client-hello")
	br := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(frame.Bytes()))}
	if err := s.handleNewStream(context.Background(), st, br, frame.Len()); err != nil {
		t.Fatalf("handleNewStream: %v", err)
	}
	select {
	case c := <-capCh:
		if c.payload != "client-hello" {
			t.Fatalf("首包内容不对: %q", c.payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("首包没有发给目标")
	}
}
