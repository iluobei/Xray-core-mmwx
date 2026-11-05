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
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport"
)

// captured 记录写进 freedom link 的一个上行 UDP 包(逐包目标 + payload 副本)。
type captured struct {
	dest    string
	payload string
}

type captureWriter struct {
	ch chan captured
}

func (w *captureWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		d := ""
		if b.UDP != nil {
			d = b.UDP.NetAddr()
		}
		w.ch <- captured{dest: d, payload: string(b.Bytes())}
	}
	buf.ReleaseMulti(mb)
	return nil
}

// eofReader 让 udpDownlink 立刻退出,不干扰上行断言。
type eofReader struct{}

func (eofReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, io.EOF }

// queueWriter 把每次 Write 作为一帧帧体放进上行队列,模拟 readLoop 收到的 PSH 帧。
type queueWriter struct{ q *uplinkQueue }

func (w queueWriter) Write(p []byte) (int, error) {
	b := buf.New()
	b.Write(p)
	return len(p), w.q.push(buf.MultiBuffer{b})
}

type fakeDispatcher struct{ link *transport.Link }

func (fakeDispatcher) Type() interface{} { return nil }
func (fakeDispatcher) Start() error      { return nil }
func (fakeDispatcher) Close() error      { return nil }
func (d fakeDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.link, nil
}
func (d fakeDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return nil
}

// TestUDPFullconeUplinkPerPacketDest 验证 full-cone 核心:not-connected UoT 逐包不同目标解析后,
// 每个包都以正确的 buf.UDP 写进同一条 freedom link(= freedom 单 socket 出站 = full-cone)。
func TestUDPFullconeUplinkPerPacketDest(t *testing.T) {
	capCh := make(chan captured, 8)
	link := &transport.Link{Reader: eofReader{}, Writer: &captureWriter{ch: capCh}}
	s := &session{
		dispatcher: fakeDispatcher{link: link},
		streams:    make(map[uint32]*stream),
	}
	st := &stream{sid: 1, udpPipe: true, up: newUplinkQueue()}
	s.streams[1] = st

	go s.handleUDPStream(context.Background(), st)

	// 编码:not-connected 请求(占位目标)+ 两个发往不同目标的包(与 sing uot WritePacket 一致)。
	w := queueWriter{st.up}
	if err := uot.WriteRequest(w, uot.Request{IsConnect: false, Destination: M.ParseSocksaddr("8.8.8.8:53")}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	writePkt := func(dest, payload string) {
		// uot 逐包地址用 uot.AddrParser(IPv4 类型字节=0x00),不是 M.SocksaddrSerializer(0x01)。
		if err := uot.AddrParser.WriteAddrPort(w, M.ParseSocksaddr(dest)); err != nil {
			t.Fatalf("write addr: %v", err)
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(payload)))
		w.Write(lb[:])
		w.Write([]byte(payload))
	}
	writePkt("1.1.1.1:5301", "hello-a")
	writePkt("9.9.9.9:5302", "hello-b")

	want := map[string]string{"1.1.1.1:5301": "hello-a", "9.9.9.9:5302": "hello-b"}
	got := map[string]string{}
	for i := 0; i < 2; i++ {
		select {
		case c := <-capCh:
			got[c.dest] = c.payload
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting packet %d, got so far: %v", i, got)
		}
	}
	st.up.closeWrite()

	for d, p := range want {
		if got[d] != p {
			t.Errorf("dest %s: got payload %q, want %q", d, got[d], p)
		}
	}
}

// oneShotUDPReader 返回一个带 buf.UDP(源地址)的回包,再返回 EOF。
type oneShotUDPReader struct {
	done    bool
	src     net.Destination
	payload string
}

func (r *oneShotUDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.done {
		return nil, io.EOF
	}
	r.done = true
	b := buf.New()
	b.Write([]byte(r.payload))
	d := r.src
	b.UDP = &d
	return buf.MultiBuffer{b}, nil
}

// TestUDPFullconeDownlinkFraming 验证下行:freedom 回包(buf.UDP=源地址)被封成 not-connected
// UoT 帧 [src addr][uint16 len][payload] 发回客户端,源地址与 payload 正确。
func TestUDPFullconeDownlinkFraming(t *testing.T) {
	var out bytes.Buffer
	s := &session{}
	s.bw = buf.NewBufferedWriter(buf.NewWriter(&out))
	s.fw = newFrameWriter(s.bw)

	src := net.UDPDestination(net.ParseAddress("1.1.1.1"), 5301)
	st := &stream{sid: 7, uotConnected: false, uotDest: net.UDPDestination(net.ParseAddress("8.8.8.8"), 53)}
	link := &transport.Link{Reader: &oneShotUDPReader{src: src, payload: "reply-a"}}

	s.udpDownlink(st, link)

	raw := out.Bytes()
	if len(raw) < 7 {
		t.Fatalf("frame too short: %d bytes", len(raw))
	}
	if raw[0] != cmdPSH {
		t.Fatalf("cmd = %d, want cmdPSH(%d)", raw[0], cmdPSH)
	}
	if sid := binary.BigEndian.Uint32(raw[1:5]); sid != 7 {
		t.Fatalf("sid = %d, want 7", sid)
	}
	bodyLen := binary.BigEndian.Uint16(raw[5:7])
	body := raw[7 : 7+int(bodyLen)]

	br := bytes.NewReader(body)
	addr, err := uot.AddrParser.ReadAddrPort(br)
	if err != nil {
		t.Fatalf("parse src addr: %v", err)
	}
	if got := singbridge.ToDestination(addr, net.Network_UDP).NetAddr(); got != "1.1.1.1:5301" {
		t.Errorf("src addr = %q, want 1.1.1.1:5301", got)
	}
	var plen uint16
	binary.Read(br, binary.BigEndian, &plen)
	payload := make([]byte, plen)
	io.ReadFull(br, payload)
	if string(payload) != "reply-a" {
		t.Errorf("payload = %q, want reply-a", string(payload))
	}
}

// 会话第一个目标是域名时,freedom 交回的回包来源也是域名;封回给客户端前要换成 IP,
// 否则 Surge 这类按 IP 认来源的客户端会把回包丢掉(#1677:以域名发 STUN 的 NAT 测试显示 Blocked)。
func TestUDPFullconeDownlinkDomainSourceBecomesIP(t *testing.T) {
	var out bytes.Buffer
	s := &session{}
	s.bw = buf.NewBufferedWriter(buf.NewWriter(&out))
	s.fw = newFrameWriter(s.bw)

	dest := net.UDPDestination(net.ParseAddress("localhost"), 3478)
	st := &stream{sid: 9, uotConnected: false, uotDest: dest}
	link := &transport.Link{Reader: &oneShotUDPReader{src: dest, payload: "stun-reply"}}

	s.udpDownlink(st, link)

	raw := out.Bytes()
	if len(raw) < 7 {
		t.Fatalf("frame too short: %d bytes", len(raw))
	}
	body := raw[7 : 7+int(binary.BigEndian.Uint16(raw[5:7]))]
	addr, err := uot.AddrParser.ReadAddrPort(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("parse src addr: %v", err)
	}
	if addr.IsFqdn() {
		t.Fatalf("回包来源仍是域名 %q,应换成 IP", addr.Fqdn)
	}
	if !addr.Addr.IsLoopback() || addr.Port != 3478 {
		t.Fatalf("回包来源 = %s,应为 localhost 解析出的回环地址:3478", addr)
	}
}
