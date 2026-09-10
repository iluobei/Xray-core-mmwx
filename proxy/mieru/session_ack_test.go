package mieru

import (
	"bytes"
	"testing"
)

// #673:mihomo(用官方 enfein/mieru 库)以 HANDSHAKE_NO_WAIT + 多路复用连上来后,
// 会话跑几个来回就整体静默 —— TCP 正常 ACK、无 RST 无丢包,应用层却不再产出数据。
// 小载荷能通、HTTPS 这类大载荷必现。
//
// 根因:出站段的 unackSeq 恒为 0,我方从不捎带累积确认。官方客户端按
// inflight = sndNext - sndUnack 做流控,sndUnack 只由对端捎带的 unackSeq 推进,
// 于是它认为一个段都没被确认,发满一个窗口后永久阻塞。
//
// 下面这些测试盯的就是「水位有没有被推进、有没有真的写进出站段」。

// newTestSession 造一个把段写进 buf 的会话(不接真实 link,只测元数据)。
func newTestSession(t *testing.T, buf *bytes.Buffer) *serverSession {
	t.Helper()
	key, _ := deriveKey(hashPassword("alice", "secret123"), timeSalt(1784817120))
	aead, _ := newAEAD(key)
	nonce := make([]byte, nonceLen)
	return &serverSession{
		id:     42,
		writer: &lockedWriter{w: newSegmentWriter(buf, aead, nonce)},
	}
}

// readBackSegments 把 buf 里的段解回来(与写出用同一把 key/nonce 起点)。
func readBackSegments(t *testing.T, buf *bytes.Buffer, n int) []*segment {
	t.Helper()
	key, _ := deriveKey(hashPassword("alice", "secret123"), timeSalt(1784817120))
	aead, _ := newAEAD(key)
	nonce := make([]byte, nonceLen)
	// 写出方会在首段前放一次 24 字节 nonce;真实链路上由调用方先读掉并据此认用户,
	// segmentReader 拿到的是已经跳过 nonce 的流。
	if buf.Len() >= nonceLen {
		got := make([]byte, nonceLen)
		_, _ = buf.Read(got)
		if !bytes.Equal(got, nonce) {
			t.Fatalf("首段 nonce 前缀不符: %x", got)
		}
	}
	r := newSegmentReader(buf, aead, nonce)
	out := make([]*segment, 0, n)
	for i := 0; i < n; i++ {
		seg, err := r.read()
		if err != nil {
			t.Fatalf("读回第 %d 段失败: %v", i, err)
		}
		out = append(out, seg)
	}
	return out
}

func TestOutboundDataCarriesCumulativeAck(t *testing.T) {
	var buf bytes.Buffer
	ss := newTestSession(t, &buf)

	// 客户端发来 seq 0(openSessionRequest)、1、2
	ss.noteClientSeq(0)
	ss.noteClientSeq(1)
	ss.noteClientSeq(2)

	if err := ss.writeData([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	seg := readBackSegments(t, &buf, 1)[0]

	if seg.unackSeq != 3 {
		t.Errorf("出站段 unackSeq = %d, want 3(已收到 0/1/2,下一个期望 3)。"+
			"恒为 0 时官方客户端流控永不滑动,窗口填满即僵死(#673)", seg.unackSeq)
	}
	if seg.window == 0 {
		t.Error("window = 0,客户端会认为不允许再发")
	}
	if string(seg.payload) != "hello" {
		t.Errorf("payload = %q", seg.payload)
	}
}

// 水位只能前进。重复/乱序段(TCP 下理论上不出现)让它倒退的话,客户端会把
// 已确认的段重新算进 inflight,窗口再次卡死。
func TestAckWatermarkNeverGoesBackwards(t *testing.T) {
	ss := &serverSession{}
	ss.noteClientSeq(10)
	if got := ss.rcvNext.Load(); got != 11 {
		t.Fatalf("rcvNext = %d, want 11", got)
	}
	for _, stale := range []uint32{0, 3, 9, 10} {
		ss.noteClientSeq(stale)
		if got := ss.rcvNext.Load(); got != 11 {
			t.Errorf("收到旧段 seq=%d 后 rcvNext 退到 %d, want 保持 11", stale, got)
		}
	}
	ss.noteClientSeq(11)
	if got := ss.rcvNext.Load(); got != 12 {
		t.Errorf("新段没能推进水位: rcvNext = %d, want 12", got)
	}
}

// seq 是 uint32,长连接会绕回 0。绕回处必须继续前进,否则一次回绕就把会话卡死。
func TestAckWatermarkWrapsAround(t *testing.T) {
	ss := &serverSession{}
	ss.rcvNext.Store(0xFFFFFFFE)
	ss.noteClientSeq(0xFFFFFFFE) // → 0xFFFFFFFF
	if got := ss.rcvNext.Load(); got != 0xFFFFFFFF {
		t.Fatalf("rcvNext = %#x, want 0xFFFFFFFF", got)
	}
	ss.noteClientSeq(0xFFFFFFFF) // → 0(回绕)
	if got := ss.rcvNext.Load(); got != 0 {
		t.Errorf("回绕后 rcvNext = %#x, want 0 —— 卡在这里会让长连接必然僵死", got)
	}
	ss.noteClientSeq(0) // → 1
	if got := ss.rcvNext.Load(); got != 1 {
		t.Errorf("回绕后无法继续前进: rcvNext = %d, want 1", got)
	}
}

// 大响应会被切成多段,每段都要带上当时的水位 —— 只有首段带的话,
// 客户端在后续段上依然拿不到新的确认。
func TestEveryFragmentCarriesAck(t *testing.T) {
	var buf bytes.Buffer
	ss := newTestSession(t, &buf)
	ss.noteClientSeq(6) // rcvNext = 7

	payload := bytes.Repeat([]byte("x"), maxFragmentLen*2+123)
	if err := ss.writeData(payload); err != nil {
		t.Fatal(err)
	}
	segs := readBackSegments(t, &buf, 3)
	total := 0
	for i, seg := range segs {
		if seg.unackSeq != 7 {
			t.Errorf("第 %d 片 unackSeq = %d, want 7", i, seg.unackSeq)
		}
		if seg.seq != uint32(i) {
			t.Errorf("第 %d 片 seq = %d, want %d", i, seg.seq, i)
		}
		total += len(seg.payload)
	}
	if total != len(payload) {
		t.Errorf("分片后总长 %d, want %d", total, len(payload))
	}
}
