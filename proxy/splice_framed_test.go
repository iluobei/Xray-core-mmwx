package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// 分段直通:每段之前入站先在连接上写一个分段头(这里用 4 字节长度),目标读完后入站还能接着写。
// 对端按「长度 · 数据」解出来的字节必须与源完全一致,且 Handoff 之前交给 link 的数据排在最前面。
// darwin 上 io.CopyN 不是真 splice,但分段、记账、收尾的逻辑就是生产这一份。

type testFramer struct {
	t       *testing.T
	conn    net.Conn
	pending []byte // 还留在「link」里、要在 Handoff 时先写上线的数据
	segs    int
	// stopAfter > 0:写过这么多段之后 Segment 返回 false(入站叫停)
	stopAfter int
	inSegment bool
	finish    chan error
}

func (f *testFramer) Handoff(closeLink func()) error {
	closeLink()
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(f.pending)))
	_, err := f.conn.Write(append(hdr, f.pending...))
	return err
}

func (f *testFramer) Segment(n int64) (bool, error) {
	if n <= 0 || n > spliceSegmentMax {
		f.t.Errorf("segment of %d bytes", n)
	}
	if f.stopAfter > 0 && f.segs >= f.stopAfter {
		return false, nil
	}
	if f.inSegment {
		f.t.Error("Segment before the previous one was reported written")
	}
	f.inSegment = true
	f.segs++
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(n))
	_, err := f.conn.Write(hdr)
	return true, err
}

func (f *testFramer) Written() { f.inSegment = false }

func (f *testFramer) Finish(err error) { f.finish <- err }

func tcpPair(t *testing.T) (a, b *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		done <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-done
	t.Cleanup(func() { c.Close(); s.Close() })
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

func TestSpliceFramed(t *testing.T) {
	destRemote, destLocal := tcpPair(t) // 目标 → 出站
	inLocal, client := tcpPair(t)       // 入站 → 客户端

	payload := make([]byte, 5<<20+12345)
	_, _ = rand.Read(payload)
	head := []byte("already-in-the-link")

	go func() {
		// 分几批写,中间停顿:要跨很多段,也要经过「缓冲空了等数据」那条路
		for i := 0; i < len(payload); {
			n := 700_000
			if n > len(payload)-i {
				n = len(payload) - i
			}
			_, _ = destRemote.Write(payload[i : i+n])
			i += n
			time.Sleep(2 * time.Millisecond)
		}
		_ = destRemote.CloseWrite()
	}()

	f := &testFramer{t: t, conn: inLocal, pending: head, finish: make(chan error, 1)}
	var accounted int64
	linkClosed := false
	errc := make(chan error, 1)
	go func() {
		errc <- spliceFramed(inLocal, destLocal, f, func() { linkClosed = true }, func(n int64) { accounted += n })
	}()

	// 客户端:按「长度 · 数据」读,直到收够
	var got []byte
	_ = client.SetReadDeadline(time.Now().Add(20 * time.Second))
	for len(got) < len(head)+len(payload) {
		var hdr [4]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			t.Fatalf("read segment header after %d bytes: %v", len(got), err)
		}
		seg := make([]byte, binary.BigEndian.Uint32(hdr[:]))
		if _, err := io.ReadFull(client, seg); err != nil {
			t.Fatalf("read segment body: %v", err)
		}
		got = append(got, seg...)
	}
	if err := <-errc; err != nil {
		t.Fatalf("spliceFramed: %v", err)
	}
	if err := <-f.finish; err != nil {
		t.Fatalf("Finish got %v", err)
	}
	if !linkClosed {
		t.Fatal("Handoff did not get to close the link")
	}
	if !bytes.Equal(got, append(head, payload...)) {
		t.Fatal("bytes changed or reordered")
	}
	if accounted != int64(len(payload)) {
		t.Fatalf("accounted %d of %d bytes", accounted, len(payload))
	}
	if f.segs < 2 {
		t.Fatalf("only %d segment(s)", f.segs)
	}

	// 直通结束后入站还能在同一条连接上接着写(通道复用靠的就是这个)
	if _, err := inLocal.Write([]byte{0, 0, 0, 3, 'e', 'n', 'd'}); err != nil {
		t.Fatal(err)
	}
	tail := make([]byte, 7)
	if _, err := io.ReadFull(client, tail); err != nil || string(tail[4:]) != "end" {
		t.Fatalf("connection not usable after the splice: %q %v", tail, err)
	}
}

// 两段之间源连接出错(对端重置 / 本端取消):每一段都是完整的,Finish 拿到 nil,入站还能接着用连接。
func TestSpliceFramedSourceErrorBetweenSegments(t *testing.T) {
	destRemote, destLocal := tcpPair(t)
	inLocal, client := tcpPair(t)
	go func() { _, _ = io.Copy(io.Discard, client) }()

	f := &testFramer{t: t, conn: inLocal, finish: make(chan error, 1)}
	errc := make(chan error, 1)
	go func() { errc <- spliceFramed(inLocal, destLocal, f, func() {}, func(int64) {}) }()

	_, _ = destRemote.Write(make([]byte, 100_000))
	time.Sleep(100 * time.Millisecond) // 等这批搬完,循环停在「等下一批」上
	_ = destLocal.Close()              // 本端取消:出站关掉目标连接
	if err := <-errc; err == nil {
		t.Fatal("expected the source error to be returned")
	}
	if err := <-f.finish; err != nil {
		t.Fatalf("Finish got %v for an error between segments", err)
	}
	if _, err := inLocal.Write([]byte{0}); err != nil {
		t.Fatalf("inbound connection unusable: %v", err)
	}
}

// 入站叫停(Segment 返回 false):已经声明的段都写完了,之后不再写;Finish 拿到 nil,连接还能接着用。
func TestSpliceFramedStoppedByInbound(t *testing.T) {
	destRemote, destLocal := tcpPair(t)
	inLocal, client := tcpPair(t)

	go func() {
		chunk := make([]byte, 64<<10)
		for {
			if _, err := destRemote.Write(chunk); err != nil {
				return
			}
		}
	}()
	f := &testFramer{t: t, conn: inLocal, finish: make(chan error, 1), stopAfter: 3}
	errc := make(chan error, 1)
	go func() { errc <- spliceFramed(inLocal, destLocal, f, func() {}, func(int64) {}) }()

	// 读掉 Handoff 的头和 3 段,之后连接上不该再有任何字节
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < 4; i++ {
		var hdr [4]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(io.Discard, client, int64(binary.BigEndian.Uint32(hdr[:]))); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("spliceFramed: %v", err)
	}
	if err := <-f.finish; err != nil {
		t.Fatalf("Finish got %v", err)
	}
	if _, err := inLocal.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	next := make([]byte, 4)
	if _, err := io.ReadFull(client, next); err != nil || string(next) != "next" {
		t.Fatalf("stray bytes after the inbound stopped the splice: %q %v", next, err)
	}
}
