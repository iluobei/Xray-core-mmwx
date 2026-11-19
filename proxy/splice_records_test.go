package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	mrand "math/rand"
	"net"
	"testing"
	"time"
)

// recordFramer 实现 SpliceFramerRecords:每一块写成「类型(S 段 / D 数据)· 4 字节长度 · 字节」,
// 交给 Data 的字节沿 TLS 记录头跟踪边界(同 Miu 入站)。
type recordFramer struct {
	t      *testing.T
	conn   net.Conn
	need   int
	hdr    []byte
	lost   bool
	segs   int
	datas  int
	finish chan error
}

func (f *recordFramer) walk(p []byte) {
	for len(p) > 0 && !f.lost {
		if f.need > 0 {
			k := min(f.need, len(p))
			f.need -= k
			p = p[k:]
			continue
		}
		k := min(5-len(f.hdr), len(p))
		f.hdr = append(f.hdr, p[:k]...)
		p = p[k:]
		if len(f.hdr) < 5 {
			return
		}
		if f.hdr[1] != 3 || f.hdr[0] < 0x14 || f.hdr[0] > 0x17 {
			f.lost = true
			return
		}
		f.need = int(binary.BigEndian.Uint16(f.hdr[3:]))
		f.hdr = f.hdr[:0]
	}
}

func (f *recordFramer) put(typ byte, p []byte) error {
	b := append([]byte{typ, 0, 0, 0, 0}, p...)
	binary.BigEndian.PutUint32(b[1:], uint32(len(p)))
	_, err := f.conn.Write(b)
	return err
}

func (f *recordFramer) Owed() int {
	switch {
	case f.lost:
		return -1
	case f.need > 0:
		return f.need
	case len(f.hdr) > 0:
		return 5 - len(f.hdr)
	}
	return 0
}

func (f *recordFramer) Handoff(closeLink func()) error { closeLink(); return nil }

func (f *recordFramer) Segment(n int64) (bool, error) {
	if f.Owed() != 0 {
		f.t.Errorf("a segment while %d bytes are owed", f.Owed())
	}
	f.segs++
	b := []byte{'S', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(n))
	_, err := f.conn.Write(b)
	return true, err
}

func (f *recordFramer) Data(p []byte) (bool, error) {
	f.datas++
	f.walk(p)
	return true, f.put('D', p)
}

func (f *recordFramer) Written()         {}
func (f *recordFramer) Finish(err error) { f.finish <- err }

// tlsRecords 生成 count 条随机长度的 TLS 记录,返回字节与每条记录结尾的偏移。
func tlsRecords(count int, r *mrand.Rand) (data []byte, ends map[int]bool) {
	ends = map[int]bool{0: true}
	for i := 0; i < count; i++ {
		n := 16384 + 17
		if r.Intn(3) == 0 {
			n = 1 + r.Intn(3000)
		}
		body := make([]byte, n)
		_, _ = rand.Read(body)
		data = append(data, 0x17, 3, 3, byte(n>>8), byte(n))
		data = append(data, body...)
		ends[len(data)] = true
	}
	return data, ends
}

// readPieces 按 recordFramer 的格式读到收够 total 个字节,检查每一段的起止都在记录边界上,返回拼起来的字节。
func readPieces(t *testing.T, c net.Conn, total int, ends map[int]bool) (got []byte, segBytes int) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	for len(got) < total {
		var h [5]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			t.Fatalf("after %d bytes: %v", len(got), err)
		}
		p := make([]byte, binary.BigEndian.Uint32(h[1:]))
		if _, err := io.ReadFull(c, p); err != nil {
			t.Fatal(err)
		}
		if h[0] == 'S' {
			if !ends[len(got)] || !ends[len(got)+len(p)] {
				t.Fatalf("segment [%d, %d) is not whole records", len(got), len(got)+len(p))
			}
			segBytes += len(p)
		}
		got = append(got, p...)
	}
	return got, segBytes
}

// 源按随机大小、带停顿地写一串 TLS 记录:直通的每一段都是完整的记录,字节不变,大部分字节走直通。
func TestSpliceFramedRecords(t *testing.T) {
	r := mrand.New(mrand.NewSource(1))
	data, ends := tlsRecords(400, r)
	destRemote, destLocal := tcpPair(t)
	inLocal, client := tcpPair(t)
	go func() {
		for i := 0; i < len(data); {
			n := min(1+r.Intn(200_000), len(data)-i)
			_, _ = destRemote.Write(data[i : i+n])
			i += n
			if r.Intn(4) == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		_ = destRemote.CloseWrite()
	}()
	f := &recordFramer{t: t, conn: inLocal, finish: make(chan error, 1)}
	var accounted int64
	errc := make(chan error, 1)
	go func() {
		errc <- spliceFramed(inLocal, destLocal, f, func() {}, func(n int64) { accounted += n }, nil, nil)
	}()
	got, segBytes := readPieces(t, client, len(data), ends)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if err := <-f.finish; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) || accounted != int64(len(data)) {
		t.Fatalf("bytes changed (accounted %d of %d)", accounted, len(data))
	}
	if segBytes < len(data)*3/4 {
		t.Fatalf("only %d of %d bytes went through segments (%d segments, %d data)", segBytes, len(data), f.segs, f.datas)
	}
}

// 交接时停在一条记录中间(这条记录的开头已经走了用户态),以及一条记录后半截迟迟不到:已到的部分与剩下的都走 Data,
// 之后从记录边界接着直通。
func TestSpliceFramedRecordsOwedAndLate(t *testing.T) {
	r := mrand.New(mrand.NewSource(2))
	data, ends := tlsRecords(20, r)
	destRemote, destLocal := tcpPair(t)
	inLocal, client := tcpPair(t)
	// 交接之前入站已经发出第一条记录的前 7 个字节
	f := &recordFramer{t: t, conn: inLocal, finish: make(chan error, 1)}
	f.walk(data[:7])
	ends2 := map[int]bool{}
	for e := range ends {
		if e >= 7 {
			ends2[e-7] = true
		}
	}
	rest := data[7:]
	split := len(rest) - 9000 // 最后一条满长记录里切开
	go func() {
		_, _ = destRemote.Write(rest[:split])
		time.Sleep(200 * time.Millisecond)
		_, _ = destRemote.Write(rest[split:])
		_ = destRemote.CloseWrite()
	}()
	errc := make(chan error, 1)
	go func() { errc <- spliceFramed(inLocal, destLocal, f, func() {}, func(int64) {}, nil, nil) }()
	got, _ := readPieces(t, client, len(rest), ends2)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if err := <-f.finish; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, rest) {
		t.Fatal("bytes changed")
	}
	if f.segs == 0 || f.datas < 3 {
		t.Fatalf("%d segments, %d data pieces", f.segs, f.datas)
	}
}

// 闸门一次放行的比一条记录还少:放行的攒着,够一条记录才搬;搬过的字节从不超过放行的总数,段照样是完整记录。
func TestSpliceFramedRecordsGate(t *testing.T) {
	r := mrand.New(mrand.NewSource(3))
	data, ends := tlsRecords(60, r)
	destRemote, destLocal := tcpPair(t)
	inLocal, client := tcpPair(t)
	go func() {
		_, _ = destRemote.Write(data)
		_ = destRemote.CloseWrite()
	}()
	f := &recordFramer{t: t, conn: inLocal, finish: make(chan error, 1)}
	var granted, moved int64
	gate := func(n int64) int64 {
		n = min(n, 10<<10)
		granted += n
		return n
	}
	account := func(n int64) {
		moved += n
	}
	errc := make(chan error, 1)
	go func() { errc <- spliceFramed(inLocal, destLocal, f, func() {}, account, nil, gate) }()
	got, segBytes := readPieces(t, client, len(data), ends)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if err := <-f.finish; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("bytes changed")
	}
	if int64(segBytes) > granted {
		t.Fatalf("segments moved %d bytes, the gate granted %d", segBytes, granted)
	}
	if granted > int64(len(data))+10<<10 {
		t.Fatalf("granted %d for %d bytes: tokens wasted on the cuts", granted, len(data))
	}
	if f.segs == 0 {
		t.Fatal("no segments")
	}
}

// 不是 TLS 记录的字节:入站跟丢边界,余下的全走 Data,一个字节不差。
func TestSpliceFramedRecordsNotTLS(t *testing.T) {
	data := make([]byte, 300<<10)
	_, _ = rand.Read(data)
	data[0], data[1] = 0x50, 0x51
	destRemote, destLocal := tcpPair(t)
	inLocal, client := tcpPair(t)
	go func() {
		_, _ = destRemote.Write(data)
		_ = destRemote.CloseWrite()
	}()
	f := &recordFramer{t: t, conn: inLocal, finish: make(chan error, 1)}
	errc := make(chan error, 1)
	go func() { errc <- spliceFramed(inLocal, destLocal, f, func() {}, func(int64) {}, nil, nil) }()
	got, segBytes := readPieces(t, client, len(data), map[int]bool{})
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if err := <-f.finish; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) || segBytes != 0 || !f.lost {
		t.Fatalf("segments %d bytes, lost %v", segBytes, f.lost)
	}
}

// 等着的字节正好是几条完整的小记录(不到 spliceSmall):它们走 Data,之后不能再按同样的长度直通一段
// (那会搬走后面的字节,段就切在记录中间了)。握手后服务端单独发的 NewSessionTicket 就是这种情况。
func TestSpliceFramedRecordsSmallWholeThenMore(t *testing.T) {
	var data []byte
	ends := map[int]bool{0: true}
	add := func(n int) {
		data = append(data, 0x17, 3, 3, byte(n>>8), byte(n))
		data = append(data, bytes.Repeat([]byte{byte(n)}, n)...)
		ends[len(data)] = true
	}
	add(200)
	add(300)
	small := len(data)
	for i := 0; i < 30; i++ {
		add(16384 + 17)
	}
	destRemote, destLocal := tcpPair(t)
	inLocal, client := tcpPair(t)
	go func() {
		_, _ = destRemote.Write(data[:small])
		time.Sleep(100 * time.Millisecond)
		_, _ = destRemote.Write(data[small:])
		_ = destRemote.CloseWrite()
	}()
	f := &recordFramer{t: t, conn: inLocal, finish: make(chan error, 1)}
	errc := make(chan error, 1)
	go func() { errc <- spliceFramed(inLocal, destLocal, f, func() {}, func(int64) {}, nil, nil) }()
	got, segBytes := readPieces(t, client, len(data), ends)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if err := <-f.finish; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) || f.lost || segBytes == 0 {
		t.Fatalf("bytes equal %v, lost %v, segments %d bytes", bytes.Equal(got, data), f.lost, segBytes)
	}
}
