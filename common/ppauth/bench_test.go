package ppauth

import (
	"encoding/binary"
	"github.com/pires/go-proxyproto"
	"testing"
	"time"
)

func BenchmarkSign(b *testing.B) {
	k, _ := NewKey(1)
	now := time.Now()
	for i := 0; i < b.N; i++ {
		h := header("203.0.113.9:51000", "198.51.100.2:443")
		_ = Sign(h, k, "c13:p42210", now)
	}
}

func benchVerify(b *testing.B, prefill int) {
	k, _ := NewKey(1)
	now := time.Unix(1_800_000_000, 0)
	v := NewVerifier("c13:p42210", []Key{k})
	v.now = func() time.Time { return now }
	for i := 0; i < prefill; i++ { // 窗口内已经见过的连接(都还没过期)
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(i)|1<<63)
		v.cur[n] = struct{}{}
	}
	v.rotAt = now.Unix() + 240
	hs := make([]*testHeader, 0, 1024)
	for i := 0; i < 1024; i++ {
		h := header("203.0.113.9:51000", "198.51.100.2:443")
		_ = Sign(h, k, "c13:p42210", now)
		hs = append(hs, &testHeader{h})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := hs[i%1024].h
		if i%1024 == 0 && i > 0 {
			b.StopTimer()
			for j := range hs {
				nh := header("203.0.113.9:51000", "198.51.100.2:443")
				_ = Sign(nh, k, "c13:p42210", now)
				hs[j] = &testHeader{nh}
			}
			b.StartTimer()
			h = hs[0].h
		}
		_ = v.Verify(h)
	}
}

func BenchmarkVerifyEmpty(b *testing.B)    { benchVerify(b, 0) }
func BenchmarkVerifyFull70k(b *testing.B)  { benchVerify(b, 70000) }
func BenchmarkVerifyFull200k(b *testing.B) { benchVerify(b, 200000) }

type testHeader struct{ h *proxyproto.Header }
