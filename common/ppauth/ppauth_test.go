package ppauth

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

func header(src, dst string) *proxyproto.Header {
	s, _ := net.ResolveTCPAddr("tcp", src)
	d, _ := net.ResolveTCPAddr("tcp", dst)
	return proxyproto.HeaderProxyFromAddrs(2, s, d)
}

// 写出去再读回来:签名要经得起序列化,接收方拿到的才是这份字节。
func wire(t *testing.T, h *proxyproto.Header) *proxyproto.Header {
	t.Helper()
	var buf bytes.Buffer
	if _, err := h.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := proxyproto.Read(bufio.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k, _ := NewKey(3)
	now := time.Unix(1_800_000_000, 0)
	for _, addrs := range [][2]string{{"203.0.113.9:51000", "198.51.100.2:443"}, {"[2001:db8::9]:51000", "[2001:db8::2]:443"}} {
		h := header(addrs[0], addrs[1])
		if err := Sign(h, k, "c13:p42210", now); err != nil {
			t.Fatal(err)
		}
		v := NewVerifier("c13:p42210", []Key{k})
		v.now = func() time.Time { return now.Add(30 * time.Second) }
		if err := v.Verify(wire(t, h)); err != nil {
			t.Fatalf("%v: 有效签名应通过: %v", addrs, err)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	k, _ := NewKey(1)
	other, _ := NewKey(1)
	now := time.Unix(1_800_000_000, 0)
	signed := func() *proxyproto.Header {
		h := header("203.0.113.9:51000", "198.51.100.2:443")
		if err := Sign(h, k, "c13:p42210", now); err != nil {
			t.Fatal(err)
		}
		return wire(t, h)
	}
	verifier := func(ctx string, keys ...Key) *Verifier {
		v := NewVerifier(ctx, keys)
		v.now = func() time.Time { return now }
		return v
	}

	if err := verifier("c13:p42210", k).Verify(header("203.0.113.9:51000", "198.51.100.2:443")); err != ErrNoSignature {
		t.Fatalf("没签名应拒: %v", err)
	}
	if err := verifier("c13:p42210", other).Verify(signed()); err != ErrBadMAC {
		t.Fatalf("同编号不同密钥应拒: %v", err)
	}
	if err := verifier("c14:p42210", k).Verify(signed()); err != ErrBadMAC {
		t.Fatalf("别的链(context 不同)应拒: %v", err)
	}
	k9 := Key{ID: 9, Secret: k.Secret}
	if err := verifier("c13:p42210", k9).Verify(signed()); err != ErrUnknownKey {
		t.Fatalf("密钥编号不认识应拒: %v", err)
	}

	// 篡改源地址:签名绑定了地址
	h := signed()
	h.SourceAddr = &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 51000}
	if err := verifier("c13:p42210", k).Verify(h); err != ErrBadMAC {
		t.Fatalf("改了源地址应拒: %v", err)
	}

	// 过期 / 时钟超前
	v := verifier("c13:p42210", k)
	v.now = func() time.Time { return now.Add(Window + time.Second) }
	if err := v.Verify(signed()); err != ErrExpired {
		t.Fatalf("过期应拒: %v", err)
	}
	v.now = func() time.Time { return now.Add(-Window - time.Second) }
	if err := v.Verify(signed()); err != ErrExpired {
		t.Fatalf("时间戳超前太多应拒: %v", err)
	}

	// 重放:同一个头第二次
	v = verifier("c13:p42210", k)
	one := signed()
	if err := v.Verify(one); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(one); err != ErrReplay {
		t.Fatalf("重放应拒: %v", err)
	}
}

// 轮换期新旧两把都认;其它 TLV 原样保留;重复签名只留一个签名 TLV。
func TestRotationAndOtherTLVs(t *testing.T) {
	oldK, _ := NewKey(1)
	newK, _ := NewKey(2)
	now := time.Unix(1_800_000_000, 0)
	h := header("203.0.113.9:51000", "198.51.100.2:443")
	if err := h.SetTLVs([]proxyproto.TLV{{Type: proxyproto.PP2_TYPE_AUTHORITY, Value: []byte("example.com")}}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(h, oldK, "ctx", now); err != nil {
		t.Fatal(err)
	}
	if err := Sign(h, newK, "ctx", now); err != nil {
		t.Fatal(err)
	}
	got := wire(t, h)
	tlvs, _ := got.TLVs()
	sigs, auth := 0, false
	for _, tl := range tlvs {
		if tl.Type == TLVType {
			sigs++
		}
		if tl.Type == proxyproto.PP2_TYPE_AUTHORITY && string(tl.Value) == "example.com" {
			auth = true
		}
	}
	if sigs != 1 || !auth {
		t.Fatalf("应只有一个签名 TLV 且保留其它 TLV: sigs=%d authority=%v", sigs, auth)
	}
	v := NewVerifier("ctx", []Key{oldK, newK})
	v.now = func() time.Time { return now }
	if err := v.Verify(got); err != nil {
		t.Fatalf("新密钥签的应被认: %v", err)
	}
}

func TestParseKey(t *testing.T) {
	k, _ := NewKey(7)
	got, err := ParseKey(k.String())
	if err != nil || got.ID != 7 || !bytes.Equal(got.Secret, k.Secret) {
		t.Fatalf("往返失败: %v %+v", err, got)
	}
	for _, bad := range []string{"", "7", "x:AAAA", "300:" + k.String()[2:], "7:c2hvcnQ="} {
		if _, err := ParseKey(bad); err == nil {
			t.Fatalf("%q 应解析失败", bad)
		}
	}
	if NewVerifier("ctx", nil) != nil {
		t.Fatal("没有密钥时不该验签")
	}
}
