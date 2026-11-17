// Package ppauth 给 PROXY protocol v2 头签名 / 验签(转发链透传客户端 IP 用)。
//
// 头里加一个自定义 TLV(类型 0xE5,在 PROXY v2 规范留给私用的 0xE0–0xEF 里),里面是用这条链的密钥
// 对头里的地址算出的 HMAC。配了密钥的接收方只采信签名有效、没过期、没重放过的头;
// 不认识这个 TLV 的接收方(nginx、HAProxy、go-proxyproto 等)按规范忽略它,照样读出客户端地址。
//
// TLV 内容(30 字节):版本(1) | 密钥编号(1) | 时间戳 unix 秒(4,大端) | 随机数(8) | MAC(16)
// MAC = HMAC-SHA256(密钥, "mmwx-ppauth" 0x00 context 0x00 版本 编号 时间戳 随机数 源 IP(16) 源端口(2) 目标 IP(16) 目标端口(2)) 的前 16 字节。
// IP 一律按 16 字节(IPv4 用 v4-mapped)参与计算,签名方与验证方对同一个头得到同一串字节。
package ppauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
)

const (
	// TLVType 签名 TLV 的类型(PROXY v2 私用段)。
	TLVType proxyproto.PP2Type = 0xE5

	version = 1
	tlvLen  = 1 + 1 + 4 + 8 + 16
	macLen  = 16

	// Window 时间戳前后允许的偏差。各跳时钟要在这个范围内,出口才认。
	Window = 120 * time.Second
)

var (
	ErrNoSignature = errors.New("ppauth: 头里没有签名")
	ErrMalformed   = errors.New("ppauth: 签名格式不对")
	ErrUnknownKey  = errors.New("ppauth: 密钥编号不认识")
	ErrBadMAC      = errors.New("ppauth: 签名不对")
	ErrExpired     = errors.New("ppauth: 签名过期(或者两台机器时钟差太多)")
	ErrReplay      = errors.New("ppauth: 签名重放")
	ErrNoAddress   = errors.New("ppauth: 头里没有 TCP 地址")
)

// Key 一把签名密钥。
type Key struct {
	ID     byte
	Secret []byte
}

// String 写成配置里用的 "<编号>:<base64 密钥>"。
func (k Key) String() string {
	return strconv.Itoa(int(k.ID)) + ":" + base64.StdEncoding.EncodeToString(k.Secret)
}

// ParseKey 解析 "<编号>:<base64 密钥>"。
func ParseKey(s string) (Key, error) {
	idText, secret, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return Key{}, fmt.Errorf("ppauth: 密钥格式应为 <编号>:<base64>")
	}
	id, err := strconv.Atoi(idText)
	if err != nil || id < 0 || id > 255 {
		return Key{}, fmt.Errorf("ppauth: 密钥编号不对: %q", idText)
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil || len(raw) < 16 {
		return Key{}, fmt.Errorf("ppauth: 密钥要是至少 16 字节的 base64")
	}
	return Key{ID: byte(id), Secret: raw}, nil
}

// ParseKeys 解析一组密钥;写错的项跳过(只会少认,不会多认)。
func ParseKeys(list []string) []Key {
	out := make([]Key, 0, len(list))
	for _, s := range list {
		if k, err := ParseKey(s); err == nil {
			out = append(out, k)
		}
	}
	return out
}

// NewKey 生成一把 32 字节的随机密钥。
func NewKey(id byte) (Key, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return Key{}, err
	}
	return Key{ID: id, Secret: secret}, nil
}

func addrBytes(a net.Addr) ([16]byte, uint16, bool) {
	var ip16 [16]byte
	tcp, ok := a.(*net.TCPAddr)
	if !ok || tcp == nil || tcp.IP == nil {
		return ip16, 0, false
	}
	ip := tcp.IP.To16()
	if ip == nil {
		return ip16, 0, false
	}
	copy(ip16[:], ip)
	return ip16, uint16(tcp.Port), true
}

func mac(secret []byte, context string, keyID byte, ts uint32, nonce []byte, src, dst net.Addr) ([]byte, error) {
	sIP, sPort, ok1 := addrBytes(src)
	dIP, dPort, ok2 := addrBytes(dst)
	if !ok1 || !ok2 {
		return nil, ErrNoAddress
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("mmwx-ppauth"))
	m.Write([]byte{0})
	m.Write([]byte(context))
	m.Write([]byte{0, version, keyID})
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ts)
	m.Write(b[:])
	m.Write(nonce)
	m.Write(sIP[:])
	binary.BigEndian.PutUint16(b[:2], sPort)
	m.Write(b[:2])
	m.Write(dIP[:])
	binary.BigEndian.PutUint16(b[:2], dPort)
	m.Write(b[:2])
	return m.Sum(nil)[:macLen], nil
}

// Sign 给头加上签名 TLV(已有的签名 TLV 先去掉,其它 TLV 原样保留)。头必须是 v2、带 TCP 地址。
func Sign(h *proxyproto.Header, k Key, context string, now time.Time) error {
	if h == nil || h.Version != 2 {
		return ErrMalformed
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ts := uint32(now.Unix())
	sum, err := mac(k.Secret, context, k.ID, ts, nonce, h.SourceAddr, h.DestinationAddr)
	if err != nil {
		return err
	}
	val := make([]byte, 0, tlvLen)
	val = append(val, version, k.ID)
	val = binary.BigEndian.AppendUint32(val, ts)
	val = append(val, nonce...)
	val = append(val, sum...)
	tlvs, err := h.TLVs()
	if err != nil {
		tlvs = nil
	}
	kept := tlvs[:0]
	for _, t := range tlvs {
		if t.Type != TLVType {
			kept = append(kept, t)
		}
	}
	kept = append(kept, proxyproto.TLV{Type: TLVType, Value: val})
	return h.SetTLVs(kept)
}

// Verifier 出口验签:认一组密钥,记着见过的随机数防重放。
type Verifier struct {
	context string
	keys    map[byte][]byte
	now     func() time.Time

	// 见过的随机数,分两代:每 2×Window 整代轮换一次(cur → old,old 丢掉),查重看两代。
	// 一个随机数至少留 2×Window,够覆盖它的签名还有效的时间;查和清都是 O(1),不用扫表。
	mu    sync.Mutex
	cur   map[[8]byte]struct{}
	old   map[[8]byte]struct{}
	rotAt int64 // 下次轮换的时间(unix 秒)
}

// NewVerifier keys 为空时返回 nil(不验签)。
func NewVerifier(context string, keys []Key) *Verifier {
	if len(keys) == 0 {
		return nil
	}
	v := &Verifier{context: context, keys: map[byte][]byte{}, now: time.Now, cur: map[[8]byte]struct{}{}, old: map[[8]byte]struct{}{}}
	for _, k := range keys {
		v.keys[k.ID] = k.Secret
	}
	return v
}

// Verify 检查头上的签名。随机数只在签名完全有效时才记下,无效的头不会挤占防重放表。
func (v *Verifier) Verify(h *proxyproto.Header) error {
	if h == nil {
		return ErrNoSignature
	}
	tlvs, err := h.TLVs()
	if err != nil {
		return ErrMalformed
	}
	var val []byte
	for _, t := range tlvs {
		if t.Type == TLVType {
			val = t.Value
		}
	}
	if val == nil {
		return ErrNoSignature
	}
	if len(val) != tlvLen || val[0] != version {
		return ErrMalformed
	}
	keyID := val[1]
	secret, ok := v.keys[keyID]
	if !ok {
		return ErrUnknownKey
	}
	ts := binary.BigEndian.Uint32(val[2:6])
	nonce := val[6:14]
	want, err := mac(secret, v.context, keyID, ts, nonce, h.SourceAddr, h.DestinationAddr)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, val[14:]) {
		return ErrBadMAC
	}
	now := v.now()
	signed := time.Unix(int64(ts), 0)
	if signed.Before(now.Add(-Window)) || signed.After(now.Add(Window)) {
		return ErrExpired
	}
	var n [8]byte
	copy(n[:], nonce)
	v.mu.Lock()
	defer v.mu.Unlock()
	nowUnix := now.Unix()
	if nowUnix >= v.rotAt {
		gen := int64(2 * Window / time.Second)
		if nowUnix >= v.rotAt+gen {
			v.old = map[[8]byte]struct{}{} // 两代都过期了(很久没连接)
		} else {
			v.old = v.cur
		}
		v.cur = map[[8]byte]struct{}{}
		v.rotAt = nowUnix + gen
	}
	if _, dup := v.cur[n]; dup {
		return ErrReplay
	}
	if _, dup := v.old[n]; dup {
		return ErrReplay
	}
	// 只有签名完全有效的才记:塞满它只能靠有效签名,而有效签名只有持有密钥的一方能产出。
	v.cur[n] = struct{}{}
	return nil
}
