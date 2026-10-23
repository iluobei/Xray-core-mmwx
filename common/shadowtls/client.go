package shadowtls

// ShadowTLS v3 客户端。与 server.go 一样,只按原作者公开的协议文档(ihciah/shadow-tls 的
// docs/protocol-v3-en.md,MIT)独立实现,不含 sing-shadowtls / mihomo 的任何代码(两者是 GPL)。
//
// 流程:
//  1. 用 uTLS(Chrome 指纹)以 ServerName 为 SNI 跟握手服务器做一次真实的 TLS 握手,
//     ClientHello 的 SessionID 末 4 字节 = HMAC(password, 去掉记录头的 ClientHello,这 4 字节按 0 计);
//  2. 握手期间服务端转回来的 ApplicationData 带 HMAC_ServerRandom 标记且被 XOR 过,认出来就去掉标记、
//     XOR 回去再交给 TLS;一帧都认不出说明对面不是自己人(密码错 / 被劫持),握手完即放弃;
//  3. 只接受 TLS 1.3(协议的 strict 要求:TLS 1.2 下抵抗不了连接劫持);
//  4. 之后不再碰 TLS:写出 ApplicationData + HMAC_ServerRandomC,读入校验 HMAC_ServerRandomS,
//     服务端切换前转来的握手残帧(HMAC_ServerRandom 标记)丢弃。

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/errors"
)

const clientHandshakeTimeout = 15 * time.Second

// ClientConfig 一个出站的 ShadowTLS 设置。
type ClientConfig struct {
	Password string
	// ServerName 握手用的 SNI,即服务端配置的握手服务器域名。
	ServerName string
}

// Client 在 conn 上跑 ShadowTLS v3 客户端握手,返回承载内层数据流的 net.Conn。
// 失败时 conn 由调用方关闭。
func Client(ctx context.Context, conn net.Conn, cfg *ClientConfig) (net.Conn, error) {
	if cfg.ServerName == "" {
		return nil, errors.New("shadowtls: server name is required")
	}
	rw := &handshakeReader{Conn: conn, password: cfg.Password}
	// 不验证握手服务器证书:身份靠 HMAC_ServerRandom 标记确认(中间人造不出来),里面的数据另有加密;
	// 也省得精简系统缺根证书时握手失败。这不改变 ClientHello 的样子。
	uconn := utls.UClient(rw, &utls.Config{ServerName: cfg.ServerName, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if err := signClientHello(uconn, cfg.Password); err != nil {
		return nil, err
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, clientHandshakeTimeout)
		defer cancel()
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, errors.New("shadowtls: tls handshake").Base(err)
	}
	if uconn.ConnectionState().Version != utls.VersionTLS13 {
		return nil, errors.New("shadowtls: handshake server did not negotiate TLS 1.3")
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if !rw.verified {
		return nil, errors.New("shadowtls: server not authenticated (wrong password, or connection hijacked)")
	}
	// 握手读端每次最多交出一整条记录,TLS 握手完成时不该还有没交出去的半条。
	if len(rw.pending) != 0 {
		return nil, errors.New("shadowtls: unexpected data left after handshake")
	}
	pw := []byte(cfg.Password)
	return &dataConn{
		Conn:      conn,
		hmacRead:  newStreamHMAC(pw, rw.serverRandom, []byte("S")),
		residual:  rw.hmacSR,
		hmacWrite: newStreamHMAC(pw, rw.serverRandom, []byte("C")),
	}, nil
}

// signClientHello 生成 ClientHello,并把 HMAC 写进 SessionID 末 4 字节。
func signClientHello(uconn *utls.UConn, password string) error {
	if err := uconn.BuildHandshakeState(); err != nil {
		return errors.New("shadowtls: build client hello").Base(err)
	}
	sid := make([]byte, sessionIDLen)
	if _, err := rand.Read(sid[:sessionIDLen-hmacLen]); err != nil {
		return err
	}
	uconn.HandshakeState.Hello.SessionId = sid
	if err := uconn.MarshalClientHello(); err != nil {
		return errors.New("shadowtls: marshal client hello").Base(err)
	}
	// 此刻 Raw(去掉记录头的 ClientHello)里 SessionID 末 4 字节为 0,正好是 HMAC 的输入。
	h := newStreamHMAC([]byte(password))
	h.write(uconn.HandshakeState.Hello.Raw)
	sum := h.sum4()
	sid = append([]byte(nil), sid...)
	copy(sid[sessionIDLen-hmacLen:], sum[:])
	uconn.HandshakeState.Hello.SessionId = sid
	if err := uconn.MarshalClientHello(); err != nil {
		return errors.New("shadowtls: marshal client hello").Base(err)
	}
	// 用服务端的校验函数核对一遍:两次序列化之间除 SessionID 外若有变化(某些扩展每次随机),服务端会认不出。
	raw := uconn.HandshakeState.Hello.Raw
	rec := make([]byte, recordHeaderLen, recordHeaderLen+len(raw))
	rec[0], rec[1], rec[2] = typeHandshake, 0x03, 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(raw)))
	if !verifyClientHello(append(rec, raw...), password) {
		return errors.New("shadowtls: client hello changed between marshals")
	}
	return nil
}

// handshakeReader 是握手期间 TLS 客户端读的那一层:每次只交出一整条记录;
// 认出带 HMAC_ServerRandom 标记的 ApplicationData 就去掉标记、XOR 回去。
type handshakeReader struct {
	net.Conn
	password string

	mu           sync.Mutex
	serverRandom []byte
	hmacSR       *streamHMAC
	key          []byte
	verified     bool // 至少有一帧 ApplicationData 带着正确标记
	pending      []byte
}

func (r *handshakeReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.pending) == 0 {
		rec, err := readRecord(r.Conn)
		if err != nil {
			return 0, err
		}
		switch {
		case rec[0] == typeHandshake && r.serverRandom == nil:
			if sr, ok := extractServerRandom(rec); ok {
				r.serverRandom = sr
				r.hmacSR = newStreamHMAC([]byte(r.password), sr)
				r.key = xorKey(r.password, sr)
			}
		case rec[0] == typeApplicationData && r.hmacSR != nil && len(rec) >= recordHeaderLen+hmacLen:
			data := rec[recordHeaderLen+hmacLen:]
			h := r.hmacSR.clone()
			h.write(data)
			if sum := h.sum4(); bytes.Equal(sum[:], rec[recordHeaderLen:recordHeaderLen+hmacLen]) {
				r.hmacSR = h
				r.verified = true
				xorCycle(data, r.key)
				out := make([]byte, recordHeaderLen+len(data))
				copy(out, rec[:recordHeaderLen])
				binary.BigEndian.PutUint16(out[3:5], uint16(len(data)))
				copy(out[recordHeaderLen:], data)
				rec = out
			}
		}
		r.pending = rec
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
