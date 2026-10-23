// Package shadowtls 是 ShadowTLS v3 的服务端与客户端(客户端见 client.go)。
//
// 按原作者公开的协议文档(ihciah/shadow-tls 的 docs/protocol-v3-en.md,MIT)独立实现,
// 不含 sing-shadowtls / mihomo 的任何代码(两者是 GPL)。
//
// 工作方式:客户端用真正的 TLS 跟「握手服务器」(某个公网网站)握手,服务端只是把握手原样转过去,
// 外人看到的就是一次访问那个网站的 TLS 连接。客户端在 ClientHello 的 SessionID 里藏一个 HMAC 证明身份:
//   - 认不出(主动探测、普通浏览器):整条连接透明转发给握手服务器,对方看到的就是真网站;
//   - 认出来:继续转发握手,但把握手服务器发回的 ApplicationData 加上 HMAC 标记并做 XOR(客户端据此
//     确认服务端是自己人,中间人劫持握手时拿不到这个标记);客户端发出第一帧带自己 HMAC 的数据即「切换」,
//     之后双方都不再碰 TLS,数据装在 ApplicationData 记录里、各带 4 字节流式 HMAC。
package shadowtls

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	recordHeaderLen = 5
	tlsRandomLen    = 32
	sessionIDLen    = 32

	typeChangeCipherSpec = 0x14
	typeAlert            = 0x15
	typeHandshake        = 0x16
	typeApplicationData  = 0x17

	handshakeClientHello = 0x01
	handshakeServerHello = 0x02

	extSupportedVersions = 43
	versionTLS13         = 0x0304

	// 记录头(5) + 握手类型(1) + 长度(3) + 版本(2) 之后就是 Random。
	randomIdx = recordHeaderLen + 1 + 3 + 2
	// SessionID 长度字节的位置;HMAC 放在 SessionID 的最后 4 字节。
	sessionIDLenIdx = randomIdx + tlsRandomLen
	sessionHMACIdx  = sessionIDLenIdx + 1 + sessionIDLen - hmacLen

	// 切换后服务端写出的每帧数据上限。
	maxWriteChunk = 1<<14 - hmacLen

	dialTimeout = 10 * time.Second
)

// ErrFallback 表示这条连接不是 ShadowTLS 客户端(或握手服务器不满足条件),
// Accept 已经把它整条转发给握手服务器、直到任一端关闭。调用方直接结束即可。
var ErrFallback = errors.New("shadowtls: not a shadowtls client, relayed to handshake server")

// Config 一个入站的 ShadowTLS 设置。
type Config struct {
	Password string
	// Handshake 握手服务器 host:port,必须支持 TLS 1.3(Strict 时)。
	Handshake string
	// Strict 只接受握手服务器协商出 TLS 1.3 的连接(协议文档的 strict 模式,默认开)。
	// TLS 1.2 下 ShadowTLS v3 抵抗不了连接劫持,原作者只在非 strict 模式下放行。
	Strict bool
	// Dial 拨握手服务器;为空用 net.Dialer。
	Dial func(ctx context.Context, address string) (net.Conn, error)
}

func (c *Config) dial(ctx context.Context) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, c.Handshake)
	}
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "tcp", c.Handshake)
}

// Accept 在 conn 上跑 ShadowTLS v3 服务端握手。认证通过返回承载内层数据流的 net.Conn;
// 否则把连接转发给握手服务器直到结束,返回 ErrFallback。其它错误表示连接已不可用。
func Accept(ctx context.Context, conn net.Conn, cfg *Config) (net.Conn, error) {
	clientHello, err := readRecord(conn)
	if err != nil {
		return nil, errors.New("shadowtls: read client hello").Base(err)
	}
	authed := verifyClientHello(clientHello, cfg.Password)

	hs, err := cfg.dial(ctx)
	if err != nil {
		return nil, errors.New("shadowtls: dial handshake server ", cfg.Handshake).Base(err)
	}
	if _, err := hs.Write(clientHello); err != nil {
		hs.Close()
		return nil, errors.New("shadowtls: write client hello").Base(err)
	}
	if !authed {
		relay(conn, hs)
		return nil, ErrFallback
	}

	serverHello, err := readRecord(hs)
	if err != nil {
		hs.Close()
		return nil, errors.New("shadowtls: read server hello").Base(err)
	}
	if _, err := conn.Write(serverHello); err != nil {
		hs.Close()
		return nil, errors.New("shadowtls: write server hello").Base(err)
	}
	serverRandom, ok := extractServerRandom(serverHello)
	if !ok || (cfg.Strict && !serverHelloIsTLS13(serverHello)) {
		relay(conn, hs)
		return nil, ErrFallback
	}

	pw := []byte(cfg.Password)
	hmacClient := newStreamHMAC(pw, serverRandom, []byte("C"))
	hmacServer := newStreamHMAC(pw, serverRandom, []byte("S"))
	hmacHandshake := newStreamHMAC(pw, serverRandom)
	key := xorKey(cfg.Password, serverRandom)

	// 握手服务器 → 客户端:ApplicationData 加 HMAC_ServerRandom 标记、XOR 后转发,直到客户端切换。
	var writeMu sync.Mutex
	stopped := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			rec, err := readRecord(hs)
			if err != nil {
				return
			}
			select {
			case <-stopped:
				return // 客户端已切换:不再往回写握手残帧
			default:
			}
			if rec[0] == typeApplicationData {
				rec = markHandshakeRecord(rec, hmacHandshake, key)
			}
			writeMu.Lock()
			_, err = conn.Write(rec)
			writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	// 客户端 → 握手服务器:原样转发,直到出现第一帧带 HMAC_ServerRandomC 的 ApplicationData。
	firstData, err := forwardUntilSwitch(conn, hs, hmacClient)
	close(stopped)
	// 关掉握手服务器连接让上面的 goroutine 从 Read 里出来,并等它写完手上那一帧,
	// 之后这条连接上只有我们自己的数据帧,不会和握手残帧交错。
	hs.Close()
	<-done
	if err != nil {
		return nil, errors.New("shadowtls: forward handshake").Base(err)
	}

	return &dataConn{
		Conn:        conn,
		pending:     firstData,
		hmacRead:    hmacClient,
		hmacWrite:   hmacServer,
		alertOnFail: !serverHelloIsTLS13(serverHello),
	}, nil
}

// verifyClientHello 校验 ClientHello 里 SessionID 末 4 字节的 HMAC。
// HMAC(password) 覆盖去掉 5 字节记录头的整个 ClientHello,其中 HMAC 自己那 4 个字节按 0 计。
func verifyClientHello(rec []byte, password string) bool {
	if len(rec) < sessionHMACIdx+hmacLen || rec[0] != typeHandshake || rec[recordHeaderLen] != handshakeClientHello {
		return false
	}
	if rec[sessionIDLenIdx] != sessionIDLen {
		return false
	}
	h := newStreamHMAC([]byte(password))
	h.write(rec[recordHeaderLen:sessionHMACIdx])
	h.write(make([]byte, hmacLen))
	h.write(rec[sessionHMACIdx+hmacLen:])
	sum := h.sum4()
	return subtle.ConstantTimeCompare(sum[:], rec[sessionHMACIdx:sessionHMACIdx+hmacLen]) == 1
}

func extractServerRandom(rec []byte) ([]byte, bool) {
	if len(rec) < randomIdx+tlsRandomLen || rec[0] != typeHandshake || rec[recordHeaderLen] != handshakeServerHello {
		return nil, false
	}
	return append([]byte(nil), rec[randomIdx:randomIdx+tlsRandomLen]...), true
}

// serverHelloIsTLS13 ServerHello 的 supported_versions 扩展是否选了 TLS 1.3。
func serverHelloIsTLS13(rec []byte) bool {
	p := rec[min(len(rec), sessionIDLenIdx):]
	if len(p) < 1 {
		return false
	}
	sidLen := int(p[0])
	p = p[1:]
	// session id | cipher suite(2) | compression(1) | extensions length(2)
	if len(p) < sidLen+3+2 {
		return false
	}
	p = p[sidLen+3:]
	extLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if extLen < len(p) {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p)
		l := int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if l > len(p) {
			return false
		}
		if typ == extSupportedVersions {
			return l == 2 && binary.BigEndian.Uint16(p) == versionTLS13
		}
		p = p[l:]
	}
	return false
}

// markHandshakeRecord 改写握手服务器发来的一帧 ApplicationData:数据 XOR,前面插入 HMAC_ServerRandom 的 4 字节,
// 记录长度 +4。这个 HMAC 实例在整个握手阶段连续使用(每帧只喂数据,不喂标记本身)。
func markHandshakeRecord(rec []byte, h *streamHMAC, key []byte) []byte {
	data := rec[recordHeaderLen:]
	xorCycle(data, key)
	h.write(data)
	sum := h.sum4()
	out := make([]byte, 0, len(rec)+hmacLen)
	out = append(out, rec[:recordHeaderLen]...)
	out = append(out, sum[:]...)
	out = append(out, data...)
	binary.BigEndian.PutUint16(out[3:5], uint16(len(data)+hmacLen))
	return out
}

// forwardUntilSwitch 把客户端的握手记录原样转给握手服务器,遇到第一帧「数据 HMAC 对得上 HMAC_ServerRandomC」的
// ApplicationData 就停下,返回这帧里的数据。匹配后数据与 4 字节标记都喂进 h,接着用于后续数据帧校验。
func forwardUntilSwitch(client, hs net.Conn, h *streamHMAC) ([]byte, error) {
	for {
		rec, err := readRecord(client)
		if err != nil {
			return nil, err
		}
		if rec[0] == typeApplicationData && len(rec) > recordHeaderLen+hmacLen {
			tmp := h.clone()
			tmp.write(rec[recordHeaderLen+hmacLen:])
			sum := tmp.sum4()
			if bytes.Equal(sum[:], rec[recordHeaderLen:recordHeaderLen+hmacLen]) {
				h.write(rec[recordHeaderLen+hmacLen:])
				h.write(rec[recordHeaderLen : recordHeaderLen+hmacLen])
				return append([]byte(nil), rec[recordHeaderLen+hmacLen:]...), nil
			}
		}
		if _, err := hs.Write(rec); err != nil {
			return nil, err
		}
	}
}

// readRecord 读一整条 TLS 记录(含 5 字节头)。
func readRecord(r io.Reader) ([]byte, error) {
	var hdr [recordHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	// 长度不按 TLS 的 2^14 上限卡:切换后的数据帧由客户端自己封装,原实现与各客户端都只认 2 字节长度字段。
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	rec := make([]byte, recordHeaderLen+n)
	copy(rec, hdr[:])
	if _, err := io.ReadFull(r, rec[recordHeaderLen:]); err != nil {
		return nil, err
	}
	return rec, nil
}

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// 一个方向结束就把两头都关掉,另一个方向的 Copy 随之返回。
		_ = dst.Close()
		_ = src.Close()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// dataConn 切换之后的数据连接(服务端与客户端共用):读端剥 ApplicationData 头并校验对端的 HMAC
// (服务端读 HMAC_ServerRandomC、客户端读 HMAC_ServerRandomS),写端把数据装进 ApplicationData 并加自己这一侧的 HMAC。
// 两个 HMAC 都是流式的:每帧先喂数据、取 4 字节,再把这 4 字节喂回去(防止截断拼接)。
type dataConn struct {
	net.Conn

	readMu   sync.Mutex
	pending  []byte
	hmacRead *streamHMAC
	// residual 仅客户端用:服务端切换前还会转来几帧握手服务器的 ApplicationData(如 TLS 1.3 的 NewSessionTicket),
	// 带的是 HMAC_ServerRandom 标记,丢掉即可。按协议,收到第一帧服务端自己的数据(HMAC_ServerRandomS)后
	// 这个分支即关闭,置空。
	residual *streamHMAC

	writeMu   sync.Mutex
	hmacWrite *streamHMAC

	// TLS 1.2 的握手服务器下,校验失败按协议回一个 Alert;TLS 1.3 下不回(与原实现一致)。
	alertOnFail bool
}

func (c *dataConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.pending) == 0 {
		rec, err := readRecord(c.Conn)
		if err != nil {
			return 0, err
		}
		switch rec[0] {
		case typeAlert:
			return 0, io.EOF
		case typeApplicationData:
		default:
			c.fail()
			return 0, errors.New("shadowtls: unexpected record type ", rec[0])
		}
		if len(rec) < recordHeaderLen+hmacLen {
			c.fail()
			return 0, errors.New("shadowtls: short record")
		}
		data := rec[recordHeaderLen+hmacLen:]
		mark := rec[recordHeaderLen : recordHeaderLen+hmacLen]
		h := c.hmacRead
		if c.residual != nil {
			h = h.clone() // 可能是残帧,先别动正式的 HMAC 状态
		}
		h.write(data)
		sum := h.sum4()
		if !bytes.Equal(sum[:], mark) {
			if c.residual != nil {
				r := c.residual.clone()
				r.write(data)
				if sum := r.sum4(); bytes.Equal(sum[:], mark) {
					c.residual = r
					continue
				}
			}
			c.fail()
			return 0, errors.New("shadowtls: bad record mac")
		}
		h.write(sum[:])
		c.hmacRead, c.residual = h, nil
		c.pending = data
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *dataConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	buf := make([]byte, recordHeaderLen+hmacLen+min(len(p), maxWriteChunk))
	for len(p) > 0 {
		n := min(len(p), maxWriteChunk)
		chunk := p[:n]
		rec := buf[:recordHeaderLen+hmacLen+n]
		rec[0], rec[1], rec[2] = typeApplicationData, 0x03, 0x03
		binary.BigEndian.PutUint16(rec[3:5], uint16(hmacLen+n))
		c.hmacWrite.write(chunk)
		sum := c.hmacWrite.sum4()
		c.hmacWrite.write(sum[:])
		copy(rec[recordHeaderLen:], sum[:])
		copy(rec[recordHeaderLen+hmacLen:], chunk)
		if _, err := c.Conn.Write(rec); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// fail 数据校验失败:TLS 1.2 时按协议回 Alert(内容随机),然后由调用方关闭连接。
func (c *dataConn) fail() {
	if !c.alertOnFail {
		return
	}
	alert := make([]byte, 31)
	alert[0], alert[1], alert[2] = typeAlert, 0x03, 0x03
	binary.BigEndian.PutUint16(alert[3:5], uint16(len(alert)-recordHeaderLen))
	_, _ = rand.Read(alert[recordHeaderLen:])
	c.writeMu.Lock()
	_, _ = c.Conn.Write(alert)
	c.writeMu.Unlock()
}
