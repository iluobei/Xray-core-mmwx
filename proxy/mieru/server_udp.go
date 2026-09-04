// server_udp.go:mieru UDP underlay 入站。xray proxyman 的 udpWorker 已按客户端源地址解复用,
// 每个客户端一次 Process(Network_UDP, conn);conn.ReadMultiBuffer 保留数据报边界(每 buffer=一个 UDP 包=一个段),
// conn.Write 发一个数据报。这里在此之上:定位用户 → 按 sessionID 解复用到 per-session ARQ(arq.go)→
// 会话逻辑(socks5+dispatch+relay,与 TCP 同)。可靠性由 ARQ 提供。
package mieru

import (
	"context"
	"crypto/cipher"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// resolveUDPUser 用首包(nonce 末 4 字节 userTag + 3 timeSalt 试解)定位用户,返回派生 AEAD。
func (s *Server) resolveUDPUser(firstPkt []byte) (*protocol.MemoryUser, cipher.AEAD, error) {
	if len(firstPkt) < nonceLen {
		return nil, nil, errors.New("mieru udp: short first packet")
	}
	nonce := firstPkt[:nonceLen]
	salts := candidateRoundedTimes(time.Now().Unix())
	tryUser := func(u *protocol.MemoryUser) cipher.AEAD {
		acc := u.Account.(*MemoryAccount)
		for _, r := range salts {
			key, kerr := deriveKey(acc.hashedPassword, timeSalt(r))
			if kerr != nil {
				continue
			}
			aead, aerr := newAEAD(key)
			if aerr != nil {
				continue
			}
			if _, derr := decodeUDPSegment(firstPkt, aead); derr == nil {
				return aead
			}
		}
		return nil
	}
	for _, u := range s.users {
		if nonceMatchesUser(u.Account.(*MemoryAccount).Username, nonce) {
			if aead := tryUser(u); aead != nil {
				return u, aead, nil
			}
		}
	}
	for _, u := range s.users {
		if aead := tryUser(u); aead != nil {
			return u, aead, nil
		}
	}
	return nil, nil, errors.New("mieru udp: no user matched")
}

func (s *Server) processUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// udpWorker 给的 udpConn 实现 buf.Reader,且 Read([]byte) 会 panic → 必须走 ReadMultiBuffer(每 buffer=一个 UDP 包)。
	reader, ok := conn.(buf.Reader)
	if !ok {
		return errors.New("mieru udp: connection is not a buf.Reader")
	}
	firstMB, err := reader.ReadMultiBuffer()
	if err != nil {
		return nil
	}
	pkts := splitPackets(firstMB)
	if len(pkts) == 0 {
		return nil
	}
	user, aead, uerr := s.resolveUDPUser(pkts[0])
	if uerr != nil {
		return errors.New("mieru udp: handshake").Base(uerr)
	}
	username := user.Account.(*MemoryAccount).Username

	var writeMu sync.Mutex
	writePkt := func(pkt []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_, e := conn.Write(pkt)
		return e
	}

	base := session.InboundFromContext(ctx)
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	var mu sync.Mutex
	sessions := make(map[uint32]*udpServerSession)
	defer func() {
		mu.Lock()
		for _, us := range sessions {
			us.shutdown()
		}
		mu.Unlock()
	}()

	handle := func(pkt []byte) {
		seg, derr := decodeUDPSegment(pkt, aead)
		if derr != nil {
			return // 丢弃坏包
		}
		mu.Lock()
		us := sessions[seg.sessionID]
		if us == nil && seg.protocolType == protoOpenSessionRequest {
			us = newUDPServerSession(connCtx, seg.sessionID, user, username, aead, writePkt, base, dispatcher)
			sessions[seg.sessionID] = us
			go us.consume()
		}
		mu.Unlock()
		if us != nil {
			us.arq.onSegment(seg)
		}
	}

	for _, p := range pkts {
		handle(p)
	}
	for {
		mb, rerr := reader.ReadMultiBuffer()
		if rerr != nil {
			return nil
		}
		for _, p := range splitPackets(mb) {
			handle(p)
		}
	}
}

// splitPackets 把一次 ReadMultiBuffer 的每个 buffer 取成独立字节切片(每 buffer=一个 UDP 包)。
func splitPackets(mb buf.MultiBuffer) [][]byte {
	var out [][]byte
	for _, b := range mb {
		if b.Len() > 0 {
			cp := make([]byte, b.Len())
			copy(cp, b.Bytes())
			out = append(out, cp)
		}
	}
	buf.ReleaseMulti(mb)
	return out
}

// udpServerSession 是 UDP underlay 上的一条会话。可靠性由 arq 提供,业务逻辑与 TCP 同。
type udpServerSession struct {
	id         uint32
	arq        *arqSession
	ctx        context.Context
	cancel     context.CancelFunc
	base       *session.Inbound
	user       *protocol.MemoryUser
	dispatcher routing.Dispatcher
	link       *transport.Link
	closeOnce  sync.Once
}

func newUDPServerSession(ctx context.Context, id uint32, user *protocol.MemoryUser, username string,
	aead cipher.AEAD, writePkt func([]byte) error, base *session.Inbound, dispatcher routing.Dispatcher) *udpServerSession {
	sctx, cancel := context.WithCancel(ctx)
	us := &udpServerSession{
		id: id, ctx: sctx, cancel: cancel, base: base, user: user, dispatcher: dispatcher,
	}
	us.arq = newARQSession(id, username, aead, writePkt)
	return us
}

// consume 按 ARQ 有序交付处理会话流:首段=openSessionRequest(socks5+初始数据),后续=数据/关闭。
func (us *udpServerSession) consume() {
	for {
		var seg *segment
		select {
		case seg = <-us.arq.delivered:
		case <-us.ctx.Done():
			return
		case <-us.arq.closed:
			return
		}
		switch seg.protocolType {
		case protoOpenSessionRequest:
			if us.link == nil {
				if !us.handleOpen(seg) {
					us.shutdown()
					return
				}
			}
		case protoDataClientToServer:
			if us.link != nil && len(seg.payload) > 0 {
				if werr := us.link.Writer.WriteMultiBuffer(bytesToMultiBuffer(seg.payload)); werr != nil {
					us.shutdown()
					return
				}
			}
		case protoCloseSessionRequest:
			_ = us.sendSession(protoCloseSessionResponse)
			us.shutdown()
			return
		}
	}
}

// handleOpen 解析 socks5 目标 → dispatch → 回 openSessionResponse + socks5 成功回复 + 初始数据 → 启动 pump。
func (us *udpServerSession) handleOpen(seg *segment) bool {
	dest, cmd, consumed, perr := parseSocks5Request(seg.payload)
	if perr != nil || cmd != socks5CmdConnect {
		return false
	}
	ib := session.Inbound{}
	if us.base != nil {
		ib = *us.base
	}
	ib.User = us.user
	ib.Name = "mieru"
	ib.CanSpliceCopy = 3
	sctx := session.ContextWithInbound(us.ctx, &ib)
	link, derr := us.dispatcher.Dispatch(accessLogCtx(sctx, dest), dest)
	if derr != nil {
		return false
	}
	us.link = link

	if err := us.sendSession(protoOpenSessionResponse); err != nil {
		return false
	}
	if err := us.sendData(socks5SuccessReplyIPv4); err != nil {
		return false
	}
	if consumed < len(seg.payload) {
		if err := us.link.Writer.WriteMultiBuffer(bytesToMultiBuffer(seg.payload[consumed:])); err != nil {
			return false
		}
	}
	go us.pump()
	return true
}

// pump 读落地响应,分片成 dataServerToClient 段经 ARQ 可靠发出。
func (us *udpServerSession) pump() {
	reader := us.link.Reader
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			break
		}
		data := mbToBytes(mb)
		for _, frag := range bytesToUDPFragments(data) {
			if werr := us.sendData(frag); werr != nil {
				us.notifyClose()
				return
			}
		}
	}
	us.notifyClose()
}

// sendSession 经 ARQ 发一个会话控制段(open/close response)。
func (us *udpServerSession) sendSession(protoType uint8) error {
	return us.arq.sendSegment(func(seq, _ uint32, _ uint16) []byte {
		return sessionMeta{protocolType: protoType, sessionID: us.id, seq: seq}.encode()
	}, nil)
}

// sendData 经 ARQ 发一个 dataServerToClient 段(捎带累积 ack + window)。
func (us *udpServerSession) sendData(payload []byte) error {
	return us.arq.sendSegment(func(seq, unack uint32, win uint16) []byte {
		return dataMeta{
			protocolType: protoDataServerToClient,
			sessionID:    us.id,
			seq:          seq,
			unackSeq:     unack,
			window:       win,
			payloadLen:   uint16(len(payload)),
		}.encode()
	}, payload)
}

// notifyClose 落地关闭时通知客户端关闭会话。
func (us *udpServerSession) notifyClose() {
	_ = us.sendSession(protoCloseSessionRequest)
	us.shutdown()
}

func (us *udpServerSession) shutdown() {
	us.closeOnce.Do(func() {
		us.cancel()
		us.arq.close()
		if us.link != nil {
			common.Interrupt(us.link.Reader)
			common.Interrupt(us.link.Writer)
		}
	})
}
