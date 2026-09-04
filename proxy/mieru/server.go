// server.go:mieru 入站(proxy.Inbound)。一条 TCP underlay = 一个已认证用户,其上多路复用多个会话。
// 认证:读 24B nonce → 末 4 字节 userTag 定位候选用户 → 3 个 timeSalt 试解首段元数据(AEAD tag 即认证)。
// 认证后 setInbound(ctx,user) + dispatcher.Dispatch,统计/限速/限连接数与 snell 同源自动生效。
package mieru

import (
	"bufio"
	"context"
	"crypto/cipher"
	crand "crypto/rand"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Server 是 mieru 入站处理器。
type Server struct {
	users         []*protocol.MemoryUser
	policyManager policy.Manager
}

// NewServer 从配置构建 mieru 入站。
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	s := &Server{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}
	for _, u := range config.Users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return nil, errors.New("mieru: parse user").Base(err)
		}
		if _, ok := mu.Account.(*MemoryAccount); !ok {
			return nil, errors.New("mieru: invalid account type")
		}
		s.users = append(s.users, mu)
	}
	if len(s.users) == 0 {
		return nil, errors.New("mieru: no users configured")
	}
	return s, nil
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}
}

// resolveUser 读出 24B nonce,定位用户 + timeSalt,返回派生的 AEAD 与 nonce。
// br 会被推进 24 字节(nonce);首段元数据仅 Peek 试解、不消费,交给 segmentReader 正式读。
func (s *Server) resolveUser(br *bufio.Reader) (*protocol.MemoryUser, cipher.AEAD, []byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(br, nonce); err != nil {
		return nil, nil, nil, err
	}
	encMeta, err := br.Peek(metadataLen + aeadTagLen)
	if err != nil {
		return nil, nil, nil, err
	}
	salts := candidateRoundedTimes(time.Now().Unix())
	// 先试 userTag 命中的用户,未命中再兜底试全部(tag 仅为加速)。
	tryUser := func(u *protocol.MemoryUser) (cipher.AEAD, bool) {
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
			n := make([]byte, nonceLen)
			copy(n, nonce)
			if _, oerr := aead.Open(nil, n, encMeta, nil); oerr == nil {
				return aead, true
			}
		}
		return nil, false
	}
	for _, u := range s.users {
		if nonceMatchesUser(u.Account.(*MemoryAccount).Username, nonce) {
			if aead, ok := tryUser(u); ok {
				return u, aead, nonce, nil
			}
		}
	}
	for _, u := range s.users { // 兜底:tag 未命中也全试一遍
		if aead, ok := tryUser(u); ok {
			return u, aead, nonce, nil
		}
	}
	return nil, nil, nil, errors.New("mieru: no user matched handshake")
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if network == xnet.Network_UDP {
		return s.processUDP(ctx, conn, dispatcher)
	}

	sessPolicy := s.policyManager.ForLevel(0)
	_ = conn.SetReadDeadline(time.Now().Add(sessPolicy.Timeouts.Handshake))

	br := bufio.NewReader(conn)
	user, aead, nonce, err := s.resolveUser(br)
	if err != nil {
		return errors.New("mieru: handshake").Base(err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	username := user.Account.(*MemoryAccount).Username

	// 出站(server→client)方向:同一 key,新 nonce(末 4 字节带 userTag,与观测一致)。
	outNonce := make([]byte, nonceLen)
	_, _ = crand.Read(outNonce)
	applyUserTag(outNonce, username)
	writer := &lockedWriter{w: newSegmentWriter(conn, aead, outNonce)}
	reader := newSegmentReader(br, aead, nonce)

	// 每会话 Inbound 继承 proxyman 的 source/gateway/tag,并带上认证用户(统计/限速/限连接数依据)。
	base := session.InboundFromContext(ctx)

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	var mu sync.Mutex
	sessions := make(map[uint32]*serverSession)
	closeAll := func() {
		mu.Lock()
		for _, ss := range sessions {
			ss.interrupt()
		}
		sessions = map[uint32]*serverSession{}
		mu.Unlock()
	}
	defer closeAll()

	for {
		seg, rerr := reader.read()
		if rerr != nil {
			return nil // 连接结束/客户端关闭
		}
		switch seg.protocolType {
		case protoOpenSessionRequest:
			s.handleOpen(connCtx, base, user, username, seg, dispatcher, writer, &mu, sessions)
		case protoDataClientToServer:
			mu.Lock()
			ss := sessions[seg.sessionID]
			mu.Unlock()
			if ss != nil {
				if ferr := ss.feed(seg.payload); ferr != nil {
					ss.interrupt()
				}
			}
		case protoCloseSessionRequest:
			mu.Lock()
			ss := sessions[seg.sessionID]
			delete(sessions, seg.sessionID)
			mu.Unlock()
			if ss != nil {
				_ = ss.writeControl(protoCloseSessionResponse)
				ss.interrupt()
			}
		case protoCloseSessionResponse:
			mu.Lock()
			ss := sessions[seg.sessionID]
			delete(sessions, seg.sessionID)
			mu.Unlock()
			if ss != nil {
				ss.interrupt()
			}
		default:
			// ack 段(8/9)等:TCP underlay 下无需处理,忽略
		}
	}
}

// accessLogCtx 给**这一个会话**挂上访问日志,返回会话内局部 ctx。
//
// mieru 是多路复用的:一条底层连接上跑 N 个会话,各有各的目标。所以只能挂在
// 会话自己的 ctx 上,不能改共享 ctx —— 否则所有会话共用一条 AccessMessage,日志会串。
//
// 传进来的 ctx 必须是已经 ContextWithInbound 过的那个(带 Source 与认证用户),
// 这样 From/Email 直接从 ctx 取,不必把连接对象一路传下来。
func accessLogCtx(ctx context.Context, dest xnet.Destination) context.Context {
	inb := session.InboundFromContext(ctx)
	if inb == nil || !inb.Source.IsValid() {
		return ctx
	}
	email := ""
	if inb.User != nil {
		email = inb.User.Email
	}
	return log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   inb.Source,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  email,
	})
}

// handleOpen 处理 openSessionRequest:解析 socks5 目标 → dispatch → 回 openSessionResponse + socks5 成功回复
// → 写初始数据 → 启动 pump。
func (s *Server) handleOpen(ctx context.Context, base *session.Inbound, user *protocol.MemoryUser, username string,
	seg *segment, dispatcher routing.Dispatcher, writer *lockedWriter, mu *sync.Mutex, sessions map[uint32]*serverSession) {

	dest, cmd, consumed, perr := parseSocks5Request(seg.payload)
	if perr != nil {
		return
	}
	if cmd != socks5CmdConnect {
		// UDP-associate 等后续支持;此处仅优雅忽略(不建会话)。
		return
	}

	// 每会话独立 Inbound(带认证用户),供 dispatcher 归属统计/限速/限连接数。
	ib := session.Inbound{}
	if base != nil {
		ib = *base
	}
	ib.User = user
	ib.Name = "mieru"
	ib.CanSpliceCopy = 3
	sctx, cancel := context.WithCancel(session.ContextWithInbound(ctx, &ib))

	link, derr := dispatcher.Dispatch(accessLogCtx(sctx, dest), dest)
	if derr != nil {
		cancel()
		return
	}

	ss := &serverSession{id: seg.sessionID, link: link, writer: writer, cancel: cancel}
	mu.Lock()
	sessions[seg.sessionID] = ss
	mu.Unlock()

	// openSessionResponse(seq 0)+ socks5 成功回复(首个 data 段,seq 1)
	if err := ss.writeControl(protoOpenSessionResponse); err != nil {
		ss.interrupt()
		return
	}
	if err := ss.writeData(socks5SuccessReplyIPv4); err != nil {
		ss.interrupt()
		return
	}
	// openSessionRequest 里 socks5 请求之后紧跟的初始应用数据 → 写给落地
	if consumed < len(seg.payload) {
		if err := ss.feed(seg.payload[consumed:]); err != nil {
			ss.interrupt()
			return
		}
	}
	go ss.pump()
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
