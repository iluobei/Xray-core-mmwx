package snell

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"sort"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

// Server 是 Snell inbound。v4/v5 与 v6 都按 per-user PSK 逐一试解首个 record 定位用户
// (v6 default 从 saltBlock 提取 salt、unshaped 读明文 salt),从而支持 per-user 流量统计 / 限速 /
// 限连接数;unsafe-raw 无任何密钥无法区分用户,回落首个用户。
type Server struct {
	policyManager policy.Manager
	users         []*protocol.MemoryUser
	obfs          obfsConfig

	// v6 专用(version==6 时生效)
	version uint32
	v6Mode  Mode
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	s := &Server{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}
	for _, u := range config.Users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return nil, errors.New("snell: parse user").Base(err)
		}
		if _, ok := mu.Account.(*MemoryAccount); !ok {
			return nil, errors.New("snell: invalid account type")
		}
		s.users = append(s.users, mu)
	}
	if len(s.users) == 0 {
		return nil, errors.New("snell: no users configured")
	}
	acc0 := s.users[0].Account.(*MemoryAccount)
	s.version = acc0.Version

	if s.version == 6 {
		// v6:每个用户各自的 PSK 派生 profile / AEAD;服务端逐 PSK 试解首个 record 定位用户
		// (见 identifyV6User),从而支持 per-user 流量统计 / 限速 / 限连接数。整形本身即混淆,无 obfs。
		mode, err := ParseMode(acc0.V6Mode)
		if err != nil {
			return nil, err
		}
		s.v6Mode = mode
		for _, u := range s.users {
			if psk := u.Account.(*MemoryAccount).PSK; len(psk) < 12 || len(psk) > 255 {
				return nil, errors.New("snell: v6 psk length must be 12..255 bytes")
			}
		}
		return s, nil
	}

	// v4/v5:obfs 是传输层设置(与 PSK/用户无关),取首个用户的配置作为该 inbound 的混淆模式。
	mode, err := parseObfsMode(acc0.ObfsMode)
	if err != nil {
		return nil, err
	}
	s.obfs = obfsConfig{mode: mode, host: acc0.ObfsHost}
	return s, nil
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// handshake 读取 salt,用每个用户的 PSK 试解首个 record header(GCM tag 即认证),
// 返回定位到首个 record 的 reader 与匹配用户。兼容单/多用户,兼容标准单-PSK 客户端。
func (s *Server) handshake(conn xnet.Conn) (*recordReader, *protocol.MemoryUser, error) {
	br := bufio.NewReader(conn)
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(br, salt); err != nil {
		return nil, nil, err
	}
	headerCipher, err := br.Peek(headerCipherLen)
	if err != nil {
		return nil, nil, err
	}
	for _, u := range s.users {
		acc, ok := u.Account.(*MemoryAccount)
		if !ok {
			continue
		}
		aead, err := newAEAD(deriveKey(acc.PSK, salt))
		if err != nil {
			continue
		}
		nonce := make([]byte, nonceLen)
		if _, err := aead.Open(nil, nonce, headerCipher, nil); err == nil {
			// tag 验证通过即认证成功(伪造在计算上不可行),不消费 header,交给 readRecord 复读。
			return newRecordReaderResume(br, aead), u, nil
		}
	}
	return nil, nil, errors.New("snell: no user matched handshake")
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessPolicy := s.policyManager.ForLevel(0)
	_ = conn.SetReadDeadline(time.Now().Add(sessPolicy.Timeouts.Handshake))

	if s.version == 6 {
		return s.processV6(ctx, conn, dispatcher, sessPolicy)
	}

	// v4/v5:obfs 在 record 层之下,先套混淆包装;再逐 PSK 试解握手。
	oconn := s.obfs.serverConn(conn)
	reader, user, err := s.handshake(oconn)
	if err != nil {
		return errors.New("snell: handshake").Base(err)
	}
	account := user.Account.(*MemoryAccount)

	req, err := readRequest(reader)
	if err != nil {
		return errors.New("snell: read request").Base(err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	s.setInbound(ctx, user)
	writer := newRecordWriter(oconn, account.PSK)
	return s.serve(ctx, req, reader, writer, dispatcher, sessPolicy)
}

// processV6:逐 PSK 试解首个 record 定位用户(default/unshaped),再按该用户各自的 PSK 建 reader/writer。
// unsafe-raw 无密钥无法区分用户,回落 users[0](明文调试模式,不用于多用户统计)。
func (s *Server) processV6(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher, sessPolicy policy.Session) error {
	// v6 无 obfs(整形本身即混淆)。
	user, profile, head, err := s.identifyV6User(conn)
	if err != nil {
		return errors.New("snell v6: identify user").Base(err)
	}
	account := user.Account.(*MemoryAccount)

	// head 是识别阶段已从 conn 消费的首 record 前缀(salt/saltBlock + prefix + header)。
	// 用 MultiReader 把它拼回 conn,让 reader 从头重读 salt+header —— 与未消费时逻辑完全一致。
	var src io.Reader = conn
	if len(head) > 0 {
		src = io.MultiReader(bytes.NewReader(head), conn)
	}
	reader := newV6Reader(src, s.v6Mode, account.PSK, profile)
	req, err := readRequest(reader)
	if err != nil {
		return errors.New("snell v6: read request").Base(err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	s.setInbound(ctx, user)
	writer, err := newV6Writer(conn, s.v6Mode, account.PSK, profile)
	if err != nil {
		return errors.New("snell v6: create writer").Base(err)
	}
	return s.serve(ctx, req, reader, writer, dispatcher, sessPolicy)
}

// identifyV6User 逐 PSK 试解首个 record 的 header(AEAD tag 即认证)定位用户。返回:命中用户、
// 其 profile(default 模式非 nil;unshaped/raw 为 nil)、以及识别阶段已从 conn 消费的首 record 前缀
// head(供 processV6 用 MultiReader 拼回)。raw 模式线上无任何密钥,直接回落 users[0]。
func (s *Server) identifyV6User(conn io.Reader) (*protocol.MemoryUser, *Profile, []byte, error) {
	switch s.v6Mode {
	case ModeUnsafeRaw:
		return s.users[0], nil, nil, nil
	case ModeUnshaped:
		return s.identifyV6Unshaped(conn)
	default:
		return s.identifyV6Shaped(conn)
	}
}

// identifyV6Unshaped:salt 是明文前缀,各用户 need 相同(saltLen+headerCipherLen),读一次逐 PSK 试解。
func (s *Server) identifyV6Unshaped(conn io.Reader) (*protocol.MemoryUser, *Profile, []byte, error) {
	head := make([]byte, saltLen+headerCipherLen)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, nil, nil, err
	}
	salt := head[:saltLen]
	nonce := make([]byte, nonceLen)
	for _, u := range s.users {
		aead, err := newAEAD(deriveKey(u.Account.(*MemoryAccount).PSK, salt))
		if err != nil {
			continue
		}
		tmp := make([]byte, headerCipherLen)
		copy(tmp, head[saltLen:])
		if _, err := aead.Open(tmp[:0], nonce, tmp, nil); err == nil {
			return u, nil, head, nil
		}
	}
	return nil, nil, nil, errors.New("snell v6 unshaped: no user matched")
}

// identifyV6Shaped:salt 藏在 saltBlock 里,saltBlock/prefix 长度由各用户 profile 决定(need 各异)。
// 按 need 升序增量读取:命中即止,绝不读超过命中候选的 need(= 正确用户首 record 必然有的字节数),
// 从而不会为 need 更大的错误候选阻塞等待不存在的字节(否则会握手超时)。
func (s *Server) identifyV6Shaped(conn io.Reader) (*protocol.MemoryUser, *Profile, []byte, error) {
	type candidate struct {
		user    *protocol.MemoryUser
		profile *Profile
		need    int
	}
	cands := make([]candidate, len(s.users))
	for i, u := range s.users {
		p := NewProfile(u.Account.(*MemoryAccount).PSK)
		cands[i] = candidate{user: u, profile: p, need: p.saltBlockLen + p.recordPrefixLen(0) + headerCipherLen}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].need < cands[j].need })

	nonce := make([]byte, nonceLen)
	var head []byte
	for _, c := range cands {
		for len(head) < c.need {
			chunk := make([]byte, c.need-len(head))
			n, err := io.ReadFull(conn, chunk)
			head = append(head, chunk[:n]...)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		salt := c.profile.extractSalt(head[:c.profile.saltBlockLen])
		aead, err := newAEAD(deriveKey(c.user.Account.(*MemoryAccount).PSK, salt[:]))
		if err != nil {
			continue
		}
		prefixLen := c.profile.recordPrefixLen(0)
		prefix := head[c.profile.saltBlockLen : c.profile.saltBlockLen+prefixLen]
		headerCipher := make([]byte, headerCipherLen)
		copy(headerCipher, head[c.need-headerCipherLen:c.need])
		if _, err := aead.Open(headerCipher[:0], nonce, headerCipher, prefix); err == nil {
			return c.user, c.profile, head, nil
		}
	}
	return nil, nil, nil, errors.New("snell v6 shaped: no user matched")
}

// accessLogCtx 给这一条流/这一个数据报挂上访问日志。
//
// 移植 snell 时漏了这一步,导致用 snell 的用户在 access.log 里完全不可见 ——
// 内置协议(vless/trojan/shadowsocks…)都会在 Dispatch 之前把 AccessMessage 放进 ctx,
// 由分发器统一补上 Detour 后写出。
//
// From 取 inbound.Source 而不是 conn.RemoteAddr():两者是同一个地址,而前者已经在 ctx 里,
// 不必把 conn 一路传到 serveTCP/handleUDP。与 shadowsocks 的写法一致。
func accessLogCtx(ctx context.Context, dest xnet.Destination) context.Context {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || !inbound.Source.IsValid() {
		return ctx
	}
	email := ""
	if inbound.User != nil {
		email = inbound.User.Email
	}
	return log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   inbound.Source,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  email,
	})
}

func (s *Server) setInbound(ctx context.Context, user *protocol.MemoryUser) {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "snell"
	inbound.User = user
	inbound.CanSpliceCopy = 3
}

// serve 按 command 分 TCP/UDP。reader/writer 已按版本建好,以下逻辑版本无关。
// CommandConnect(0x01)与 ConnectV2(0x05)首个响应格式相同,均按非复用 TCP 处理。
func (s *Server) serve(ctx context.Context, req request, reader snellReader, writer snellWriter, dispatcher routing.Dispatcher, sessPolicy policy.Session) error {
	switch req.command {
	case commandConnect, commandConnectV2:
		return s.serveTCP(ctx, req.destination, reader, writer, dispatcher, sessPolicy)
	case commandUDP:
		return s.handleUDP(ctx, reader, writer, dispatcher, sessPolicy)
	default:
		return errors.New("snell: unsupported command ", req.command)
	}
}

func (s *Server) serveTCP(ctx context.Context, destination xnet.Destination, reader snellReader, writer snellWriter, dispatcher routing.Dispatcher, sessPolicy policy.Session) error {
	ctx = accessLogCtx(ctx, destination)
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return errors.New("snell: dispatch").Base(err)
	}

	// 回程首字节必须是 ReplyTunnel(0x00),客户端据此确认隧道建立。
	if _, err := writer.Write([]byte{replyTunnel}); err != nil {
		return errors.New("snell: write tunnel reply").Base(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessPolicy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		if err := buf.Copy(buf.NewReader(reader), link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("snell: transport request").Base(err)
		}
		return nil
	}
	responseDone := func() error {
		if err := buf.Copy(link.Reader, buf.NewWriter(writer), buf.UpdateActivity(timer)); err != nil {
			return errors.New("snell: transport response").Base(err)
		}
		return nil
	}

	requestDoneAndCloseWriter := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDoneAndCloseWriter, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("snell: connection ends").Base(err)
	}
	return nil
}

// handleUDP 处理 CommandUDP:每个 record = 一个数据报(client→server: 0x01|地址|payload)。
// 用 udp.Dispatcher 把每个数据报按各自目标转发(全锥),响应回程编码为 地址|payload record。
func (s *Server) handleUDP(ctx context.Context, reader snellReader, writer snellWriter, dispatcher routing.Dispatcher, sessPolicy policy.Session) error {
	// 回程首个 record 为 ReplyTunnel(0x00),表示 UDP 隧道建立。
	if _, err := writer.Write([]byte{replyTunnel}); err != nil {
		return errors.New("snell: write udp reply").Base(err)
	}
	packetWriter := &udpPacketWriter{writer: writer, response: true}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	udpServer := udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		payload := packet.Payload
		if payload == nil {
			return
		}
		if err := packetWriter.writePacket(payload.Bytes(), packet.Source); err != nil {
			errors.LogWarningInner(ctx, err, "snell: write udp response")
			payload.Release()
			cancel()
			return
		}
		payload.Release()
		timer.Update()
	})
	defer udpServer.RemoveRay()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		record, err := reader.nextRecord()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return errors.New("snell: read udp datagram").Base(err)
		}
		if len(record) < 1 || record[0] != udpCommandForward {
			continue
		}
		dest, payload, err := readUDPRequestAddress(record[1:])
		if err != nil {
			return errors.New("snell: parse udp request").Base(err)
		}
		timer.Update()
		b := buf.New()
		if _, err := b.Write(payload); err != nil {
			b.Release()
			return err
		}
		// 逐包挂日志:UDP 一条隧道会打到很多目标,不能共用一条 AccessMessage。
		udpServer.Dispatch(accessLogCtx(ctx, dest), dest, b)
	}
}
