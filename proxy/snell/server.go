package snell

import (
	"bufio"
	"bytes"
	"context"
	goerrors "errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/shadowtls"
	"github.com/xtls/xray-core/common/signal"
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

	// userMu 只保护 users。users 是 copy-on-write 的:写侧(user.go 的 AddUser/RemoveUser)
	// 永远新建一份 slice 再整体替换,绝不原地 append/删除;读侧因此只需在 RLock 里复制一次
	// slice header 就能出锁,之后遍历的是一份再也不会被改写的快照(见 snapshotUsers)。
	userMu sync.RWMutex
	users  []*protocol.MemoryUser

	obfs obfsConfig
	// shadowTLS 非空时连接先过 ShadowTLS v3 外壳(仅 v4/v5,与 obfs 互斥,配置层已校验)。
	shadowTLS *shadowtls.Config

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
	if st := config.GetShadowTls(); st != nil {
		s.shadowTLS = &shadowtls.Config{Password: st.Password, Handshake: st.Handshake, Strict: st.Strict}
	}
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
	for _, u := range s.snapshotUsers() {
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

	// ShadowTLS:先跟握手服务器转完 TLS 握手、剥掉外壳,拿到里面的 Snell 数据流;
	// 认不出的连接已被整条转发给握手服务器(探测者看到的是真网站),这里直接结束。
	var inner net.Conn = conn
	if s.shadowTLS != nil {
		c, err := shadowtls.Accept(ctx, conn, s.shadowTLS)
		if err != nil {
			if goerrors.Is(err, shadowtls.ErrFallback) {
				errors.LogInfo(ctx, "snell: shadowtls authentication failed, relayed to handshake server")
				return nil
			}
			return errors.New("snell: shadowtls").Base(err)
		}
		inner = c
	}

	// v4/v5:obfs 在 record 层之下,先套混淆包装;再逐 PSK 试解握手。
	oconn := s.obfs.serverConn(inner)
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
	return s.serve(ctx, conn, user, req, reader, writer, dispatcher, sessPolicy)
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
	return s.serve(ctx, conn, user, req, reader, writer, dispatcher, sessPolicy)
}

// identifyV6User 逐 PSK 试解首个 record 的 header(AEAD tag 即认证)定位用户。返回:命中用户、
// 其 profile(default 模式非 nil;unshaped/raw 为 nil)、以及识别阶段已从 conn 消费的首 record 前缀
// head(供 processV6 用 MultiReader 拼回)。raw 模式线上无任何密钥,直接回落 users[0]。
func (s *Server) identifyV6User(conn io.Reader) (*protocol.MemoryUser, *Profile, []byte, error) {
	switch s.v6Mode {
	case ModeUnsafeRaw:
		// RemoveUser 拒绝删掉最后一个用户,正是为了让这里的 users[0] 永远有得取;
		// 仍然兜一手,是因为这条索引一旦越界就是整个 xray 进程 panic。
		users := s.snapshotUsers()
		if len(users) == 0 {
			return nil, nil, nil, errors.New("snell v6 raw: no users")
		}
		return users[0], nil, nil, nil
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
	for _, u := range s.snapshotUsers() {
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
	users := s.snapshotUsers()
	cands := make([]candidate, len(users))
	for i, u := range users {
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

// drainLimit 是「下行已结束、等客户端的结束 record」期间最多读掉丢弃多少字节。客户端等服务端的
// 结束 record 时也有同量级的上限(Surge / sing-snell 是 0x80001),超过就不再陪它耗,直接断开。
const drainLimit = 0x80000

// serve 按 command 分 TCP/UDP。reader/writer 已按版本建好,以下逻辑版本无关。
//
// CommandConnect(0x01)一条连接只跑一条流。ConnectV2(0x05)的连接可复用:一条流的两个方向各自以
// 零长度 record 结束之后,客户端可以在同一条连接上接着发下一个请求 —— 加密状态沿用(不重新握手、
// 不重发 salt),服务端对每个请求各回一次应答。
func (s *Server) serve(ctx context.Context, conn stat.Connection, user *protocol.MemoryUser, req request, reader snellReader, writer snellWriter, dispatcher routing.Dispatcher, sessPolicy policy.Session) error {
	for {
		switch req.command {
		case commandConnect, commandConnectV2:
			reusable, err := s.serveTCP(ctx, conn, req, reader, writer, dispatcher, sessPolicy)
			if err != nil || !reusable {
				return err
			}
		case commandUDP:
			return s.handleUDP(ctx, reader, writer, dispatcher, sessPolicy)
		default:
			return errors.New("snell: unsupported command ", req.command)
		}

		// 上一条流两个方向都正常结束了,等客户端在这条连接上发下一个请求。空闲多久算到头用
		// ConnectionIdle:客户端的连接池最多把一条空闲连接留 180 秒(sing-snell;mihomo 是 15 秒),
		// 默认的 300 秒够它先放手。服务端先关的话,sing-snell 的池里会留下一条死连接,它的下一个
		// 请求就得失败一次 —— 所以别把 connIdle 调到 180 秒以下。
		_ = conn.SetReadDeadline(time.Now().Add(sessPolicy.Timeouts.ConnectionIdle))
		var err error
		if req, err = readRequest(reader); err != nil {
			if err == io.EOF || goerrors.Is(err, os.ErrDeadlineExceeded) {
				return nil // 客户端关了连接,或者空闲到点
			}
			return errors.New("snell: read next request").Base(err)
		}
		_ = conn.SetReadDeadline(time.Time{})

		// 后续请求不再握手,用户是这条连接建立时认下的。不查这一步的话,被删掉的用户只要连接池
		// 不空就能一直用下去 —— 没有复用的时候,它的下一个请求必然要重新握手、当场被拒。
		if !s.hasUser(user) {
			return errors.New("snell: user ", user.Email, " is gone, closing reused connection")
		}
	}
}

// hasUser 报告 user 是否还在用户表里(按指针:删掉重加的同名用户算另一个人,它的 PSK 可能已经换了)。
func (s *Server) hasUser(user *protocol.MemoryUser) bool {
	for _, u := range s.snapshotUsers() {
		if u == user {
			return true
		}
	}
	return false
}

// streamContext 给一条流准备它自己的 ctx。Outbound / Content 是分发器按「一条流」写的状态(目标、
// 嗅探到的协议与域名、RouteTarget……),worker 只在连接建立时各给了一份;复用连接上先后要跑多条流,
// 共用同一份的话,上一个请求嗅探出的结果会漏给下一个请求的路由。
func streamContext(ctx context.Context, dest xnet.Destination) context.Context {
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	if content := session.ContentFromContext(ctx); content != nil {
		ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: content.SniffingRequest})
	}
	return accessLogCtx(ctx, dest)
}

// 出站在交出任何数据之前就失败(连不上、解析不了、被路由拒掉)时回给客户端的 ReplyError:
// 0x02 | code | 文案长度 | 文案。具体原因只进服务端日志,入站这里只知道「没成」;code 取 0xff ——
// 参考实现记下的官方服务端行为里,网络层的错误走的也是它。
const (
	replyErrorCode    = 0xff
	replyErrorMessage = "connection failed"
)

// replyErrorLinger 是回完 ReplyError 之后最多等客户端关连接多久。
const replyErrorLinger = 2 * time.Second

// closeAfterReplyError 在回完 ReplyError、关连接之前调用:先半关闭写端(客户端读完错误应答立刻读到
// EOF),再把客户端已经发来、我们没读的数据读掉,等它先关。直接关的话,收缓冲里还剩没读的数据(请求
// 后面跟着的首包)会让内核发 RST 而不是 FIN;Windows 客户端收到 RST 会把还没读的 ReplyError 一起丢掉,
// 只看到「连接被重置」。
func closeAfterReplyError(conn stat.Connection, uplink <-chan error, uplinkExited bool) {
	if cw, ok := stat.TryUnwrapStatsConn(conn).(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(replyErrorLinger))
	// 上行 goroutine 还在读的话,等它读到 EOF / 到点 / 往已放掉的 link 写失败后退出,不和它抢着读。
	if !uplinkExited {
		<-uplink
	}
	var b [4096]byte
	for discarded := 0; discarded < drainLimit; {
		n, err := conn.Read(b[:])
		if err != nil {
			return
		}
		discarded += n
	}
}

// replyWriter 是一条流的下行写端。应答(ReplyTunnel)等到出站交出第一批数据才回,和这批数据放进
// 同一个 record(官方服务端也是这样):在那之前出站还可能失败,那时该回的是 ReplyError,而不是先说
// 隧道通了、再把连接关掉 —— 后者会让分不清「TCP 被关」与「结束 record」的客户端把死连接放回池里。
type replyWriter struct {
	writer  snellWriter
	rest    buf.Writer
	replied bool
}

func (w *replyWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.replied {
		return w.rest.WriteMultiBuffer(mb)
	}
	w.replied = true
	first := make([]byte, 1, 1+mb.Len())
	first[0] = replyTunnel
	for _, b := range mb {
		first = append(first, b.Bytes()...)
	}
	buf.ReleaseMulti(mb)
	_, err := w.writer.Write(first)
	return err
}

// serveTCP 转发一条 TCP 流。返回 true 表示这条流的两个方向都已按协议结束(零长度 record 一收一发),
// 连接上可以接着读下一个请求;只有 ConnectV2 的流才会返回 true。
//
// 上行、下行各一个 goroutine 只管搬数据,怎么收场由这里统一决定 —— 往客户端写结束 record / 错误应答
// 都等下行 goroutine 退出之后才做,不会有两处同时写。
func (s *Server) serveTCP(ctx context.Context, conn stat.Connection, req request, reader snellReader, writer snellWriter, dispatcher routing.Dispatcher, sessPolicy policy.Session) (bool, error) {
	reuse := req.command == commandConnectV2

	// 这条流自己的 ctx,流结束就 cancel:出站那一侧、在线 IP 记账都挂在分发用的 ctx 上,连接不复用时
	// 它们随连接一起收场;复用之后连接还要活很久,得按流收。
	ctx, cancel := context.WithCancel(streamContext(ctx, req.destination))
	defer cancel()

	link, err := dispatcher.Dispatch(ctx, req.destination)
	if err != nil {
		return false, errors.New("snell: dispatch").Base(err)
	}
	abort := func(err error) (bool, error) {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return false, errors.New("snell: connection ends").Base(err)
	}

	timer := signal.CancelAfterInactivity(ctx, cancel, sessPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	// 两个结果都是 buf.Copy 的原始返回值:nil = 这个方向正常结束(上行:读到客户端的结束 record;
	// 下行:目标 EOF)。先交结果、再缩短定时器,这样定时器到点时结果一定已经在 channel 里。
	uplink := make(chan error, 1)
	downlink := make(chan error, 1)
	response := &replyWriter{writer: writer, rest: buf.NewWriter(writer)}
	go func() {
		err := buf.Copy(buf.NewReader(reader), link.Writer, buf.UpdateActivity(timer))
		if err == nil {
			common.Close(link.Writer)
		}
		uplink <- err
		timer.SetTimeout(sessPolicy.Timeouts.DownlinkOnly)
	}()
	go func() {
		err := buf.Copy(link.Reader, response, buf.UpdateActivity(timer))
		downlink <- err
		timer.SetTimeout(sessPolicy.Timeouts.UplinkOnly)
	}()

	// 等下行结束。
	var uplinkErr, downlinkErr error
	uplinkExited, timedOut := false, false
	for waiting := true; waiting; {
		select {
		case uplinkErr = <-uplink:
			uplinkExited = true
			if uplinkErr != nil && !buf.IsWriteError(uplinkErr) {
				return abort(uplinkErr) // 客户端这头读不下去了
			}
		case downlinkErr = <-downlink:
			waiting = false
		case <-ctx.Done():
			// 定时器到点:放掉 link 让下行 goroutine 退出;它要是正卡在往客户端写,让那次写立刻失败。
			timedOut = true
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			_ = conn.SetWriteDeadline(time.Now())
			downlinkErr = <-downlink
			_ = conn.SetWriteDeadline(time.Time{})
			waiting = false
		}
	}
	if !uplinkExited {
		select {
		case uplinkErr = <-uplink:
			uplinkExited = true
		default:
		}
	}
	clientEnded := uplinkExited && uplinkErr == nil

	switch {
	case downlinkErr == nil:
		// 目标 EOF。
	case timedOut && clientEnded && buf.IsReadError(downlinkErr):
		// 客户端已经结束,目标在 DownlinkOnly 之内再没有动静 —— xray 不把半关闭传给目标,「客户端先关、
		// 目标还开着」的流都是这样收场的,算正常结束。这时关 TCP 的话,正等着结束 record 的客户端
		// 分不清两者,会把死连接放回池里。
	default:
		// 出站那边失败了,或者这条流整个空闲到点。还没回过应答、又确实是出站没成,就把话说明白;
		// 别的情况只断开,不能让客户端把截断的响应当成完整的。
		if !response.replied && !timedOut {
			if _, err := writer.Write(append([]byte{replyError, replyErrorCode, byte(len(replyErrorMessage))}, replyErrorMessage...)); err == nil {
				reusable, err := abort(downlinkErr)
				closeAfterReplyError(conn, uplink, uplinkExited)
				return reusable, err
			}
		}
		return abort(downlinkErr)
	}

	// 下行正常结束:发零长度 record,客户端才知道到此为止。不发的话,靠「连接关闭」表示响应结束的
	// 流量(HTTP/1.0、不带 Content-Length 的 Connection: close、whois……)会一直挂到某一头超时。
	// 目标一个字节没发就结束的,应答在这里补上。
	if !response.replied {
		if _, err := writer.Write([]byte{replyTunnel}); err != nil {
			return abort(err)
		}
	}
	if err := writer.writeZeroChunk(); err != nil {
		return abort(err)
	}

	// 半关闭:下行结束了,客户端这一半还可以接着发,最多等它 UplinkOnly(定时器在下行结束时已经缩短)。
	if !uplinkExited {
		select {
		case uplinkErr = <-uplink:
			uplinkExited = true
		case <-ctx.Done():
		}
	}
	if uplinkExited && uplinkErr == nil {
		return reuse, nil
	}
	common.Interrupt(link.Reader)
	common.Interrupt(link.Writer)
	if !reuse {
		return false, nil
	}

	// 可复用的连接,只是客户端那一半迟迟不结束(UplinkOnly 到点),或者它在出站收场之后还在发数据。
	// 这条流在我们这边到此为止(link 已经放掉),但连接不能关:客户端读到了结束 record,会把这条连接
	// 当成可复用的放回池里,关掉等于给它留一条死连接。所以只把它后面发来的数据读掉丢弃,等到它的
	// 结束 record 为止。
	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(sessPolicy.Timeouts.ConnectionIdle))
	if !uplinkExited {
		uplinkErr = <-uplink
	}
	if uplinkErr == nil {
		return true, nil
	} else if !buf.IsWriteError(uplinkErr) {
		return false, errors.New("snell: drain request").Base(uplinkErr)
	}
	for discarded := 0; discarded < drainLimit; {
		record, err := reader.nextRecord()
		if err == io.EOF {
			return true, nil
		}
		if err != nil {
			return false, errors.New("snell: drain request").Base(err)
		}
		discarded += len(record)
	}
	return false, errors.New("snell: too much data after response ended")
}

// udpSources 把域名形式的回包来源换成 IP。snell 的回包地址只有 IPv4 / IPv6 两种写法,而出站
// (freedom)会把「会话第一个目标」的来源还原成当初拨号用的地址 —— 那个目标是域名的话,回包来源
// 就是域名,原样拿去编码只会失败。真实的对端 IP 出站没有交出来,这里只能自己再解析一次;每个域名
// 只解析一次并记住(失败也记),同一个会话里它的回包来源不会变来变去。
type udpSources struct {
	sync.Mutex
	ips map[string]xnet.Address // nil = 解析失败
}

func (s *udpSources) resolve(source xnet.Destination) (xnet.Destination, error) {
	if !source.Address.Family().IsDomain() {
		return source, nil
	}
	domain := source.Address.Domain()

	s.Lock()
	defer s.Unlock()
	ip, ok := s.ips[domain]
	if !ok {
		// freedom 不配 domainStrategy 时,拨号走的也是这个解析入口。
		if addr, err := xnet.ResolveUDPAddr("udp", source.NetAddr()); err == nil {
			ip = xnet.IPAddress(addr.IP)
		}
		if s.ips == nil {
			s.ips = make(map[string]xnet.Address)
		}
		s.ips[domain] = ip
	}
	if ip == nil {
		return source, errors.New("snell: udp response source ", domain, " has no ip")
	}
	source.Address = ip
	return source, nil
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

	var sources udpSources
	udpServer := udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		payload := packet.Payload
		if payload == nil {
			return
		}
		source, err := sources.resolve(packet.Source)
		if err != nil {
			// 只丢这一个回包:会话里还有别的目标在收发。
			errors.LogInfoInner(ctx, err, "snell: drop udp response from ", packet.Source)
			payload.Release()
			return
		}
		if err := packetWriter.writePacket(payload.Bytes(), source); err != nil {
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
		// 每个数据报标上它自己的目标。udp.Dispatcher 整个会话只按第一个目标建一条链路,
		// 不标的话之后发往别处的数据报全会被送到第一个目标(游戏 / 语音 / P2P 这类一个会话
		// 要和多个地址通信的应用就坏了);直连出站认 b.UDP,按包各发各的(trojan / shadowsocks
		// / anytls 的服务端都是这么做的)。会话走哪个出站仍由第一个目标的路由决定。
		target := dest
		b.UDP = &target
		// 逐包挂日志:UDP 一条隧道会打到很多目标,不能共用一条 AccessMessage。
		udpServer.Dispatch(accessLogCtx(ctx, dest), dest, b)
	}
}
