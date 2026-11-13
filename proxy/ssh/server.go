// server.go:SSH 入站(proxy.Inbound),给 mihomo 的 `type: ssh` 出站这类「把 SSH 当代理用」的客户端连。
//
// 一条 TCP = 一次 SSH 认证 = 一个用户;客户端在上面每代理一个请求就开一个 direct-tcpip channel。
// 每个 channel 当一条独立连接走标准 dispatcher.Dispatch(带认证出来的用户、Source=TCP 对端),
// 于是 agent 侧的连接数 / IP 数限制、限速、按用户流量统计、在线记录全部按 channel 自动生效。
//
// 安全边界:这里只是个代理,不是登录服务。
//   - 只接受 direct-tcpip channel;session(shell / exec / subsystem=sftp)、x11、forwarded-tcpip、
//     direct-streamlocal 等一律拒绝,用户在服务器上执行不了任何东西。
//   - 全局请求(tcpip-forward、streamlocal-forward 等远端转发)一律回失败,开不了端口。
//   - 认证失败按来源 IP 拖延 + 封禁,见 guard.go。
//
// 踢人:SSH 只在建连时认证一次,客户端会一直复用这条连接。所以
//   - 每开一个新 channel 都重新确认这个用户还在当前用户表里、凭据没换(否则拒掉并断开整条连接);
//   - RemoveUser 立刻断开该用户的全部 SSH 连接;
//   - Close(入站被移除 / 整入站替换时 proxyman 会调)断开全部 SSH 连接。
package ssh

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
	gossh "golang.org/x/crypto/ssh"
)

const (
	// defaultServerVersion 伪装成常见发行版的 OpenSSH。
	defaultServerVersion = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"

	// handshakeTimeout 是从 TCP 建立到认证完成的上限(OpenSSH 的 LoginGraceTime 默认 120s,
	// 代理客户端用不了这么久,给扫描器留太久只是白占资源)。
	handshakeTimeout = 20 * time.Second
	// maxHandshakes 是同时处于「未认证」状态的连接上限。密钥交换要花 CPU,
	// 一次涌进成千上万条扫描连接时超出的直接关掉,已认证的连接不受影响。
	maxHandshakes = 256

	// 认证后的保活:SSH 本身没有心跳,客户端(NAT 超时、断网)死掉之后服务端这条连接会一直挂着。
	// 仿 OpenSSH 的 ClientAliveInterval,定期发 keepalive@openssh.com,回不来就断。
	keepaliveInterval = 60 * time.Second
	keepaliveTimeout  = 90 * time.Second

	// Permissions.Extensions 里携带认证出来的身份。不能靠回调里写闭包变量:
	// publickey 的回调结果按 (user,key) 缓存,最终成功的那次认证未必会再调一次回调。
	extUser  = "xray-ssh-user"
	extEmail = "xray-ssh-email"
)

// Server 是 SSH 入站处理器。
type Server struct {
	// users 是 copy-on-write 的(与 mieru/snell 一致):写侧整体替换,读侧在 RLock 里取一次快照就出锁。
	userMu sync.RWMutex
	users  []*protocol.MemoryUser

	policyManager policy.Manager
	base          gossh.ServerConfig // 每条连接拷一份再挂上本连接的回调
	guard         *authGuard
	handshakes    chan struct{}

	connMu sync.Mutex
	conns  map[*serverConn]struct{}
	closed bool
}

// serverConn 是一条已认证的 SSH 连接。
type serverConn struct {
	sconn *gossh.ServerConn
	user  *protocol.MemoryUser
}

// NewServer 从配置构建 SSH 入站。
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	return newServer(v.GetFeature(policy.ManagerType()).(policy.Manager), config)
}

func newServer(pm policy.Manager, config *ServerConfig) (*Server, error) {
	s := &Server{
		policyManager: pm,
		guard:         newAuthGuard(),
		handshakes:    make(chan struct{}, maxHandshakes),
		conns:         make(map[*serverConn]struct{}),
	}
	for _, u := range config.Users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return nil, errors.New("ssh: parse user").Base(err)
		}
		if _, ok := mu.Account.(*MemoryAccount); !ok {
			return nil, errors.New("ssh: invalid account type")
		}
		s.users = append(s.users, mu)
	}

	signer, err := parseHostKey(config.HostKey)
	if err != nil {
		return nil, err
	}
	version := strings.TrimSpace(config.ServerVersion)
	if version == "" {
		version = defaultServerVersion
	}
	if !strings.HasPrefix(version, "SSH-2.0-") {
		return nil, errors.New("ssh: serverVersion must start with SSH-2.0-")
	}
	s.base = gossh.ServerConfig{
		ServerVersion: version,
		MaxAuthTries:  6,
	}
	s.base.AddHostKey(signer)
	return s, nil
}

// parseHostKey 解析 PEM 主机私钥;为空时临时生成一把 ed25519(重启即变,只适合调试)。
func parseHostKey(pemKey string) (gossh.Signer, error) {
	if strings.TrimSpace(pemKey) == "" {
		_, priv, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			return nil, errors.New("ssh: generate host key").Base(err)
		}
		errors.LogWarning(context.Background(), "ssh: no hostKey configured, using an ephemeral ed25519 key (changes on restart)")
		return gossh.NewSignerFromKey(priv)
	}
	signer, err := gossh.ParsePrivateKey([]byte(pemKey))
	if err != nil {
		return nil, errors.New("ssh: invalid hostKey").Base(err)
	}
	return signer, nil
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Close 断开全部已认证的 SSH 连接,此后新连接一律拒绝。
// 入站被移除 / 整入站替换(RemoveHandler)时 AlwaysOnInboundHandler.Close 会调到这里 ——
// tcpWorker 只关监听器、不管已 accept 的连接,不在这里断的话,
// 已经连着的客户端(mihomo 一条连接用到天荒地老)完全感知不到增删用户。
func (s *Server) Close() error {
	s.connMu.Lock()
	s.closed = true
	conns := make([]*serverConn, 0, len(s.conns))
	for sc := range s.conns {
		conns = append(conns, sc)
	}
	s.conns = map[*serverConn]struct{}{}
	s.connMu.Unlock()
	for _, sc := range conns {
		_ = sc.sconn.Close()
	}
	return nil
}

func (s *Server) isClosed() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.closed
}

func (s *Server) track(sc *serverConn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closed {
		return false
	}
	s.conns[sc] = struct{}{}
	return true
}

func (s *Server) untrack(sc *serverConn) {
	s.connMu.Lock()
	delete(s.conns, sc)
	s.connMu.Unlock()
}

// kickEmail 断开某用户的全部 SSH 连接,返回断开的条数。
func (s *Server) kickEmail(email string) int {
	s.connMu.Lock()
	var victims []*serverConn
	for sc := range s.conns {
		if strings.EqualFold(sc.user.Email, email) {
			victims = append(victims, sc)
			delete(s.conns, sc)
		}
	}
	s.connMu.Unlock()
	for _, sc := range victims {
		_ = sc.sconn.Close()
	}
	return len(victims)
}

// connConfig 给一条连接拷一份 ServerConfig,挂上认证回调。
func (s *Server) connConfig(ip string, conn stat.Connection) *gossh.ServerConfig {
	cfg := s.base
	cfg.PasswordCallback = func(meta gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		for _, u := range s.snapshotUsers() {
			if u.Account.(*MemoryAccount).checkPassword(meta.User(), password) {
				return identity(u), nil
			}
		}
		return nil, errAuthFailed
	}
	cfg.PublicKeyCallback = func(meta gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		wire := key.Marshal()
		for _, u := range s.snapshotUsers() {
			if u.Account.(*MemoryAccount).hasKey(meta.User(), wire) {
				return identity(u), nil
			}
		}
		return nil, errAuthFailed
	}
	cfg.AuthLogCallback = func(meta gossh.ConnMetadata, method string, err error) {
		if err == nil || method == "none" {
			return
		}
		delay, banned := s.guard.fail(ip)
		if banned > 0 {
			errors.LogWarning(context.Background(), "ssh: too many auth failures from ", ip, ", blocked for ", banned)
			_ = conn.Close()
			return
		}
		errors.LogDebug(context.Background(), "ssh: auth failed from ", ip, " user=", meta.User(), " method=", method)
		time.Sleep(delay)
	}
	return &cfg
}

var errAuthFailed = errors.New("ssh: authentication failed")

func identity(u *protocol.MemoryUser) *gossh.Permissions {
	return &gossh.Permissions{Extensions: map[string]string{
		extUser:  u.Account.(*MemoryAccount).Username,
		extEmail: u.Email,
	}}
}

// resolveIdentity 按认证结果在**当前**用户表里找回用户。找不到(认证之后用户刚被摘掉)返回 nil。
func (s *Server) resolveIdentity(perms *gossh.Permissions) *protocol.MemoryUser {
	if perms == nil {
		return nil
	}
	name, email := perms.Extensions[extUser], perms.Extensions[extEmail]
	for _, u := range s.snapshotUsers() {
		if u.Email == email && u.Account.(*MemoryAccount).Username == name {
			return u
		}
	}
	return nil
}

// stillValid 报告认证出来的这个用户是否仍在当前用户表里且凭据没换。
func (s *Server) stillValid(user *protocol.MemoryUser) bool {
	for _, u := range s.snapshotUsers() {
		if u == user {
			return true
		}
		if u.Email == user.Email && u.Account.Equals(user.Account) {
			return true
		}
	}
	return false
}

func sourceIP(inb *session.Inbound) string {
	if inb == nil || !inb.Source.IsValid() || inb.Source.Address == nil || inb.Source.Address.Family().IsDomain() {
		return ""
	}
	return inb.Source.Address.IP().String()
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	base := session.InboundFromContext(ctx)
	ip := sourceIP(base)

	// 入站已关闭,或封禁中的 IP:握手前就关掉,不花一点密钥交换的 CPU,也不打日志。
	if s.isClosed() || !s.guard.allowed(ip) {
		return nil
	}
	select {
	case s.handshakes <- struct{}{}:
	default:
		errors.LogDebug(ctx, "ssh: too many pending handshakes, dropping ", ip)
		return nil
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sconn, chans, reqs, err := gossh.NewServerConn(conn, s.connConfig(ip, conn))
	<-s.handshakes
	if err != nil {
		// 扫描器、握手不全、认证失败都会落到这里:只进 debug,不刷屏。
		errors.LogDebug(ctx, "ssh: handshake from ", ip, " failed: ", err)
		return nil
	}
	_ = conn.SetDeadline(time.Time{})

	user := s.resolveIdentity(sconn.Permissions)
	if user == nil {
		_ = sconn.Close()
		return nil
	}
	s.guard.success(ip)

	sc := &serverConn{sconn: sconn, user: user}
	if !s.track(sc) {
		_ = sconn.Close()
		return nil
	}
	defer s.untrack(sc)
	defer sconn.Close()

	// 全局请求(tcpip-forward / streamlocal-forward / 未知请求)一律回失败。
	go gossh.DiscardRequests(reqs)

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go keepalive(connCtx, sconn)

	var wg sync.WaitGroup
	for newCh := range chans {
		if newCh.ChannelType() != "direct-tcpip" {
			// session(shell/exec/sftp)、x11、forwarded-tcpip、direct-streamlocal@openssh.com ……
			_ = newCh.Reject(gossh.Prohibited, "administratively prohibited")
			errors.LogDebug(ctx, "ssh: rejected channel type ", newCh.ChannelType(), " from ", user.Email)
			continue
		}
		if !s.stillValid(user) {
			// 用户已被摘掉 / 凭据已换:拒掉并断开整条连接,客户端重连时认证就过不去了。
			_ = newCh.Reject(gossh.Prohibited, "administratively prohibited")
			errors.LogInfo(ctx, "ssh: user ", user.Email, " no longer valid, closing connection")
			_ = sconn.Close()
			continue // 继续把 chans 排空,直到它随连接关闭
		}
		wg.Add(1)
		go func(newCh gossh.NewChannel) {
			defer wg.Done()
			s.handleDirectTCPIP(connCtx, base, user, newCh, dispatcher)
		}(newCh)
	}
	cancel()
	wg.Wait()
	return nil
}

// keepalive 定期发 keepalive@openssh.com,对端回不来就断开(客户端回 failure 也算活着)。
func keepalive(ctx context.Context, sconn *gossh.ServerConn) {
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		res := make(chan error, 1)
		go func() {
			_, _, err := sconn.SendRequest("keepalive@openssh.com", true, nil)
			res <- err
		}()
		timer := time.NewTimer(keepaliveTimeout)
		select {
		case err := <-res:
			timer.Stop()
			if err != nil {
				_ = sconn.Close()
				return
			}
		case <-timer.C:
			_ = sconn.Close()
			return
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

// directTCPIPPayload 是 RFC 4254 §7.2 direct-tcpip 的 channel 附加数据。
type directTCPIPPayload struct {
	Host     string
	Port     uint32
	OrigHost string
	OrigPort uint32
}

func (s *Server) handleDirectTCPIP(ctx context.Context, base *session.Inbound, user *protocol.MemoryUser, newCh gossh.NewChannel, dispatcher routing.Dispatcher) {
	var req directTCPIPPayload
	if err := gossh.Unmarshal(newCh.ExtraData(), &req); err != nil || req.Host == "" || req.Port == 0 || req.Port > 65535 {
		_ = newCh.Reject(gossh.ConnectionFailed, "invalid request")
		return
	}
	dest := xnet.TCPDestination(xnet.ParseAddress(req.Host), xnet.Port(req.Port))

	// 每个 channel 一份独立的 Inbound(带认证用户),dispatcher 据此做统计 / 限速 / 限连接数。
	ib := session.Inbound{}
	if base != nil {
		ib = *base
	}
	ib.User = user
	ib.Name = "ssh"
	ib.CanSpliceCopy = 3
	ctx = session.ContextWithInbound(ctx, &ib)
	ctx = c.ContextWithID(ctx, session.NewID())
	ctx = streamContext(ctx, dest)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sessPolicy := s.policyManager.ForLevel(user.Level)
	ctx = policy.ContextWithBufferPolicy(ctx, sessPolicy.Buffer)

	// 先分发再接受 channel:连接数 / IP 数超限、用户已被摘掉时 Dispatch 直接报错,
	// 回给客户端「connect failed」,与 OpenSSH 连不上目标时的表现一致。
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		_ = newCh.Reject(gossh.ConnectionFailed, "connect failed")
		errors.LogInfoInner(ctx, err, "ssh: dispatch ", dest, " failed")
		return
	}
	ch, chReqs, err := newCh.Accept()
	if err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return
	}
	go gossh.DiscardRequests(chReqs)
	defer ch.Close()

	timer := signal.CancelAfterInactivity(ctx, cancel, sessPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	requestDone := func() error {
		defer timer.SetTimeout(sessPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(buf.NewReader(ch), link.Writer, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessPolicy.Timeouts.UplinkOnly)
		if err := buf.Copy(link.Reader, buf.NewWriter(ch), buf.UpdateActivity(timer)); err != nil {
			return err
		}
		return ch.CloseWrite()
	}
	if err := task.Run(ctx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		errors.LogDebugInner(ctx, err, "ssh: channel ends")
	}
}

// streamContext 给一个 channel 准备独立的出站 / 嗅探 / 访问日志上下文(同 snell):
// 一条 SSH 连接上并发多个 channel,这些都不能共用 proxyman 给整条连接的那一份。
func streamContext(ctx context.Context, dest xnet.Destination) context.Context {
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	if content := session.ContentFromContext(ctx); content != nil {
		ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: content.SniffingRequest})
	}
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
		Email:  email,
	})
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
