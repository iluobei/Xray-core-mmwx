package wireguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/curve25519"
)

var nullDestination = net.TCPDestination(net.AnyIP, 0)

// 支持 api 侧的 AddUser/RemoveUser 等动态用户管理。
var _ proxy.UserManager = (*Server)(nil)

var _ common.Closable = (*Server)(nil)

type Server struct {
	bindServer *netBindServer

	info          routingInfo
	policyManager policy.Manager

	// 以下为支持 per-user 识别与动态 peer 管理所加,移植自上游 345c76f9(#6360)。
	// tun 过去被就地丢弃,导致入站运行期不可回收(每次整入站重建都会泄漏一套
	// gvisor stack + wireguard Device + receive goroutine);保存下来同时也是
	// AddUser/RemoveUser 走 IpcSet 增量改 peer 的前提。
	conf  *DeviceConfig
	tun   Tunnel
	pub   [32]byte
	users *sync.Map // key: [32]byte 公钥 -> *protocol.MemoryUser
	mu    sync.Mutex
}

type routingInfo struct {
	ctx        context.Context
	dispatcher routing.Dispatcher
	inboundTag *session.Inbound
	contentTag *session.Content
}

func NewServer(ctx context.Context, conf *DeviceConfig) (*Server, error) {
	v := core.MustFromContext(ctx)

	endpoints, hasIPv4, hasIPv6, err := parseEndpoints(conf)
	if err != nil {
		return nil, err
	}

	server := &Server{
		bindServer: &netBindServer{
			netBind: netBind{
				dns: v.GetFeature(dns.ClientType()).(dns.Client),
				dnsOption: dns.IPOption{
					IPv4Enable: hasIPv4,
					IPv6Enable: hasIPv6,
				},
				workers:   int(conf.NumWorkers),
				readQueue: make(chan *netReadInfo),
			},
		},
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		conf:          conf,
		users:         new(sync.Map),
	}

	if err := server.loadUsers(conf); err != nil {
		return nil, err
	}
	if pub, err := serverPubKey(conf.SecretKey); err == nil {
		server.pub = pub
	} else {
		// 只用于 AddUser 时挡「peer 公钥 == 服务端公钥」,推导不出来不该拦住启动。
		errors.LogWarningInner(ctx, err, "wireguard: cannot derive server public key")
	}

	tun, err := conf.createTun()(endpoints, int(conf.Mtu), server.forwardConnection)
	if err != nil {
		return nil, err
	}

	if err = tun.BuildDevice(server.buildIPCRequest(), server.bindServer); err != nil {
		_ = tun.Close()
		return nil, err
	}
	server.tun = tun

	return server, nil
}

// loadUsers 把配置里的 peer 统一收敛成 users 表。
// 两个来源:
//   - conf.Users —— 新形态,带 email,限速/连接数/流量统计据此归属
//   - conf.Peers —— 旧形态,同一公钥未在 Users 出现时补一个无 email 的用户,
//     保证既有配置行为不变(只是仍然没有用户身份,与今天一致)
func (s *Server) loadUsers(conf *DeviceConfig) error {
	for _, u := range conf.Users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return errors.New("failed to parse wireguard user ", u.Email).Base(err)
		}
		acc, ok := mu.Account.(*MemoryAccount)
		if !ok {
			return errors.New("unexpected account type for wireguard user ", u.Email)
		}
		if _, dup := s.users.LoadOrStore(acc.Pub, mu); dup {
			return errors.New("duplicated wireguard peer public key for user ", u.Email)
		}
	}

	for _, p := range conf.Peers {
		acc, err := p.AsAccount()
		if err != nil {
			return err
		}
		s.users.LoadOrStore(acc.(*MemoryAccount).Pub, &protocol.MemoryUser{Account: acc})
	}
	return s.validateUserAddrs(nil)
}

// validateUserAddrs 校验 allowed_ips 足以作为「身份」使用。
//
// GetUserByAddr 是按隧道内源地址落到某个 peer 的 allowed_ips 上来归属流量的,
// 所以地址集合一旦重叠,归属就取决于 sync.Map 的遍历顺序 —— 表现为流量、
// 配额和限速随机算到另一个用户头上,且没有任何报错。宁可在启动/加用户时炸掉。
//
// 没有任何 peer 带 email 时直接放行:那是纯粹的旧配置,本来就没有用户身份,
// allowed_ips 写 0.0.0.0/0 是合法且常见的,不能因为本次改动把它判成非法。
func (s *Server) validateUserAddrs(extra *protocol.MemoryUser) error {
	type entry struct {
		name string
		acc  *MemoryAccount
	}

	var all []entry
	hasEmail := false
	collect := func(u *protocol.MemoryUser) {
		acc, ok := u.Account.(*MemoryAccount)
		if !ok {
			return
		}
		name := u.Email
		if name == "" {
			name = "peer " + hex.EncodeToString(acc.Pub[:4])
		} else {
			hasEmail = true
		}
		all = append(all, entry{name, acc})
	}

	s.users.Range(func(key, value any) bool {
		collect(value.(*protocol.MemoryUser))
		return true
	})
	if extra != nil {
		collect(extra)
	}
	if !hasEmail {
		return nil
	}

	for _, e := range all {
		if len(e.acc.AllowedIPs) == 0 {
			return errors.New("wireguard ", e.name, ": empty allowed_ips, user would be unidentifiable")
		}
		for _, pfx := range e.acc.AllowedIPs {
			if pfx.Masked() != pfx {
				return errors.New("wireguard ", e.name, ": allowed_ip ", pfx.String(), " is not in canonical form")
			}
		}
	}

	for i := range all {
		for j := i + 1; j < len(all); j++ {
			for _, a := range all[i].acc.AllowedIPs {
				for _, b := range all[j].acc.AllowedIPs {
					if a.Contains(b.Addr()) || b.Contains(a.Addr()) {
						return errors.New("wireguard: allowed_ip ", a.String(), " of ", all[i].name,
							" overlaps ", b.String(), " of ", all[j].name, "; traffic attribution would be ambiguous")
					}
				}
			}
		}
	}
	return nil
}

// buildIPCRequest 从 users 表生成设备初始配置。
// 服务端模式不写 peer 的 endpoint:客户端地址由握手学习(且会漫游),
// 写死反而会在客户端换网时把包发到旧地址。
func (s *Server) buildIPCRequest() string {
	var request strings.Builder

	request.WriteString("private_key=" + s.conf.SecretKey + "\n")
	// placeholder, we'll handle actual port listening on Xray
	request.WriteString("listen_port=1337\n")

	s.users.Range(func(key, value any) bool {
		request.WriteString(peerIPCRequest(value.(*protocol.MemoryUser).Account.(*MemoryAccount), false))
		return true
	})

	return request.String()
}

// serverPubKey 由私钥推导服务端公钥。私钥到达这里时已由 infra/conf 统一成 hex。
func serverPubKey(secret string) ([32]byte, error) {
	var priv, pub [32]byte
	dat, err := hex.DecodeString(secret)
	if err != nil || len(dat) != 32 {
		return pub, errors.New("invalid wireguard secret key")
	}
	copy(priv[:], dat)
	curve25519.ScalarBaseMult(&pub, &priv)
	return pub, nil
}

// Network implements proxy.Inbound.
func (*Server) Network() []net.Network {
	return []net.Network{net.Network_UDP}
}

// Process implements proxy.Inbound.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	s.info = routingInfo{
		ctx:        ctx,
		dispatcher: dispatcher,
		inboundTag: session.InboundFromContext(ctx),
		contentTag: session.ContentFromContext(ctx),
	}

	ep, err := s.bindServer.ParseEndpoint(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	nep := ep.(*netEndpoint)
	nep.conn = conn

	reader := buf.NewPacketReader(conn)
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			nep.conn = nil
			buf.ReleaseMulti(mb)
			return err
		}

		for i, b := range mb {
			buff := b.Bytes()

			if b.Len() > 3 {
				buff[1] = 0
				buff[2] = 0
				buff[3] = 0
			}

			select {
			case s.bindServer.readQueue <- &netReadInfo{
				buff:     buff,
				endpoint: nep,
			}:
			case <-s.bindServer.closedCh:
				nep.conn = nil
				buf.ReleaseMulti(mb[i:])
				return errors.New("bind closed")
			}
		}
	}
}

func (s *Server) forwardConnection(dest net.Destination, conn net.Conn) {
	if s.info.dispatcher == nil {
		errors.LogError(s.info.ctx, "unexpected: dispatcher == nil")
		return
	}

	remote := conn.RemoteAddr()
	if remote == nil {
		errors.LogError(s.info.ctx, "wireguard: nil remote addr")
		return
	}

	ctx, cancel := context.WithCancel(core.ToBackgroundDetachedContext(s.info.ctx))
	sid := session.NewID()
	ctx = c.ContextWithID(ctx, sid)
	inbound := session.Inbound{} // since promiscuousModeHandler mixed-up context, we shallow copy inbound (tag) and content (configs)
	if s.info.inboundTag != nil {
		inbound = *s.info.inboundTag
	}
	inbound.Name = "wireguard"
	inbound.CanSpliceCopy = 3

	// overwrite the source to use the tun address for each sub context.
	// Since gvisor.ForwarderRequest doesn't provide any info to associate the sub-context with the Parent context
	// Currently we have no way to link to the original **public** source address —— 但隧道内的源地址是有的,
	// 而它足以定位用户:wireguard-go 在解密后做 cryptokey routing 校验(device/receive.go),
	// 源地址不在该 peer 的 allowed_ips 里的包会被直接丢弃,所以 tun 内地址不可伪造。
	inbound.Source = net.DestinationFromAddr(remote)

	// 填 User 之后,限速 / 并发连接数 / per-user 流量统计三者一并生效 ——
	// 它们都只依赖 si.User.Email,与协议无关。
	if user := s.userByConnAddr(remote); user != nil {
		inbound.User = user
	}
	ctx = session.ContextWithInbound(ctx, &inbound)
	content := new(session.Content)
	if s.info.contentTag != nil {
		content.SniffingRequest = s.info.contentTag.SniffingRequest
	}
	ctx = session.ContextWithContent(ctx, content)
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   nullDestination,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})

	err := s.info.dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: buf.NewReader(conn),
		Writer: buf.NewWriter(conn),
	})

	if err != nil {
		errors.LogInfoInner(ctx, err, "connection ends")
	}

	cancel()
	conn.Close()
}

// Close 回收 tun/device。入站被销毁时由 app/proxyman/inbound 的 worker
// 经 common.Close(w.proxy) 调用 —— 过去 Server 没有这个方法,加上 NewServer
// 就地丢弃 tun 句柄,每次入站重建都会漏一套 gvisor stack + Device + 收包 goroutine。
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tun == nil {
		return nil
	}
	err := s.tun.Close()
	s.tun = nil
	return err
}

// userByConnAddr 用隧道内源地址反查用户。取不到时返回 nil(调用方按匿名处理),
// 不阻断连接 —— 旧配置(只有 peers、没有 users)下本来就没有用户身份。
func (s *Server) userByConnAddr(remote net.Addr) *protocol.MemoryUser {
	var addr netip.Addr
	switch v := remote.(type) {
	case *net.TCPAddr:
		addr, _ = netip.AddrFromSlice(v.IP)
	case *net.UDPAddr:
		addr, _ = netip.AddrFromSlice(v.IP)
	default:
		errors.LogError(s.info.ctx, "wireguard: invalid addr type ", reflect.TypeOf(v))
		return nil
	}
	return s.GetUserByAddr(context.Background(), addr.Unmap())
}

// GetUserByAddr 按隧道内地址查用户。allowed_ips 必须是互不重叠的 host 前缀,
// 这一点由 infra/conf 在 server 模式下强制校验(否则一个 /0 就会吞掉全部流量,
// 让全节点的流量与配额都算到同一个用户头上)。
func (s *Server) GetUserByAddr(ctx context.Context, addr netip.Addr) (user *protocol.MemoryUser) {
	s.users.Range(func(key, value any) bool {
		peer := value.(*protocol.MemoryUser).Account.(*MemoryAccount)
		for i := range peer.AllowedIPs {
			if peer.AllowedIPs[i].Contains(addr) {
				user = value.(*protocol.MemoryUser)
				return false
			}
		}
		return true
	})
	return
}

func (s *Server) GetUser(ctx context.Context, email string) (user *protocol.MemoryUser) {
	s.users.Range(func(key, value any) bool {
		if value.(*protocol.MemoryUser).Email == email {
			user = value.(*protocol.MemoryUser)
			return false
		}
		return true
	})
	return
}

func (s *Server) GetUsers(ctx context.Context) (users []*protocol.MemoryUser) {
	s.users.Range(func(key, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return
}

func (s *Server) GetUsersCount(context.Context) (count int64) {
	s.users.Range(func(key, value any) bool {
		count++
		return true
	})
	return
}

// AddUser 增量加一个 peer,不重建入站、不影响在线用户。
func (s *Server) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tun == nil {
		return errors.New("wireguard: device not ready")
	}
	peer, ok := user.Account.(*MemoryAccount)
	if !ok {
		return errors.New("wireguard: unexpected account type")
	}
	if peer.Pub == s.pub {
		return errors.New("wireguard: peer public key must differ from the server's")
	}
	if _, dup := s.users.Load(peer.Pub); dup {
		return errors.New("wireguard: peer public key already exists")
	}
	if err := s.validateUserAddrs(user); err != nil {
		return err
	}
	if err := s.tun.IpcSet(peerIPCRequest(peer, true)); err != nil {
		return err
	}
	s.users.Store(peer.Pub, user)
	return nil
}

// RemoveUser 增量删一个 peer。IpcSet 与内存表必须同步 ——
// 两者漂移会造成静默的归属错误(限速失效,或流量算到别人头上)。
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tun == nil {
		return errors.New("wireguard: device not ready")
	}
	user := s.GetUser(ctx, email)
	if user == nil {
		return nil // 幂等:已经不在了
	}
	peer := user.Account.(*MemoryAccount)
	if err := s.tun.IpcSet("public_key=" + hex.EncodeToString(peer.Pub[:]) + "\nremove=true\n"); err != nil {
		return err
	}
	s.users.Delete(peer.Pub)
	return nil
}

// peerIPCRequest 拼一个 peer 的 IPC 片段。replaceAllowedIPs 用于增量添加时
// 覆盖既有 allowed_ips,避免同一公钥重复添加后地址集合越滚越大。
func peerIPCRequest(peer *MemoryAccount, replaceAllowedIPs bool) string {
	var sb strings.Builder
	sb.WriteString("public_key=" + hex.EncodeToString(peer.Pub[:]) + "\n")
	if replaceAllowedIPs {
		sb.WriteString("replace_allowed_ips=true\n")
	}
	for i := range peer.AllowedIPs {
		sb.WriteString("allowed_ip=" + peer.AllowedIPs[i].String() + "\n")
	}
	if peer.PreSharedKey != "" {
		sb.WriteString("preshared_key=" + peer.PreSharedKey + "\n")
	}
	if peer.KeepAlive != 0 {
		sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.KeepAlive))
	}
	return sb.String()
}
