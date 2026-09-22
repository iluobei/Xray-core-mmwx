package wireguard

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"golang.zx2c4.com/wireguard/conn"
)

func pubHex(b byte) string {
	return strings.Repeat(string("0123456789abcdef"[b&0xf]), 64)
}

func newTestServer(t *testing.T, conf *DeviceConfig) (*Server, error) {
	t.Helper()
	s := &Server{conf: conf, users: new(sync.Map)}
	return s, s.loadUsers(conf)
}

func named(email string, p *PeerConfig) *protocol.User {
	return &protocol.User{Email: email, Account: serial.ToTypedMessage(p)}
}

func mustUsers(t *testing.T, users ...*protocol.User) []*protocol.User {
	t.Helper()
	return users
}

func peer(pub string, ips ...string) *PeerConfig {
	return &PeerConfig{PublicKey: pub, AllowedIps: ips}
}

// 两个用户各自一个 /32:归属必须精确,且互不串味。这是整个 per-user 计费的地基。
func TestLoadUsersDistinctHostPrefixes(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	conf.Users = mustUsers(t,
		named("alice", peer(pubHex(2), "10.0.0.2/32", "fd00::2/128")),
		named("bob", peer(pubHex(3), "10.0.0.3/32", "fd00::3/128")),
	)

	s, err := newTestServer(t, conf)
	if err != nil {
		t.Fatalf("loadUsers: %v", err)
	}
	if got := s.GetUsersCount(context.Background()); got != 2 {
		t.Fatalf("GetUsersCount = %d, want 2", got)
	}

	for _, tc := range []struct{ addr, want string }{
		{"10.0.0.2", "alice"},
		{"10.0.0.3", "bob"},
		{"fd00::2", "alice"},
		{"fd00::3", "bob"},
	} {
		u := s.GetUserByAddr(context.Background(), netip.MustParseAddr(tc.addr))
		if u == nil || u.Email != tc.want {
			t.Fatalf("GetUserByAddr(%s) = %v, want %s", tc.addr, u, tc.want)
		}
	}
	// 不属于任何 peer 的地址不应该被硬塞给某个用户
	if u := s.GetUserByAddr(context.Background(), netip.MustParseAddr("10.0.0.9")); u != nil {
		t.Fatalf("GetUserByAddr(10.0.0.9) = %v, want nil", u.Email)
	}
	if u := s.GetUser(context.Background(), "bob"); u == nil {
		t.Fatal("GetUser(bob) = nil")
	}
}

// 重叠的 allowed_ips 会让归属取决于 map 遍历顺序 —— 必须在加载期就拒绝。
func TestLoadUsersRejectsOverlap(t *testing.T) {
	for name, ips := range map[string][2][]string{
		"subnet-contains-host": {{"10.0.0.0/24"}, {"10.0.0.3/32"}},
		"identical":            {{"10.0.0.2/32"}, {"10.0.0.2/32"}},
		"default-catch-all":    {{"0.0.0.0/0"}, {"10.0.0.3/32"}},
		"v6-overlap":           {{"fd00::/64"}, {"fd00::3/128"}},
	} {
		t.Run(name, func(t *testing.T) {
			conf := &DeviceConfig{SecretKey: pubHex(1)}
			conf.Users = mustUsers(t,
				named("alice", peer(pubHex(2), ips[0]...)),
				named("bob", peer(pubHex(3), ips[1]...)),
			)
			if _, err := newTestServer(t, conf); err == nil {
				t.Fatal("expected overlap to be rejected, got nil error")
			}
		})
	}
}

// 非规范写法(10.0.0.5/24)几乎总是笔误,静默按 10.0.0.0/24 生效会吞掉整段。
func TestLoadUsersRejectsNonCanonicalPrefix(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	conf.Users = mustUsers(t, named("alice", peer(pubHex(2), "10.0.0.5/24")))
	if _, err := newTestServer(t, conf); err == nil {
		t.Fatal("expected non-canonical prefix to be rejected")
	}
}

// 纯旧配置(只有匿名 peers)必须原样工作:它本来就没有用户身份,
// 0.0.0.0/0 是合法且常见的,不能被本次改动判成非法。
func TestLoadUsersLegacyAnonymousPeersUnaffected(t *testing.T) {
	conf := &DeviceConfig{
		SecretKey: pubHex(1),
		Peers: []*PeerConfig{
			peer(pubHex(2), "0.0.0.0/0", "::/0"),
		},
	}
	s, err := newTestServer(t, conf)
	if err != nil {
		t.Fatalf("legacy config rejected: %v", err)
	}
	if got := s.GetUsersCount(context.Background()); got != 1 {
		t.Fatalf("GetUsersCount = %d, want 1", got)
	}
	if u := s.GetUserByAddr(context.Background(), netip.MustParseAddr("10.0.0.9")); u == nil || u.Email != "" {
		t.Fatalf("legacy peer should resolve anonymously, got %v", u)
	}
}

// 一旦有带 email 的用户,匿名的 0.0.0.0/0 peer 就会把它的流量抢走,必须拒绝混用。
func TestLoadUsersRejectsMixedAnonymousCatchAll(t *testing.T) {
	conf := &DeviceConfig{
		SecretKey: pubHex(1),
		Peers:     []*PeerConfig{peer(pubHex(4), "0.0.0.0/0", "::/0")},
	}
	conf.Users = mustUsers(t, named("alice", peer(pubHex(2), "10.0.0.2/32")))
	if _, err := newTestServer(t, conf); err == nil {
		t.Fatal("expected anonymous catch-all peer to be rejected alongside an emailed user")
	}
}

// 同一公钥重复出现会让 IPC 与内存表漂移,归属静默出错。
func TestLoadUsersRejectsDuplicatePublicKey(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	conf.Users = mustUsers(t,
		named("alice", peer(pubHex(2), "10.0.0.2/32")),
		named("bob", peer(pubHex(2), "10.0.0.3/32")),
	)
	if _, err := newTestServer(t, conf); err == nil {
		t.Fatal("expected duplicate public key to be rejected")
	}
}

// 初始 IPC 必须把每个用户都下发成 peer,否则用户握手直接失败。
func TestBuildIPCRequestCoversAllUsers(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	conf.Users = mustUsers(t,
		named("alice", peer(pubHex(2), "10.0.0.2/32")),
		named("bob", peer(pubHex(3), "10.0.0.3/32")),
	)
	s, err := newTestServer(t, conf)
	if err != nil {
		t.Fatalf("loadUsers: %v", err)
	}
	ipc := s.buildIPCRequest()
	for _, want := range []string{
		"private_key=" + pubHex(1),
		"listen_port=1337",
		"public_key=" + pubHex(2),
		"public_key=" + pubHex(3),
		"allowed_ip=10.0.0.2/32",
		"allowed_ip=10.0.0.3/32",
	} {
		if !strings.Contains(ipc, want) {
			t.Fatalf("ipc request missing %q:\n%s", want, ipc)
		}
	}
}

// ValidateDevicePeers 是 infra/conf Build 提前拦坏配置用的,它与 NewServer 的判定必须
// 完全一致:更严会让原本能跑的配置升级后起不来,更松则拦不住会让 NewServer 炸掉的配置。
func TestValidateDevicePeersAgreesWithLoadUsers(t *testing.T) {
	upper := strings.ToUpper("ab" + strings.Repeat("0", 62))
	lower := "ab" + strings.Repeat("0", 62)
	serverPub, err := serverPubKey(pubHex(1))
	if err != nil {
		t.Fatalf("serverPubKey: %v", err)
	}
	cases := []struct {
		name    string
		users   []*protocol.User
		peers   []*PeerConfig
		wantErr bool
	}{
		{
			name: "distinct-dual-stack-hosts",
			users: []*protocol.User{
				named("alice", peer(pubHex(2), "10.0.0.2/32", "fd00::2/128")),
				named("bob", peer(pubHex(3), "10.0.0.3/32", "fd00::3/128")),
			},
		},
		{
			// 主控的探测 peer / 中转 peer 形态:email + /32 + /128,IPAM 分配,互不重叠
			name: "probe-and-transit-shape",
			users: []*protocol.User{
				named("alice__wg-in", peer(pubHex(2), "10.66.0.2/32", "fd66::2/128")),
				named("__wgprobe__", peer(pubHex(3), "10.66.3.254/32", "fd66::3fe/128")),
				named("__wgtransit__1", peer(pubHex(4), "10.66.0.5/32")),
			},
		},
		{
			name:  "legacy-anonymous-catch-all",
			peers: []*PeerConfig{peer(pubHex(2), "0.0.0.0/0", "::0/0")},
		},
		{
			// 匿名 peer 与用户公钥相同:NewServer 按 LoadOrStore 静默丢掉它,
			// 丢掉之后才查重叠 —— 所以它的 0.0.0.0/0 不能让配置失败。
			name:  "anonymous-duplicate-of-user-is-dropped",
			users: []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.2/32"))},
			peers: []*PeerConfig{peer(pubHex(2), "0.0.0.0/0", "::0/0")},
		},
		{
			name:  "anonymous-duplicates-each-other",
			peers: []*PeerConfig{peer(pubHex(2), "0.0.0.0/0"), peer(pubHex(2), "0.0.0.0/0")},
		},
		{
			// NewServer 不查「peer 公钥 == 服务端公钥」(只有 AddUser 查),这里也不能查。
			name:  "peer-key-equals-server-public-key",
			users: []*protocol.User{named("alice", peer(hex.EncodeToString(serverPub[:]), "10.0.0.2/32"))},
		},
		{
			name:    "overlap",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.0/24")), named("bob", peer(pubHex(3), "10.0.0.3/32"))},
			wantErr: true,
		},
		{
			name:    "overlap-with-anonymous",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.2/32"))},
			peers:   []*PeerConfig{peer(pubHex(4), "0.0.0.0/0", "::0/0")},
			wantErr: true,
		},
		{
			name:    "non-canonical",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.5/24"))},
			wantErr: true,
		},
		{
			name:    "empty-allowed-ips",
			users:   []*protocol.User{named("alice", peer(pubHex(2)))},
			wantErr: true,
		},
		{
			name:    "duplicate-public-key",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.2/32")), named("bob", peer(pubHex(2), "10.0.0.3/32"))},
			wantErr: true,
		},
		{
			// 公钥比较的是解码后的字节:同一把 hex 公钥大小写不同也是同一个 peer。
			name:    "duplicate-public-key-hex-case",
			users:   []*protocol.User{named("alice", peer(upper, "10.0.0.2/32")), named("bob", peer(lower, "10.0.0.3/32"))},
			wantErr: true,
		},
		{
			name:    "duplicate-email",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.2/32")), named("alice", peer(pubHex(3), "10.0.0.3/32"))},
			wantErr: true,
		},
		{
			name:    "unparsable-allowed-ip",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.300/32"))},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf := &DeviceConfig{SecretKey: pubHex(1), Users: tc.users, Peers: tc.peers}
			validateErr := ValidateDevicePeers(conf.Users, conf.Peers)
			_, loadErr := newTestServer(t, conf)
			if (validateErr != nil) != (loadErr != nil) {
				t.Fatalf("ValidateDevicePeers err=%v but loadUsers err=%v: the two must agree", validateErr, loadErr)
			}
			if (validateErr != nil) != tc.wantErr {
				t.Fatalf("ValidateDevicePeers err=%v, wantErr=%v", validateErr, tc.wantErr)
			}
		})
	}
}

// fakeTun 只记录 IpcSet,供 AddUser/RemoveUser 测试用(newTestServer 不带 tun,
// AddUser 在 tun==nil 时直接返回 device not ready)。
type fakeTun struct {
	ipc []string
}

func (f *fakeTun) BuildDevice(string, conn.Bind) error { return nil }
func (f *fakeTun) IpcSet(uapi string) error {
	f.ipc = append(f.ipc, uapi)
	return nil
}

func (f *fakeTun) DialContextTCPAddrPort(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeTun) DialUDPAddrPort(netip.AddrPort, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeTun) Close() error { return nil }

func memUser(t *testing.T, email string, p *PeerConfig) *protocol.MemoryUser {
	t.Helper()
	mu, err := named(email, p).ToMemoryUser()
	if err != nil {
		t.Fatalf("ToMemoryUser: %v", err)
	}
	return mu
}

func newServerWithTun(t *testing.T, users ...*protocol.User) (*Server, *fakeTun) {
	t.Helper()
	s, err := newTestServer(t, &DeviceConfig{SecretKey: pubHex(1), Users: users})
	if err != nil {
		t.Fatalf("loadUsers: %v", err)
	}
	tun := &fakeTun{}
	s.tun = tun
	return s, tun
}

// 同一 email 再加一个 peer(换密钥时先加后删):RemoveUser(email) 之后只删得掉一个,
// 另一个继续以同一身份在线计费。必须拒绝,且不能已经把 peer 下发给设备。
func TestAddUserRejectsDuplicateEmail(t *testing.T) {
	ctx := context.Background()
	s, tun := newServerWithTun(t, named("alice", peer(pubHex(2), "10.0.0.2/32")))

	err := s.AddUser(ctx, memUser(t, "alice", peer(pubHex(3), "10.0.0.3/32")))
	if err == nil {
		t.Fatal("AddUser with an existing email must fail")
	}
	if len(tun.ipc) != 0 {
		t.Fatalf("rejected AddUser must not touch the device, got IpcSet %q", tun.ipc)
	}
	if got := s.GetUsersCount(ctx); got != 1 {
		t.Fatalf("GetUsersCount = %d, want 1", got)
	}
	if u := s.GetUser(ctx, "alice"); u == nil || u.Account.(*MemoryAccount).Pub[0] != 0x22 {
		t.Fatalf("alice must keep her original key, got %v", u)
	}

	// 其它 email 不受影响;匿名(空 email)peer 不参与 email 查重。
	if err := s.AddUser(ctx, memUser(t, "bob", peer(pubHex(4), "10.0.0.4/32"))); err != nil {
		t.Fatalf("AddUser(bob): %v", err)
	}
	if err := s.AddUser(ctx, memUser(t, "", peer(pubHex(5), "10.0.0.5/32"))); err != nil {
		t.Fatalf("AddUser(anonymous #1): %v", err)
	}
	if err := s.AddUser(ctx, memUser(t, "", peer(pubHex(6), "10.0.0.6/32"))); err != nil {
		t.Fatalf("AddUser(anonymous #2): %v", err)
	}
	if got := s.GetUsersCount(ctx); got != 4 {
		t.Fatalf("GetUsersCount = %d, want 4", got)
	}
}

// 换密钥的正确顺序是先 RemoveUser 再 AddUser:同 email、同地址、新公钥必须能加回去。
func TestRemoveThenAddRotatesKeyForSameEmail(t *testing.T) {
	ctx := context.Background()
	s, tun := newServerWithTun(t,
		named("alice", peer(pubHex(2), "10.0.0.2/32", "fd00::2/128")),
		named("bob", peer(pubHex(3), "10.0.0.3/32")),
	)

	if err := s.RemoveUser(ctx, "alice"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if err := s.AddUser(ctx, memUser(t, "alice", peer(pubHex(7), "10.0.0.2/32", "fd00::2/128"))); err != nil {
		t.Fatalf("AddUser after RemoveUser: %v", err)
	}
	u := s.GetUserByAddr(ctx, netip.MustParseAddr("10.0.0.2"))
	if u == nil || u.Email != "alice" || u.Account.(*MemoryAccount).Pub[0] != 0x77 {
		t.Fatalf("10.0.0.2 must resolve to alice with the new key, got %v", u)
	}
	if got := s.GetUsersCount(ctx); got != 2 {
		t.Fatalf("GetUsersCount = %d, want 2", got)
	}
	if len(tun.ipc) != 2 || !strings.Contains(tun.ipc[0], "remove=true") || !strings.Contains(tun.ipc[1], "public_key="+pubHex(7)) {
		t.Fatalf("unexpected IpcSet sequence: %q", tun.ipc)
	}
}

// AddUser 走的仍是同一套地址校验:与现有用户重叠必须拒绝。
func TestAddUserRejectsOverlap(t *testing.T) {
	ctx := context.Background()
	s, tun := newServerWithTun(t, named("alice", peer(pubHex(2), "10.0.0.2/32")))
	if err := s.AddUser(ctx, memUser(t, "bob", peer(pubHex(3), "10.0.0.0/24"))); err == nil {
		t.Fatal("expected overlap to be rejected")
	}
	if len(tun.ipc) != 0 {
		t.Fatalf("rejected AddUser must not touch the device, got IpcSet %q", tun.ipc)
	}
}
