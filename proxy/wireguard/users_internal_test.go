package wireguard

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
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
