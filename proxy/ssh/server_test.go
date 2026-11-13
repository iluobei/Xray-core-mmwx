package ssh

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	gossh "golang.org/x/crypto/ssh"
)

// recordingDispatcher 记下每次 Dispatch 的目标与入站身份,返回一根回显管道(写进去什么就读回什么)。
type recordingDispatcher struct {
	mu    sync.Mutex
	calls []dispatchCall
	fail  bool
}

type dispatchCall struct {
	dest   xnet.Destination
	email  string
	source string
	name   string
}

func (*recordingDispatcher) Type() interface{} { return nil }
func (*recordingDispatcher) Start() error      { return nil }
func (*recordingDispatcher) Close() error      { return nil }
func (*recordingDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return nil
}

func (d *recordingDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	inb := session.InboundFromContext(ctx)
	call := dispatchCall{dest: dest, name: inb.Name, source: inb.Source.Address.String()}
	if inb.User != nil {
		call.email = inb.User.Email
	}
	d.mu.Lock()
	d.calls = append(d.calls, call)
	fail := d.fail
	d.mu.Unlock()
	if fail {
		return nil, errors.New("connection limit reached")
	}
	r, w := pipe.New(pipe.WithoutSizeLimit())
	return &transport.Link{Reader: r, Writer: w}, nil
}

func (d *recordingDispatcher) last() dispatchCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls[len(d.calls)-1]
}

func testHostKey(t *testing.T) (string, gossh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), signer.PublicKey()
}

func sshUser(email, username, password string, keys ...string) *protocol.User {
	return &protocol.User{
		Email:   email,
		Account: serial.ToTypedMessage(&Account{Username: username, Password: password, AuthorizedKeys: keys}),
	}
}

func memUser(t *testing.T, u *protocol.User) *protocol.MemoryUser {
	t.Helper()
	mu, err := u.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	return mu
}

type testServer struct {
	srv  *Server
	addr string
	disp *recordingDispatcher
	host gossh.PublicKey
}

func startServer(t *testing.T, users ...*protocol.User) *testServer {
	t.Helper()
	oldStep, oldMax := guardDelayStep, guardDelayMax
	guardDelayStep, guardDelayMax = 0, 0
	t.Cleanup(func() { guardDelayStep, guardDelayMax = oldStep, oldMax })

	hostPEM, hostPub := testHostKey(t)
	srv, err := newServer(policy.DefaultManager{}, &ServerConfig{Users: users, HostKey: hostPEM})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	disp := &recordingDispatcher{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				ictx := session.ContextWithInbound(ctx, &session.Inbound{
					Source: xnet.DestinationFromAddr(c.RemoteAddr()),
					Tag:    "ssh-in",
					Conn:   c,
				})
				_ = srv.Process(ictx, xnet.Network_TCP, c, disp)
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = srv.Close()
	})
	return &testServer{srv: srv, addr: ln.Addr().String(), disp: disp, host: hostPub}
}

func (ts *testServer) dial(t *testing.T, user string, auth ...gossh.AuthMethod) (*gossh.Client, error) {
	t.Helper()
	return gossh.Dial("tcp", ts.addr, &gossh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: gossh.FixedHostKey(ts.host),
		ClientVersion:   "SSH-2.0-OpenSSH_8.4",
		Timeout:         5 * time.Second,
	})
}

func echoOnce(t *testing.T, client *gossh.Client, target, msg string) {
	t.Helper()
	c, err := client.Dial("tcp", target)
	if err != nil {
		t.Fatalf("dial %s through ssh: %v", target, err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

// waitClosed 等客户端连接被服务端断开。
func waitClosed(t *testing.T, client *gossh.Client) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = client.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection was not closed by server")
	}
}

func TestPasswordAuthDirectTCPIPPerUser(t *testing.T) {
	ts := startServer(t,
		sshUser("alice@x", "alice", "pa"),
		sshUser("bob@x", "bob", "pb"))

	alice, err := ts.dial(t, "alice", gossh.Password("pa"))
	if err != nil {
		t.Fatalf("alice auth: %v", err)
	}
	defer alice.Close()
	if v := string(alice.ServerVersion()); v != defaultServerVersion {
		t.Fatalf("server version = %q", v)
	}
	echoOnce(t, alice, "example.com:80", "hello")
	call := ts.disp.last()
	if call.email != "alice@x" || call.dest.String() != "tcp:example.com:80" || call.source != "127.0.0.1" || call.name != "ssh" {
		t.Fatalf("unexpected dispatch: %+v", call)
	}
	echoOnce(t, alice, "1.1.1.1:443", "again")
	if call := ts.disp.last(); call.email != "alice@x" || call.dest.String() != "tcp:1.1.1.1:443" {
		t.Fatalf("unexpected dispatch: %+v", call)
	}

	bob, err := ts.dial(t, "bob", gossh.Password("pb"))
	if err != nil {
		t.Fatalf("bob auth: %v", err)
	}
	defer bob.Close()
	echoOnce(t, bob, "example.org:8080", "bob")
	if call := ts.disp.last(); call.email != "bob@x" {
		t.Fatalf("bob attributed to %q", call.email)
	}
}

func TestWrongCredentialsRejected(t *testing.T) {
	ts := startServer(t, sshUser("alice@x", "alice", "pa"), sshUser("bob@x", "bob", "pb"))
	if c, err := ts.dial(t, "alice", gossh.Password("wrong")); err == nil {
		c.Close()
		t.Fatal("wrong password accepted")
	}
	// 别人的密码配自己的用户名也不行
	if c, err := ts.dial(t, "alice", gossh.Password("pb")); err == nil {
		c.Close()
		t.Fatal("cross-user password accepted")
	}
	if c, err := ts.dial(t, "nobody", gossh.Password("pa")); err == nil {
		c.Close()
		t.Fatal("unknown user accepted")
	}
}

func TestOnlyDirectTCPIPAllowed(t *testing.T) {
	ts := startServer(t, sshUser("alice@x", "alice", "pa"))
	client, err := ts.dial(t, "alice", gossh.Password("pa"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if s, err := client.NewSession(); err == nil {
		// 万一 session 被接受了,再确认 shell / exec 也执行不了
		_ = s.Close()
		t.Fatal("session channel accepted")
	}
	for _, typ := range []string{"session", "x11", "forwarded-tcpip", "direct-streamlocal@openssh.com", "auth-agent@openssh.com"} {
		if ch, _, err := client.OpenChannel(typ, nil); err == nil {
			ch.Close()
			t.Fatalf("channel %s accepted", typ)
		} else {
			var oce *gossh.OpenChannelError
			if !errors.As(err, &oce) || oce.Reason != gossh.Prohibited {
				t.Fatalf("channel %s: unexpected error %v", typ, err)
			}
		}
	}
	// 远端端口转发(tcpip-forward 全局请求)
	if ln, err := client.Listen("tcp", "0.0.0.0:0"); err == nil {
		ln.Close()
		t.Fatal("tcpip-forward accepted")
	}
	if ok, _, _ := client.SendRequest("streamlocal-forward@openssh.com", true, gossh.Marshal(struct{ P string }{"/tmp/x.sock"})); ok {
		t.Fatal("streamlocal-forward accepted")
	}
	// 拒完之后连接照常可用
	echoOnce(t, client, "example.com:80", "still-ok")
}

func TestPublicKeyAuth(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(crand.Reader)
	signer, _ := gossh.NewSignerFromKey(priv)
	authLine := string(gossh.MarshalAuthorizedKey(signer.PublicKey()))
	_, otherPriv, _ := ed25519.GenerateKey(crand.Reader)
	other, _ := gossh.NewSignerFromKey(otherPriv)

	ts := startServer(t, sshUser("carol@x", "carol", "", authLine), sshUser("dave@x", "dave", "pd"))
	client, err := ts.dial(t, "carol", gossh.PublicKeys(signer))
	if err != nil {
		t.Fatalf("carol pubkey auth: %v", err)
	}
	defer client.Close()
	echoOnce(t, client, "example.com:80", "key")
	if call := ts.disp.last(); call.email != "carol@x" {
		t.Fatalf("attributed to %q", call.email)
	}
	if c, err := ts.dial(t, "carol", gossh.PublicKeys(other)); err == nil {
		c.Close()
		t.Fatal("unknown key accepted")
	}
	// carol 的 key 配 dave 的用户名不行;carol 没有密码,任何密码都不行
	if c, err := ts.dial(t, "dave", gossh.PublicKeys(signer)); err == nil {
		c.Close()
		t.Fatal("key accepted for another user")
	}
	if c, err := ts.dial(t, "carol", gossh.Password("")); err == nil {
		c.Close()
		t.Fatal("empty password accepted for key-only user")
	}
}

// 同用户名、不同公钥的两个用户:身份按「最终通过的那把 key」定,不能串号。
// (身份放在 Permissions 里,而不是回调里写闭包变量 —— publickey 回调结果按 (user,key) 缓存,
// 最终成功的那次认证未必会再调一次回调。)
func TestPublicKeyIdentityPerKey(t *testing.T) {
	_, privA, _ := ed25519.GenerateKey(crand.Reader)
	sA, _ := gossh.NewSignerFromKey(privA)
	_, privB, _ := ed25519.GenerateKey(crand.Reader)
	sB, _ := gossh.NewSignerFromKey(privB)
	ts := startServer(t,
		sshUser("a@x", "same", "", string(gossh.MarshalAuthorizedKey(sA.PublicKey()))),
		sshUser("b@x", "same", "", string(gossh.MarshalAuthorizedKey(sB.PublicKey()))))
	for _, tc := range []struct {
		signer gossh.Signer
		email  string
	}{{sB, "b@x"}, {sA, "a@x"}} {
		client, err := ts.dial(t, "same", gossh.PublicKeys(tc.signer))
		if err != nil {
			t.Fatalf("auth: %v", err)
		}
		echoOnce(t, client, "example.com:80", "id")
		if call := ts.disp.last(); call.email != tc.email {
			t.Fatalf("identity confused: attributed to %q, want %s", call.email, tc.email)
		}
		client.Close()
	}
}

func TestRemoveUserKicksLiveConnection(t *testing.T) {
	ts := startServer(t, sshUser("alice@x", "alice", "pa"), sshUser("bob@x", "bob", "pb"))
	alice, err := ts.dial(t, "alice", gossh.Password("pa"))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Close()
	bob, err := ts.dial(t, "bob", gossh.Password("pb"))
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Close()
	echoOnce(t, alice, "example.com:80", "a")

	if err := ts.srv.RemoveUser(context.Background(), "ALICE@x"); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, alice)
	if c, err := ts.dial(t, "alice", gossh.Password("pa")); err == nil {
		c.Close()
		t.Fatal("removed user can still authenticate")
	}
	// bob 不受影响
	echoOnce(t, bob, "example.com:80", "b")

	// 再加回来(换了密码):旧密码不行,新密码可以
	if err := ts.srv.AddUser(context.Background(), memUser(t, sshUser("alice@x", "alice", "pa2"))); err != nil {
		t.Fatal(err)
	}
	if c, err := ts.dial(t, "alice", gossh.Password("pa")); err == nil {
		c.Close()
		t.Fatal("old password accepted after reset")
	}
	alice2, err := ts.dial(t, "alice", gossh.Password("pa2"))
	if err != nil {
		t.Fatal(err)
	}
	defer alice2.Close()
	echoOnce(t, alice2, "example.com:80", "a2")
}

// 用户表被换掉但没走 RemoveUser(例如别的代码路径直接替换):新 channel 必须被拒,整条连接断开。
func TestNewChannelRechecksUser(t *testing.T) {
	ts := startServer(t, sshUser("alice@x", "alice", "pa"), sshUser("bob@x", "bob", "pb"))
	alice, err := ts.dial(t, "alice", gossh.Password("pa"))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Close()
	echoOnce(t, alice, "example.com:80", "a")

	// 同 email 换了密码 = 凭据已变
	ts.srv.userMu.Lock()
	ts.srv.users = []*protocol.MemoryUser{memUser(t, sshUser("alice@x", "alice", "changed")), ts.srv.users[1]}
	ts.srv.userMu.Unlock()

	if c, err := alice.Dial("tcp", "example.com:80"); err == nil {
		c.Close()
		t.Fatal("new channel accepted for stale credentials")
	}
	waitClosed(t, alice)
}

func TestCloseKicksAllAndRejectsNew(t *testing.T) {
	ts := startServer(t, sshUser("alice@x", "alice", "pa"), sshUser("bob@x", "bob", "pb"))
	alice, err := ts.dial(t, "alice", gossh.Password("pa"))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Close()
	bob, err := ts.dial(t, "bob", gossh.Password("pb"))
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Close()

	// 挂一条正在用的 channel,确认它也跟着断
	c, err := alice.Dial("tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_ = ts.srv.Close()
	waitClosed(t, alice)
	waitClosed(t, bob)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("channel still alive after Close")
	}
	if cl, err := ts.dial(t, "alice", gossh.Password("pa")); err == nil {
		cl.Close()
		t.Fatal("new connection accepted after Close")
	}
}

func TestDispatchFailureRejectsChannelOnly(t *testing.T) {
	ts := startServer(t, sshUser("alice@x", "alice", "pa"))
	client, err := ts.dial(t, "alice", gossh.Password("pa"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ts.disp.mu.Lock()
	ts.disp.fail = true
	ts.disp.mu.Unlock()
	if c, err := client.Dial("tcp", "example.com:80"); err == nil {
		c.Close()
		t.Fatal("channel accepted although dispatch failed")
	} else if !strings.Contains(err.Error(), "connect failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	ts.disp.mu.Lock()
	ts.disp.fail = false
	ts.disp.mu.Unlock()
	echoOnce(t, client, "example.com:80", "recovered")
}

func TestBruteForceBansIP(t *testing.T) {
	ts := startServer(t, sshUser("alice@x", "alice", "pa"))
	// 每条连接最多试 MaxAuthTries 次;攒够阈值之后该 IP 被封
	for i := 0; i < guardThreshold; i++ {
		if c, err := ts.dial(t, "alice", gossh.Password("bad")); err == nil {
			c.Close()
			t.Fatal("bad password accepted")
		}
		if !ts.srv.guard.allowed("127.0.0.1") {
			break
		}
	}
	if ts.srv.guard.allowed("127.0.0.1") {
		t.Fatal("ip not banned after repeated failures")
	}
	// 封禁期内连正确密码也进不来(握手前就被关掉)
	if c, err := ts.dial(t, "alice", gossh.Password("pa")); err == nil {
		c.Close()
		t.Fatal("banned ip could connect")
	}
}

func TestAuthGuardPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := newAuthGuard()
	g.now = func() time.Time { return now }

	for i := 0; i < guardThreshold-1; i++ {
		if _, b := g.fail("203.0.113.1"); b != 0 {
			t.Fatalf("banned too early at %d", i)
		}
	}
	_, b := g.fail("203.0.113.1")
	if b != guardBanBase || g.allowed("203.0.113.1") {
		t.Fatalf("expected first ban %v, got %v", guardBanBase, b)
	}
	now = now.Add(guardBanBase + time.Second)
	if !g.allowed("203.0.113.1") {
		t.Fatal("ban did not expire")
	}
	for i := 0; i < guardThreshold-1; i++ {
		g.fail("203.0.113.1")
	}
	if _, b := g.fail("203.0.113.1"); b != 2*guardBanBase {
		t.Fatalf("second ban should double, got %v", b)
	}

	// 最近成功过的 IP 不封
	g.success("198.51.100.7")
	for i := 0; i < 5*guardThreshold; i++ {
		if _, b := g.fail("198.51.100.7"); b != 0 {
			t.Fatal("trusted ip got banned")
		}
	}
	if !g.allowed("198.51.100.7") {
		t.Fatal("trusted ip not allowed")
	}

	// 失败窗口过期后重新计数
	for i := 0; i < guardThreshold-1; i++ {
		g.fail("192.0.2.9")
	}
	now = now.Add(guardWindow + time.Second)
	if _, b := g.fail("192.0.2.9"); b != 0 {
		t.Fatal("stale failures counted")
	}
}

func TestZeroUsersAndConfigValidation(t *testing.T) {
	if _, err := newServer(policy.DefaultManager{}, &ServerConfig{}); err != nil {
		t.Fatalf("zero users should be allowed (rejects everyone): %v", err)
	}
	if _, err := newServer(policy.DefaultManager{}, &ServerConfig{HostKey: "garbage"}); err == nil {
		t.Fatal("bad host key accepted")
	}
	if _, err := newServer(policy.DefaultManager{}, &ServerConfig{ServerVersion: "OpenSSH"}); err == nil {
		t.Fatal("bad version accepted")
	}
	if _, err := (&Account{Username: "u"}).AsAccount(); err == nil {
		t.Fatal("account without password and key accepted")
	}
}
