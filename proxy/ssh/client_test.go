package ssh

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
	gossh "golang.org/x/crypto/ssh"
)

// countingDialer 直接拨 TCP,记下拨了几次(验证共用一条 SSH 连接)。
type countingDialer struct {
	dials atomic.Int32
	conns []net.Conn
	mu    sync.Mutex
}

func (d *countingDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	d.dials.Add(1)
	c, err := net.Dial("tcp", dest.NetAddr())
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return c, nil
}
func (*countingDialer) DestIpAddress() net.IP                                  { return nil }
func (*countingDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

// killAll 断掉已经拨出去的 TCP 连接(模拟 SSH 连接掉线)。
func (d *countingDialer) killAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		_ = c.Close()
	}
	d.conns = nil
}

func sshOutbound(t *testing.T, ts *testServer, cfg *ClientConfig) *Client {
	t.Helper()
	host, port, _ := net.SplitHostPort(ts.addr)
	p, _ := xnet.PortFromString(port)
	cfg.Address = xnet.NewIPOrDomain(xnet.ParseAddress(host))
	cfg.Port = uint32(p)
	c, err := newClient(policy.DefaultManager{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// roundTrip 经 SSH 出站发一段数据到 target,读回同样长度(测试服务端的分发器是回显管道)。
func roundTrip(c *Client, dialer *countingDialer, network xnet.Network, target, msg string) (string, error) {
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	dest, _ := xnet.ParseDestination("tcp:" + target)
	dest.Network = network
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: dest}})
	errCh := make(chan error, 1)
	go func() { errCh <- c.Process(ctx, &transport.Link{Reader: upR, Writer: downW}, dialer) }()

	b := buf.New()
	b.WriteString(msg)
	if err := upW.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		return "", err
	}
	var got []byte
	deadline := time.After(5 * time.Second)
	for len(got) < len(msg) {
		type res struct {
			mb  buf.MultiBuffer
			err error
		}
		rc := make(chan res, 1)
		go func() { mb, err := downR.ReadMultiBuffer(); rc <- res{mb, err} }()
		select {
		case r := <-rc:
			if r.err != nil {
				return string(got), r.err
			}
			for _, x := range r.mb {
				got = append(got, x.Bytes()...)
			}
			buf.ReleaseMulti(r.mb)
		case err := <-errCh:
			return string(got), err
		case <-deadline:
			return string(got), io.ErrNoProgress
		}
	}
	upW.Close()
	return string(got), nil
}

func TestOutboundPasswordSharedConnection(t *testing.T) {
	ts := startServer(t, sshUser("a@t", "alice", "pw-a"))
	c := sshOutbound(t, ts, &ClientConfig{User: "alice", Password: "pw-a"})
	d := &countingDialer{}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := strings.Repeat("x", 100+i)
			if got, err := roundTrip(c, d, xnet.Network_TCP, "example.com:80", msg); err != nil || got != msg {
				t.Errorf("round trip %d: %q %v", i, got, err)
			}
		}(i)
	}
	wg.Wait()
	if n := d.dials.Load(); n != 1 {
		t.Fatalf("5 个并发请求应共用 1 条 SSH 连接,实际拨了 %d 次", n)
	}
	if call := ts.disp.last(); call.dest.NetAddr() != "example.com:80" || call.email != "a@t" {
		t.Fatalf("服务端收到的目标 / 用户不对:%+v", call)
	}
}

func TestOutboundHostKeyCheck(t *testing.T) {
	ts := startServer(t, sshUser("a@t", "alice", "pw-a"))
	good := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(ts.host)))
	c := sshOutbound(t, ts, &ClientConfig{User: "alice", Password: "pw-a", HostKey: []string{good}})
	if got, err := roundTrip(c, &countingDialer{}, xnet.Network_TCP, "1.2.3.4:443", "hi"); err != nil || got != "hi" {
		t.Fatalf("主机公钥对得上应能连:%q %v", got, err)
	}

	otherPub, _, _ := ed25519.GenerateKey(crand.Reader)
	other, _ := gossh.NewPublicKey(otherPub)
	bad := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(other)))
	c2 := sshOutbound(t, ts, &ClientConfig{User: "alice", Password: "pw-a", HostKey: []string{bad}})
	if _, err := roundTrip(c2, &countingDialer{}, xnet.Network_TCP, "1.2.3.4:443", "hi"); err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("主机公钥对不上必须拒绝:%v", err)
	}
}

func TestOutboundWrongPasswordRejected(t *testing.T) {
	ts := startServer(t, sshUser("a@t", "alice", "pw-a"))
	c := sshOutbound(t, ts, &ClientConfig{User: "alice", Password: "nope"})
	if _, err := roundTrip(c, &countingDialer{}, xnet.Network_TCP, "1.2.3.4:443", "hi"); err == nil {
		t.Fatal("密码错误必须失败")
	}
}

func TestOutboundPrivateKeyWithPassphrase(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(crand.Reader)
	sshPub, _ := gossh.NewPublicKey(pub)
	authLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPub)))
	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(block))
	ts := startServer(t, sshUser("k@t", "bob", "", authLine))

	c := sshOutbound(t, ts, &ClientConfig{User: "bob", PrivateKey: keyPEM, PrivateKeyPassphrase: "secret"})
	if got, err := roundTrip(c, &countingDialer{}, xnet.Network_TCP, "1.2.3.4:443", "key"); err != nil || got != "key" {
		t.Fatalf("私钥认证应能连:%q %v", got, err)
	}
	if _, err := newClient(policy.DefaultManager{}, &ClientConfig{
		Address: xnet.NewIPOrDomain(xnet.LocalHostIP), User: "bob", PrivateKey: keyPEM, PrivateKeyPassphrase: "wrong",
	}); err == nil {
		t.Fatal("私钥口令错误应在建出站时就报错")
	}
}

func TestOutboundReconnectAfterDrop(t *testing.T) {
	ts := startServer(t, sshUser("a@t", "alice", "pw-a"))
	c := sshOutbound(t, ts, &ClientConfig{User: "alice", Password: "pw-a"})
	d := &countingDialer{}
	if got, err := roundTrip(c, d, xnet.Network_TCP, "1.2.3.4:443", "one"); err != nil || got != "one" {
		t.Fatalf("first: %q %v", got, err)
	}
	d.killAll() // SSH 连接掉线
	var got string
	var err error
	for i := 0; i < 3; i++ { // 掉线可能要等 watch 摘掉连接;最多试几次
		if got, err = roundTrip(c, d, xnet.Network_TCP, "1.2.3.4:443", "two"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || got != "two" {
		t.Fatalf("掉线后应重连:%q %v", got, err)
	}
	if n := d.dials.Load(); n != 2 {
		t.Fatalf("应重拨 1 次,共 2 次,实际 %d", n)
	}
}

func TestOutboundUDPRejectedAndConfigErrors(t *testing.T) {
	ts := startServer(t, sshUser("a@t", "alice", "pw-a"))
	c := sshOutbound(t, ts, &ClientConfig{User: "alice", Password: "pw-a"})
	if _, err := roundTrip(c, &countingDialer{}, xnet.Network_UDP, "1.1.1.1:53", "q"); err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("UDP 应直接报不支持:%v", err)
	}
	addr := xnet.NewIPOrDomain(xnet.LocalHostIP)
	for name, cfg := range map[string]*ClientConfig{
		"无地址":     {Password: "x"},
		"无凭据":     {Address: addr},
		"坏主机公钥":   {Address: addr, Password: "x", HostKey: []string{"ssh-ed25519 not-base64"}},
		"坏版本串":    {Address: addr, Password: "x", ClientVersion: "OpenSSH_9"},
		"端口越界":    {Address: addr, Password: "x", Port: 70000},
		"私钥不是私钥": {Address: addr, PrivateKey: "hello"},
	} {
		if _, err := newClient(policy.DefaultManager{}, cfg); err == nil {
			t.Errorf("%s:应报错", name)
		}
	}
	c2, err := newClient(policy.DefaultManager{}, &ClientConfig{Address: addr, Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if c2.config.User != "root" || !strings.HasPrefix(c2.config.ClientVersion, "SSH-2.0-OpenSSH_") || c2.server.Port != 22 {
		t.Fatalf("默认值不对:user=%q version=%q port=%d", c2.config.User, c2.config.ClientVersion, c2.server.Port)
	}
}
