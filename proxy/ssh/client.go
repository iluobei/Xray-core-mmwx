package ssh

// SSH 出站:连上一台 SSH 服务器,每个代理请求开一个 direct-tcpip 通道(与 `ssh -W` / mihomo 的 ssh 出站同一种用法)。
// 一个出站共用一条 SSH 连接:第一次有请求时按需拨号,连接断了(对端关闭、keepalive 没回应、开通道时发现坏了)
// 就丢掉,下一个请求重连。只支持 TCP —— SSH 协议本身没有 UDP 转发。
//
// 拨号走出站自己的 dialer,streamSettings / sockopt / proxySettings 照常生效。

import (
	"context"
	crand "crypto/rand"
	goerrors "errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	gossh "golang.org/x/crypto/ssh"
)

var (
	// clientHandshakeTimeout 建 SSH 连接(TCP 已通之后的版本交换 + 密钥交换 + 认证)的上限。
	clientHandshakeTimeout = 15 * time.Second
	// clientKeepaliveInterval / clientKeepaliveTimeout 共用连接的保活:隔这么久发一次 keepalive@openssh.com,
	// 这么久没回应就当连接已死,关掉让下一个请求重连(否则 NAT 掉线后要等 TCP 超时才发现)。
	clientKeepaliveInterval = 30 * time.Second
	clientKeepaliveTimeout  = 15 * time.Second
)

// clientVersions 没配 client_version 时从里面随机挑一个,看起来像常见发行版自带的 OpenSSH。
var clientVersions = []string{
	"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
	"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
	"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
	"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
	"SSH-2.0-OpenSSH_9.9",
}

// Client 是 SSH 出站处理器。
type Client struct {
	server        xnet.Destination
	config        *gossh.ClientConfig
	policyManager policy.Manager

	mu     sync.Mutex
	conn   *gossh.Client // 当前共用的 SSH 连接;断了置 nil
	closed bool
}

// NewClient 按配置建 SSH 出站。
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	v := core.MustFromContext(ctx)
	return newClient(v.GetFeature(policy.ManagerType()).(policy.Manager), config)
}

func newClient(pm policy.Manager, config *ClientConfig) (*Client, error) {
	if config.GetAddress() == nil {
		return nil, errors.New("ssh: server address not specified")
	}
	port := config.GetPort()
	if port == 0 {
		port = 22
	}
	if port > 65535 {
		return nil, errors.New("ssh: invalid server port ", port)
	}
	cc, err := buildClientConfig(config)
	if err != nil {
		return nil, err
	}
	return &Client{
		server:        xnet.TCPDestination(config.Address.AsAddress(), xnet.Port(port)),
		config:        cc,
		policyManager: pm,
	}, nil
}

func buildClientConfig(config *ClientConfig) (*gossh.ClientConfig, error) {
	user := strings.TrimSpace(config.GetUser())
	if user == "" {
		user = "root"
	}
	var auths []gossh.AuthMethod
	if key := strings.TrimSpace(config.GetPrivateKey()); key != "" {
		var signer gossh.Signer
		var err error
		if config.GetPrivateKeyPassphrase() != "" {
			signer, err = gossh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(config.GetPrivateKeyPassphrase()))
		} else {
			signer, err = gossh.ParsePrivateKey([]byte(key))
		}
		if err != nil {
			return nil, errors.New("ssh: invalid private key").Base(err)
		}
		auths = append(auths, gossh.PublicKeys(signer))
	}
	if pw := config.GetPassword(); pw != "" {
		// 不少服务器的密码登录走 keyboard-interactive(PAM),两种都给
		auths = append(auths, gossh.Password(pw), gossh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}))
	}
	if len(auths) == 0 {
		return nil, errors.New("ssh: neither password nor private key specified")
	}
	hostKey, err := hostKeyCallback(config.GetHostKey())
	if err != nil {
		return nil, err
	}
	version := strings.TrimSpace(config.GetClientVersion())
	if version == "" {
		version = randomClientVersion()
	} else if !strings.HasPrefix(version, "SSH-2.0-") {
		return nil, errors.New("ssh: client version must start with \"SSH-2.0-\": ", version)
	}
	cc := &gossh.ClientConfig{
		User:              user,
		Auth:              auths,
		HostKeyCallback:   hostKey,
		HostKeyAlgorithms: config.GetHostKeyAlgorithms(),
		ClientVersion:     version,
		Timeout:           clientHandshakeTimeout,
	}
	cc.Ciphers = config.GetCiphers()
	cc.MACs = config.GetMacs()
	cc.KeyExchanges = config.GetKexAlgorithms()
	return cc, nil
}

// hostKeyCallback 配了主机公钥就只认这些(authorized_keys 格式,按公钥本身比对);没配就接受任何主机公钥。
func hostKeyCallback(lines []string) (gossh.HostKeyCallback, error) {
	var allowed [][]byte
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, errors.New("ssh: invalid host key: ", line).Base(err)
		}
		allowed = append(allowed, pk.Marshal())
	}
	if len(allowed) == 0 {
		return gossh.InsecureIgnoreHostKey(), nil
	}
	return func(_ string, _ net.Addr, key gossh.PublicKey) error {
		got := key.Marshal()
		for _, k := range allowed {
			if string(k) == string(got) {
				return nil
			}
		}
		return errors.New("ssh: host key mismatch, server presented ", key.Type(), " ", gossh.FingerprintSHA256(key))
	}, nil
}

func randomClientVersion() string {
	n, err := crand.Int(crand.Reader, big.NewInt(int64(len(clientVersions))))
	if err != nil {
		return clientVersions[0]
	}
	return clientVersions[n.Int64()]
}

// getConn 取共用的 SSH 连接,没有就建一条。建连接时持锁:同时到达的请求等这一次握手,不各自再拨。
func (c *Client) getConn(ctx context.Context, dialer internet.Dialer) (*gossh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("ssh: outbound closed")
	}
	if c.conn != nil {
		return c.conn, nil
	}
	// 连接会比这个请求活得久:不能跟着请求的 ctx 一起取消(值照样带着,dialer 要用)
	raw, err := dialer.Dial(context.WithoutCancel(ctx), c.server)
	if err != nil {
		return nil, errors.New("failed to dial SSH server ", c.server.NetAddr()).Base(err)
	}
	_ = raw.SetDeadline(time.Now().Add(clientHandshakeTimeout))
	sconn, chans, reqs, err := gossh.NewClientConn(raw, c.server.NetAddr(), c.config)
	if err != nil {
		_ = raw.Close()
		return nil, errors.New("SSH handshake with ", c.server.NetAddr(), " failed").Base(err)
	}
	_ = raw.SetDeadline(time.Time{})
	cl := gossh.NewClient(sconn, chans, reqs)
	c.conn = cl
	errors.LogInfo(ctx, "ssh: connected to ", c.server.NetAddr(), " (", string(sconn.ServerVersion()), ")")
	go c.watch(cl)
	return cl, nil
}

// drop 把已经坏了的连接摘掉(只摘它自己:可能已经换成新连接了)。
func (c *Client) drop(cl *gossh.Client) {
	_ = cl.Close()
	c.mu.Lock()
	if c.conn == cl {
		c.conn = nil
	}
	c.mu.Unlock()
}

// watch 连接断开时摘掉它;定时 keepalive,没回应就主动关掉。
func (c *Client) watch(cl *gossh.Client) {
	done := make(chan struct{})
	go func() {
		_ = cl.Wait()
		close(done)
	}()
	t := time.NewTicker(clientKeepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			c.drop(cl)
			return
		case <-t.C:
			replied := make(chan error, 1)
			go func() {
				_, _, err := cl.SendRequest("keepalive@openssh.com", true, nil)
				replied <- err
			}()
			select {
			case err := <-replied:
				if err != nil {
					c.drop(cl)
					return
				}
			case <-done:
				c.drop(cl)
				return
			case <-time.After(clientKeepaliveTimeout):
				errors.LogInfo(context.Background(), "ssh: keepalive to ", c.server.NetAddr(), " timed out, reconnecting on next request")
				c.drop(cl)
				return
			}
		}
	}
}

// Close 关掉共用连接(出站被删除 / 替换时)。
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	cl := c.conn
	c.conn = nil
	c.mu.Unlock()
	if cl != nil {
		return cl.Close()
	}
	return nil
}

// openChannel 在共用连接上开一个到 target 的 direct-tcpip 通道。服务器拒绝(目标连不上、不让转发)直接报错;
// 连接本身坏了(还没被发现)就摘掉、重连再试一次。
func (c *Client) openChannel(ctx context.Context, dialer internet.Dialer, target string) (net.Conn, error) {
	for attempt := 0; ; attempt++ {
		cl, err := c.getConn(ctx, dialer)
		if err != nil {
			return nil, err
		}
		conn, err := cl.DialContext(ctx, "tcp", target)
		if err == nil {
			return conn, nil
		}
		var rejected *gossh.OpenChannelError
		if goerrors.As(err, &rejected) || ctx.Err() != nil || attempt > 0 {
			return nil, errors.New("SSH server ", c.server.NetAddr(), " failed to open ", target).Base(err)
		}
		c.drop(cl)
	}
}

// Process 实现 proxy.Outbound。
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "ssh"
	ob.CanSpliceCopy = 3
	target := ob.Target
	if target.Network == xnet.Network_UDP {
		return errors.New("UDP is not supported by SSH outbound")
	}

	conn, err := c.openChannel(ctx, dialer, target.NetAddr())
	if err != nil {
		return err
	}
	defer conn.Close()
	errors.LogInfo(ctx, "tunneling request to ", target, " via SSH ", c.server.NetAddr())

	p := c.policyManager.ForLevel(0)
	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, p.Timeouts.ConnectionIdle)

	requestDone := func() error {
		defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
		if err := buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer)); err != nil {
			return err
		}
		// 上行读完:半关通道,让对端知道这边不再发(direct-tcpip 通道支持 CloseWrite)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		return nil
	}
	responseDone := func() error {
		defer timer.SetTimeout(p.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}

	if newCtx != nil {
		ctx = newCtx
	}
	responseDonePost := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDonePost); err != nil {
		return errors.New("connection ends").Base(err)
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
