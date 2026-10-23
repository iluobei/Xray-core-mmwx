package snell

import (
	"bytes"
	"context"
	"net"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/shadowtls"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Client 是 Snell outbound。支持 v4/v5(CommandConnect/UDP + obfs)与 v6(三模式流量整形)。
type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	obfs          obfsConfig
	// shadowTLS 非空时拨通后先过 ShadowTLS v3 外壳(仅 v4/v5,与 obfs 互斥)。
	shadowTLS *shadowtls.ClientConfig

	// v6 专用
	version  uint32
	v6Mode   Mode
	clientID []byte
	profile  *Profile
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config == nil || config.Server == nil {
		return nil, errors.New("snell: no server specified")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("snell: parse server spec").Base(err)
	}
	if server.User == nil {
		return nil, errors.New("snell: no user specified")
	}
	account, ok := server.User.Account.(*MemoryAccount)
	if !ok {
		return nil, errors.New("snell: invalid account type")
	}
	vcore := core.MustFromContext(ctx)
	c := &Client{
		server:        server,
		policyManager: vcore.GetFeature(policy.ManagerType()).(policy.Manager),
		version:       account.Version,
		clientID:      account.ClientID,
	}
	if st := config.GetShadowTls(); st != nil {
		// 与入站同样的限制:v6 自带整形、obfs 本身就是另一层外壳,都不能再套 ShadowTLS。
		if account.Version == 6 {
			return nil, errors.New("snell: shadowTls only supports snell v4/v5")
		}
		if m, _ := parseObfsMode(account.ObfsMode); m != obfsModeNone {
			return nil, errors.New("snell: shadowTls cannot be combined with obfs ", account.ObfsMode)
		}
		if st.Password == "" || st.ServerName == "" {
			return nil, errors.New("snell: shadowTls password and serverName are required")
		}
		c.shadowTLS = &shadowtls.ClientConfig{Password: st.Password, ServerName: st.ServerName}
	}
	if account.Version == 6 {
		if len(account.PSK) < 12 || len(account.PSK) > 255 {
			return nil, errors.New("snell: v6 psk length must be 12..255 bytes")
		}
		mode, err := ParseMode(account.V6Mode)
		if err != nil {
			return nil, err
		}
		c.v6Mode = mode
		if mode == ModeDefault {
			c.profile = NewProfile(account.PSK)
		}
		return c, nil
	}
	mode, err := parseObfsMode(account.ObfsMode)
	if err != nil {
		return nil, err
	}
	c.obfs = obfsConfig{mode: mode, host: account.ObfsHost}
	return c, nil
}

// newRW 按版本建收发对(v6 无 obfs,shaped/unshaped/raw;v4/v5 obfs + record)。
func (c *Client) newRW(conn net.Conn, account *MemoryAccount) (snellWriter, snellReader, error) {
	if c.version == 6 {
		w, err := newV6Writer(conn, c.v6Mode, account.PSK, c.profile)
		if err != nil {
			return nil, nil, err
		}
		return w, newV6Reader(conn, c.v6Mode, account.PSK, c.profile), nil
	}
	oconn := c.obfs.clientConn(conn)
	return newRecordWriter(oconn, account.PSK), newRecordReader(oconn, account.PSK), nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("snell: target not specified")
	}
	ob.Name = "snell"
	ob.CanSpliceCopy = 3
	destination := ob.Target

	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, c.server.Destination)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return errors.New("snell: failed to dial server").Base(err)
	}
	defer conn.Close()

	account := c.server.User.Account.(*MemoryAccount)
	sessPolicy := c.policyManager.ForLevel(0)

	var inner net.Conn = conn
	if c.shadowTLS != nil {
		st, err := shadowtls.Client(ctx, conn, c.shadowTLS)
		if err != nil {
			return errors.New("snell: shadowtls").Base(err)
		}
		inner = st
	}

	writer, reader, err := c.newRW(inner, account)
	if err != nil {
		return errors.New("snell: setup").Base(err)
	}

	if destination.Network == xnet.Network_UDP {
		return c.handleUDP(ctx, link, reader, writer, destination, sessPolicy)
	}

	// 首个 record 写入握手请求(CommandConnect + clientID + 目标地址),后续 app 数据走普通 record。
	var reqBuf bytes.Buffer
	req := request{command: commandConnect, clientID: c.clientID, destination: destination}
	if err := req.writeTo(&reqBuf); err != nil {
		return errors.New("snell: build request").Base(err)
	}
	if _, err := writer.Write(reqBuf.Bytes()); err != nil {
		return errors.New("snell: write request").Base(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessPolicy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		if err := buf.Copy(link.Reader, buf.NewWriter(writer), buf.UpdateActivity(timer)); err != nil {
			return errors.New("snell: transport request").Base(err)
		}
		// 本地读结束 → 发 zero chunk 告知 server 客户端不再发送(半关闭语义)。
		if err := writer.writeZeroChunk(); err != nil {
			return errors.New("snell: write eof").Base(err)
		}
		return nil
	}
	responseDone := func() error {
		// 先读掉 server 回程首字节(ReplyTunnel/Error),其余才是应用数据。
		if err := readServerReply(reader); err != nil {
			return errors.New("snell: read reply").Base(err)
		}
		if err := buf.Copy(buf.NewReader(reader), link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("snell: transport response").Base(err)
		}
		return nil
	}

	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		return errors.New("snell: connection ends").Base(err)
	}
	return nil
}

// handleUDP 处理 UDP-over-TCP outbound:握手 CommandUDP,之后每个数据报独占一个 record。
// link.Reader 的每个 buffer 携带各自目标(b.UDP,全锥);响应 record = 地址|payload。
func (c *Client) handleUDP(ctx context.Context, link *transport.Link, reader snellReader, writer snellWriter, target xnet.Destination, sessPolicy policy.Session) error {
	// 握手:CommandUDP(clientID,无地址),各数据报再各自携带目标地址。
	var reqBuf bytes.Buffer
	if err := (request{command: commandUDP, clientID: c.clientID}).writeTo(&reqBuf); err != nil {
		return errors.New("snell: build udp request").Base(err)
	}
	if _, err := writer.Write(reqBuf.Bytes()); err != nil {
		return errors.New("snell: write udp request").Base(err)
	}
	packetWriter := &udpPacketWriter{writer: writer, response: false}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessPolicy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return nil
			}
			for _, b := range mb {
				if b.IsEmpty() {
					continue
				}
				dest := target
				if b.UDP != nil {
					dest = *b.UDP
				}
				if err := packetWriter.writePacket(b.Bytes(), dest); err != nil {
					buf.ReleaseMulti(mb)
					return errors.New("snell: write udp packet").Base(err)
				}
			}
			buf.ReleaseMulti(mb)
			timer.Update()
		}
	}
	responseDone := func() error {
		if err := readServerReply(reader); err != nil {
			return errors.New("snell: read udp reply").Base(err)
		}
		for {
			record, err := reader.nextRecord()
			if err != nil {
				return nil
			}
			source, payload, err := readUDPResponseAddress(record)
			if err != nil {
				return errors.New("snell: parse udp response").Base(err)
			}
			b := buf.New()
			if _, err := b.Write(payload); err != nil {
				b.Release()
				return err
			}
			src := source
			b.UDP = &src
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				return errors.New("snell: write udp to link").Base(err)
			}
			timer.Update()
		}
	}

	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		return errors.New("snell: udp connection ends").Base(err)
	}
	return nil
}
