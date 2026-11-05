package anytls

import (
	"context"
	"encoding/binary"

	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport"
)

// feedUDPUplink 把一条 UoT 流的 PSH 帧体放进这条流的上行队列(由 handleUDPStream 解码)。
// 仅用于 canonical(mihomo/sing-box 等)客户端的 full-cone 路径;fork 自身客户端(client=xray)
// 仍走 handleFirstUDPFrame/handlePSH 的 raw 透传路径,不受影响。
//
// 从前这里是往 io.Pipe 里同步写,要等 handleUDPStream 读走;而它读走一个包就去写 link,被限速时
// 一等就是秒级,readLoop 跟着停住,同会话的其它流都卡在它后面。现在入队即返回,只有队列满了才等。
func (s *session) feedUDPUplink(st *stream, length int) error {
	body, err := readMultiBufferExact(s.br, length)
	if err != nil {
		buf.ReleaseMulti(body)
		return err
	}
	// 队列已中止(解码侧已结束、流正在关闭)时 push 释放帧体 —— 对会话非致命,丢弃即可。
	_ = st.up.push(body)
	return nil
}

// handleUDPStream 处理 canonical 客户端的一条 UDP-over-TCP(UoT v2)流,实现 full-cone:
// 从这条流的上行队列读 uot 请求 → dispatch 一条 freedom link → 逐包解目标、设 buf.UDP 后全写进
// 这条 link(freedom 用单一 UDP socket 出站 = endpoint-independent = full-cone);下行逐包封 UoT 帧回客户端。
//
// 权威 sing-box 是靠 uot.NewServerConn 逐包解目标 + 单 PacketConn 出站拿到 full-cone;fork 把 UoT
// 内嵌进 xray-core,这里用等价逻辑桥接到 xray 的 transport.Link(buf.UDP 即逐包目标)。
// 注意:逐包地址用 uot.AddrParser(IPv4 类型字节=0x00),不是 uot 请求头用的 M.SocksaddrSerializer(0x01)。
//
// ctx 是 handleNewStream 为这条流建的 dispatch ctx(其 cancel 已挂在 st.cancel 上)。
// 客户端 FIN 后队列取完返回 io.EOF,已入队的包都写出去了才收尾;流在别处结束时队列被中止,读队列立刻出错退出。
func (s *session) handleUDPStream(ctx context.Context, st *stream) {
	r := &buf.BufferedReader{Reader: st.up}
	request, err := uot.ReadRequest(r)
	if err != nil {
		buf.ReleaseMulti(r.Buffer)
		errors.LogWarning(ctx, "anytls: UoT read request error, streamId=", st.sid, " err=", err)
		s.finishStream(st.sid, nil)
		return
	}
	firstDest := singbridge.ToDestination(request.Destination, net.Network_UDP)

	// uot full-cone 只在这里 Dispatch 一次,之后逐包目标写进同一条 link ——
	// 所以访问日志只记得到首个目标。UDP 目标多为 IP 字面量,影响有限。
	link, err := s.dispatcher.Dispatch(accessLogCtx(ctx, firstDest), firstDest)
	if err != nil {
		buf.ReleaseMulti(r.Buffer)
		errors.LogWarning(ctx, "anytls: UDP dispatcher error, streamId=", st.sid, " err=", err)
		s.finishStream(st.sid, nil)
		// SYNACK 在拿到 uot 请求前就回过了,只能用 FIN 告诉客户端(同 raw 路径 handleFirstUDPFrame);
		// 否则客户端这条 UDP 一直往里发、收不到任何回应,直到它自己的空闲超时。
		_ = s.sendFrame(newFrame(cmdFIN, st.sid))
		return
	}
	st.uotConnected = request.IsConnect
	st.uotDest = firstDest
	// 流在别处结束(st.close 取消 ctx)时关掉 link.Writer:等令牌的 RateWriter 认 ctx 自己会退,
	// 出站 pipe 满时的等待要关 pipe 才解得开。link 不回写到 st 上,免得和会话关闭时的 st.close 竞争。
	context.AfterFunc(ctx, func() { common.Close(link.Writer) })

	defer func() {
		// BufferedReader 里可能还压着半帧没解析完的数据。
		buf.ReleaseMulti(r.Buffer)
		common.Close(link.Writer)
		common.Close(link.Reader)
		s.finishStream(st.sid, nil)
	}()

	go s.udpDownlink(st, link)

	// uplink:逐包解析(connected 用固定目标;not-connected 每包前缀带目标)→ 设 buf.UDP → 写进同一条 link。
	for {
		dest := firstDest
		if !request.IsConnect {
			addr, aerr := uot.AddrParser.ReadAddrPort(r)
			if aerr != nil {
				return
			}
			dest = singbridge.ToDestination(addr, net.Network_UDP)
		}
		var length uint16
		if berr := binary.Read(r, binary.BigEndian, &length); berr != nil {
			return
		}
		b := buf.New()
		if _, rerr := b.ReadFullFrom(r, int32(length)); rerr != nil {
			b.Release()
			return
		}
		d := dest
		b.UDP = &d
		if werr := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); werr != nil {
			return
		}
	}
}

// udpDownlink 从 freedom link 读回 UDP 包,逐包封成 UoT 帧发回客户端:
// not-connected 每包带源地址前缀 [src addr][uint16 len][payload];connected 只 [uint16 len][payload]。
func (s *session) udpDownlink(st *stream, link *transport.Link) {
	var sources udpSources
	for {
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return
		}
		for i, b := range mb {
			header := buf.New()
			if !st.uotConnected {
				src := st.uotDest
				if b.UDP != nil {
					src = *b.UDP
				}
				src, ok := sources.resolve(src)
				if !ok {
					// 域名解析不了:只丢这一个包,会话照常(同 snell)。
					header.Release()
					b.Release()
					continue
				}
				if werr := uot.AddrParser.WriteAddrPort(header, singbridge.ToSocksaddr(src)); werr != nil {
					header.Release()
					buf.ReleaseMulti(mb[i:])
					return
				}
			}
			binary.BigEndian.PutUint16(header.Extend(2), uint16(b.Len()))
			// sendStreamData 会 ReleaseMulti(header 与 b)。
			if serr := s.sendStreamData(st.sid, buf.MultiBuffer{header, b}, 0); serr != nil {
				buf.ReleaseMulti(mb[i+1:])
				return
			}
		}
	}
}

// udpSources 把回包的域名来源换成 IP。freedom 会把「会话第一个目标」的回包来源还原成当初拨号用的
// 地址,那个目标是域名时来源就是域名。UoT 虽然编得了域名,但 Surge 这类客户端按 IP 认来源,对不上
// 直接丢包 —— 以域名发 STUN 的 NAT 测试一个回应都收不到,显示 Blocked(#1677)。真实对端 IP 出站
// 没有交出来,只能再解析一次;每个域名只解析一次并记住(失败也记),同一条流里它的回包来源不会变来变去。
// 只在这条流的下行 goroutine 里用,不用加锁。
type udpSources struct {
	ips map[string]net.Address // nil = 解析失败
}

func (s *udpSources) resolve(source net.Destination) (net.Destination, bool) {
	if !source.Address.Family().IsDomain() {
		return source, true
	}
	domain := source.Address.Domain()
	ip, ok := s.ips[domain]
	if !ok {
		// freedom 不配 domainStrategy 时,拨号走的也是这个解析入口。
		if addr, err := net.ResolveUDPAddr("udp", source.NetAddr()); err == nil {
			ip = net.IPAddress(addr.IP)
		}
		if s.ips == nil {
			s.ips = make(map[string]net.Address)
		}
		s.ips[domain] = ip
	}
	if ip == nil {
		return source, false
	}
	source.Address = ip
	return source, true
}
