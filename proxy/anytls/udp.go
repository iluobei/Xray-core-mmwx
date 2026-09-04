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

// feedUDPUplink 把一条 UoT 流的 PSH 帧体喂进 per-stream pipe(由 handleUDPStream 解码)。
// 仅用于 canonical(mihomo/sing-box 等)客户端的 full-cone 路径;fork 自身客户端(client=xray)
// 仍走 handleFirstUDPFrame/handlePSH 的 raw 透传路径,不受影响。
func (s *session) feedUDPUplink(st *stream, length int) error {
	body, err := readMultiBufferExact(s.br, length)
	if err != nil {
		buf.ReleaseMulti(body)
		return err
	}
	defer buf.ReleaseMulti(body)
	if st.uplinkW == nil {
		return nil
	}
	for _, b := range body {
		if _, werr := st.uplinkW.Write(b.Bytes()); werr != nil {
			// 解码侧已结束(流正在关闭)——对会话非致命,丢弃即可。
			return nil
		}
	}
	return nil
}

// handleUDPStream 处理 canonical 客户端的一条 UDP-over-TCP(UoT v2)流,实现 full-cone:
// 从 per-stream pipe 读 uot 请求 → dispatch 一条 freedom link → 逐包解目标、设 buf.UDP 后全写进
// 这条 link(freedom 用单一 UDP socket 出站 = endpoint-independent = full-cone);下行逐包封 UoT 帧回客户端。
//
// 权威 sing-box 是靠 uot.NewServerConn 逐包解目标 + 单 PacketConn 出站拿到 full-cone;fork 把 UoT
// 内嵌进 xray-core,这里用等价逻辑桥接到 xray 的 transport.Link(buf.UDP 即逐包目标)。
// 注意:逐包地址用 uot.AddrParser(IPv4 类型字节=0x00),不是 uot 请求头用的 M.SocksaddrSerializer(0x01)。
func (s *session) handleUDPStream(ctx context.Context, st *stream) {
	request, err := uot.ReadRequest(st.uplinkR)
	if err != nil {
		errors.LogWarning(ctx, "anytls: UoT read request error, streamId=", st.sid, " err=", err)
		s.finishStream(st.sid, nil)
		return
	}
	firstDest := singbridge.ToDestination(request.Destination, net.Network_UDP)

	// uot full-cone 只在这里 Dispatch 一次,之后逐包目标写进同一条 link ——
	// 所以访问日志只记得到首个目标。UDP 目标多为 IP 字面量,影响有限。
	link, err := s.dispatcher.Dispatch(accessLogCtx(ctx, firstDest), firstDest)
	if err != nil {
		errors.LogWarning(ctx, "anytls: UDP dispatcher error, streamId=", st.sid, " err=", err)
		s.finishStream(st.sid, nil)
		return
	}
	st.link = link
	st.uotConnected = request.IsConnect
	st.uotDest = firstDest

	defer func() {
		common.Close(link.Writer)
		common.Close(link.Reader)
		s.finishStream(st.sid, nil)
	}()

	go s.udpDownlink(st, link)

	// uplink:逐包解析(connected 用固定目标;not-connected 每包前缀带目标)→ 设 buf.UDP → 写进同一条 link。
	for {
		dest := firstDest
		if !request.IsConnect {
			addr, aerr := uot.AddrParser.ReadAddrPort(st.uplinkR)
			if aerr != nil {
				return
			}
			dest = singbridge.ToDestination(addr, net.Network_UDP)
		}
		var length uint16
		if berr := binary.Read(st.uplinkR, binary.BigEndian, &length); berr != nil {
			return
		}
		b := buf.New()
		if _, rerr := b.ReadFullFrom(st.uplinkR, int32(length)); rerr != nil {
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
