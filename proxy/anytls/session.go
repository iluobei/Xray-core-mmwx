package anytls

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	sessionctx "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type session struct {
	isClient bool
	conn     stat.Connection
	br       *buf.BufferedReader
	bw       *buf.BufferedWriter
	fw       *frameWriter

	writeMu sync.Mutex

	streamsMu sync.Mutex
	streams   map[uint32]*stream

	peerVersion byte
	errCh       chan error
	closed      atomic.Bool
	seq         uint64

	server           *Server
	dispatcher       routing.Dispatcher
	handshakeDone    bool
	clientPaddingMD5 string
	// peerIsXrayClient 为 true 表示对端是 fork 自身的 anytls 客户端(settings 里 client=xray)。
	// 该客户端的 UDP 走非 spec 的 raw 透传;canonical 客户端(mihomo/sing-box)走 full-cone uot 路径。
	peerIsXrayClient bool

	client       *Client
	nextSID      atomic.Uint32
	pktCounter   atomic.Uint32
	settingsSent bool

	schemeMu      sync.RWMutex
	paddingScheme *paddingScheme

	synAckMu sync.Mutex
	synAckCh map[uint32]chan error

	activeStreams atomic.Int32
	idleSinceNano atomic.Int64
	inIdlePool    atomic.Bool
	dieHook       func()
}

// handlePSH 读完帧体写进流。readErr 是读会话连接失败,整条会话要结束;
// writeErr 是这条流写不进去了(帧体已读完),只影响这一条流。
func (s *session) handlePSH(ctx context.Context, st *stream, br *buf.BufferedReader, length int) (readErr, writeErr error) {
	if st == nil || st.link == nil {
		// 帧体没读,不能当成单流错误接着读(会错帧),按会话级错误处理。
		return errors.New("anytls: received PSH for unknown stream"), nil
	}
	body, err := readMultiBufferExact(br, length)
	if err != nil {
		buf.ReleaseMulti(body)
		return err, nil
	}
	if st.up != nil {
		// 服务端:入队就返回,由 writeUplink 去写(见其注释)。只有队列满了才在这里等。
		// 返回错误说明这条流已在别处结束(队列已中止)。
		return nil, st.up.push(body)
	}
	return nil, st.link.Writer.WriteMultiBuffer(body)
}

// accessLogCtx 给**这一条流**挂上访问日志,返回流内局部 ctx。
//
// anytls 是多路复用的:一条 TLS 连接上跑 N 条逻辑流,各有各的目标。所以绝不能改
// session 级的 ctx —— 那样所有流会共用同一条 AccessMessage,日志全串。
// 调用方必须把返回值当**局部变量**用,只传给这条流的 Dispatch。
//
// From 取 inbound.Source(与 shadowsocks 一致):它已经在 ctx 里,不必把 conn 传下来。
// 包名 session 被本包的 session 类型占了,所以用 sessionctx 别名(与 inbound.go 一致)。
func accessLogCtx(ctx context.Context, dest net.Destination) context.Context {
	inb := sessionctx.InboundFromContext(ctx)
	if inb == nil || !inb.Source.IsValid() {
		return ctx
	}
	email := ""
	if inb.User != nil {
		email = inb.User.Email
	}
	return xlog.ContextWithAccessMessage(ctx, &xlog.AccessMessage{
		From:   inb.Source,
		To:     dest,
		Status: xlog.AccessAccepted,
		Reason: "",
		Email:  email,
	})
}

// streamContext 给一条流派生它自己的 dispatch ctx:
//   - 独立可取消:dispatcher 对它注册 online-IP 的 RemoveIP,流结束时取消即实时清理(#731);
//   - 独立的 session.Outbound / Content(同 xray mux 服务端对每条子连接的做法):dispatcher 把这条流的
//     目标写进 Outbound,出站要到自己的 goroutine 里才去读。整条会话共用连接 ctx 里那一个的话,紧挨着
//     分发的两条流会互相覆盖,前一条被连到后一条的目标上。这本是老问题;上行改成异步入队后 readLoop
//     会一口气分发一串新流,UoT 流又在自己的 goroutine 里分发,就从偶发变成了常态。
func streamContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(sessionctx.SubContextFromMuxInbound(ctx))
}

// handleNewStream 处理一条新流的第一个 PSH 帧:帧体开头是目标地址,地址后面可以紧跟这条流的头一段数据。
//
// 协议允许客户端把目标地址和首包合在一帧发(参考实现 sing-anytls 是从流里读出地址、剩下的照常当数据)。
// 从前这里只从会话读缓冲里读出地址、不管帧长,同一帧里多出来的字节被当成下一帧的帧头去解析,整条会话错帧;
// sing-box / mihomo 的客户端恰好分帧发所以没暴露,Surge 把「地址 + UoT 请求 + 第一个 UDP 包」合在一帧,
// UDP 收不到任何回应(NAT 测试 Blocked)。现在按帧长整帧读出,地址之后的字节进这条流的上行队列。
func (s *session) handleNewStream(ctx context.Context, st *stream, br *buf.BufferedReader, length int) error {
	body, err := readMultiBufferExact(br, length)
	if err != nil {
		buf.ReleaseMulti(body)
		return err
	}
	frameData := make([]byte, body.Len())
	body, n := buf.SplitBytes(body, frameData)
	buf.ReleaseMulti(body)
	frameData = frameData[:n]
	rd := bytes.NewReader(frameData)
	addr, err := M.SocksaddrSerializer.ReadAddrPort(rd)
	if err != nil {
		return err
	}
	// rest 是同一帧里地址后面的数据(多数客户端分帧发,为空)
	rest := frameData[len(frameData)-rd.Len():]
	pushRest := func() {
		if len(rest) > 0 && st.up != nil {
			// 队列已中止(流在别处结束)时 push 自己释放,丢掉即可
			_ = st.up.push(buf.MergeBytes(nil, rest))
		}
	}
	dest := singbridge.ToDestination(addr, net.Network_TCP)
	if dest.Address == nil {
		return errors.New("anytls: invalid destination address in SYN")
	}

	// Check for UDP-over-TCP v2 magic domain in a new stream request.
	if strings.Contains(dest.Address.String(), "udp-over-tcp.arpa") {
		st.isUDP = true
		// canonical 客户端(非 fork xray):走 full-cone uot 路径 —— 后续 PSH 帧体全进这条流的上行队列,
		// 由 handleUDPStream 逐包解目标写进单条 freedom link。
		// fork 自身客户端仍走 raw 路径(handleFirstUDPFrame/handlePSH),行为不变。
		if !s.peerIsXrayClient {
			st.udpPipe = true
			st.up = newUplinkQueue()
			// dispatch ctx 在 readLoop 里建好、挂上 st.cancel,再交给 handleUDPStream 去 Dispatch:
			// 流在别处结束时 st.close 取消它,打断卡在等限速令牌上的写;handleUDPStream 不再回写 st 的字段,
			// 也就不会和会话关闭时的 st.close 并发读写。
			sctx, cancel := streamContext(ctx)
			st.cancel = cancel
			// 先起消费方再发 SYNACK:SYNACK 发送失败时 readLoop 并不退出,没人取的队列满了会把它永远卡住。
			go s.handleUDPStream(sctx, st)
			pushRest()
		} else if len(rest) > 0 {
			// fork 自身客户端的 raw 路径从下一帧读 UoT 请求,它也从不合帧发;真遇到了只能丢掉
			errors.LogWarning(ctx, "anytls: dropped ", len(rest), " bytes after UoT address in first frame, streamId=", st.sid)
		}
		if err := s.sendFrame(newFrame(cmdSYNACK, st.sid)); err != nil {
			errors.LogWarning(ctx, "anytls: UDP SYNACK send error, streamId=", st.sid, " err=", err)
			return err
		}
		return nil
	}

	// 每条流用独立可取消 ctx 去 Dispatch:dispatcher 会对该 ctx 注册 online-IP 的 RemoveIP,
	// 流结束时取消它即实时清理在线 IP,而不必等整个 anytls 会话(可能被连接池长期保活)关闭(#731)。
	sctx, cancel := streamContext(ctx)
	l, err := s.dispatcher.Dispatch(accessLogCtx(sctx, dest), dest)
	if err != nil {
		cancel()
		errors.LogWarning(ctx, "anytls: new stream dispatcher error, streamId=", st.sid, " err=", err)
		s.rejectStream(st.sid, err)
		return nil
	}
	st.cancel = cancel
	st.link = l
	// 同 UoT:写 goroutine 必须在发 SYNACK 之前起好。
	st.up = newUplinkQueue()
	go s.writeUplink(st)
	pushRest()

	if err := s.sendFrame(newFrame(cmdSYNACK, st.sid)); err != nil {
		errors.LogWarning(ctx, "anytls: new stream SYNACK send error, streamId=", st.sid, " err=", err)
		return err
	}

	go s.pumpDownlink(st.sid, l)
	return nil
}

func (s *session) handleFirstUDPFrame(ctx context.Context, st *stream, br *buf.BufferedReader) error {
	if st.link == nil {
		request, err := uot.ReadRequest(br)
		if err != nil {
			errors.LogWarning(ctx, "anytls: UDP failed to parse request:", err)
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
			s.finishStream(st.sid, nil)
			return nil
		}
		requestDest := singbridge.ToDestination(request.Destination, net.Network_UDP)

		sctx, cancel := streamContext(ctx)
		link, err := s.dispatcher.Dispatch(accessLogCtx(sctx, requestDest), requestDest)
		if err != nil {
			cancel()
			errors.LogWarning(ctx, "anytls: UDP dispatcher error, streamId=", st.sid, " err=", err)
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
			s.finishStream(st.sid, nil)
			return nil
		}

		st.cancel = cancel
		st.link = link
		st.udpTarget = &requestDest
		st.up = newUplinkQueue()
		go s.writeUplink(st)

		go s.pumpDownlink(st.sid, link)
		return nil
	}

	return nil
}

func (s *session) pumpDownlink(sid uint32, link *transport.Link) {
	defer func() {
		s.streamsMu.Lock()
		st := s.streams[sid]
		delete(s.streams, sid)
		s.streamsMu.Unlock()
		if st != nil {
			// 下行泵结束=该流关闭:st.close 取消其 dispatch ctx 触发 RemoveIP(#731)、
			// 关 link,并中止上行队列(目标都走了,还没写出去的上行没有意义)。
			st.close(nil)
		}
		if !s.isClosed() {
			_ = s.sendFrame(newFrame(cmdFIN, sid))
		}
	}()

	for {
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			break
		}

		if err := s.sendStreamData(sid, mb, 0); err != nil {
			return
		}
	}
}

// writeUplink 是服务端一条流(普通 TCP 流、fork 客户端的 raw UDP 流)的上行写 goroutine:
// 按序把 st.up 里的帧体写进 link.Writer。
//
// 从前这一步在 readLoop 里同步做。用户限速时同一用户上下行、所有连接共用一个令牌桶,下载把桶打成
// 负债后,上行哪怕几个字节的写也要排队等令牌,一等就是秒级 —— 整条会话的读循环跟着停住,新流的
// SYN / 首帧没人处理,SYNACK 发不出去,sing-anytls 客户端(mihomo / sing-box)开新流 3 秒等不到
// SYNACK 就关掉整条会话。现在限速和出站慢都只卡这一条流。
//
// 收尾:
//   - 客户端 FIN:readLoop 只 closeWrite,已入队的数据照常写完、拿到 io.EOF 后才在这里 finishStream
//     关 link —— FIN 不能抢在还没写出去的上行数据前面把它丢掉(从前同步写时 FIN 本就排在它们后面)。
//   - 写失败:只结束这一条流(同从前 handlePSH 的 writeErr),剩余缓冲由 st.close 中止队列时释放。
//   - 流在别处结束(下行结束 / 会话关闭):队列已中止,取队返回 ErrClosedPipe;流已不在 map 里,
//     这里的 finishStream 是空操作。
func (s *session) writeUplink(st *stream) {
	var werr error
	for {
		mb, err := st.up.ReadMultiBuffer()
		if err != nil {
			break
		}
		if werr = st.link.Writer.WriteMultiBuffer(mb); werr != nil {
			break
		}
	}
	s.finishStream(st.sid, werr)
}

func (s *session) isClosed() bool {
	return s.closed.Load()
}

func (s *session) close(err error) {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if err != nil {
		select {
		case s.errCh <- err:
		default:
		}
	}
	_ = s.conn.Close()

	s.streamsMu.Lock()
	streams := make([]*stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[uint32]*stream)
	s.streamsMu.Unlock()

	for _, st := range streams {
		st.close(err)
	}
	if s.dieHook != nil {
		s.dieHook()
	}
}

func (s *session) finishStream(sid uint32, err error) {
	s.streamsMu.Lock()
	st := s.streams[sid]
	if st != nil {
		delete(s.streams, sid)
	}
	s.streamsMu.Unlock()

	if st == nil {
		return
	}

	if s.client != nil {
		s.activeStreams.Add(-1)
	}
	st.close(err)
}

// rejectStream:新流分发被拒(限速的并发连接上限等)时告诉客户端,只结束这一条流,同参考实现
// HandshakeFailure 之后 Close:v2 对端先回带错误信息的 SYNACK,sing-anytls / mihomo 只关这条流
// (remote: ...);再发 FIN,不认 SYNACK 的 v1 对端靠它收流(带帧体的未知命令会读乱 v1 的帧)。
//
// 从前什么都不回、流也留在 map 里:客户端开新流后 3 秒等不到 SYNACK,把整条会话连同上面其它
// 在跑的流一起关掉;客户端不等 SYNACK 就发出的首包还会被当成新流地址解析,把会话的帧读乱。
// 错误详情只进本地日志:dispatcher 的错误文本带 email。
func (s *session) rejectStream(sid uint32, err error) {
	s.finishStream(sid, err)
	if s.peerVersion >= 2 {
		_ = s.sendFrame(&frame{cmd: cmdSYNACK, sid: sid, data: []byte("stream rejected")})
	}
	_ = s.sendFrame(newFrame(cmdFIN, sid))
}

func (s *session) sendFrame(f *frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.fw.writeFrame(f); err != nil {
		return err
	}
	return s.fw.flush()
}

func (s *session) sendStreamData(sid uint32, data buf.MultiBuffer, packetIndex uint32) error {
	defer buf.ReleaseMulti(data)
	for !data.IsEmpty() {
		var chunk buf.MultiBuffer
		data, chunk = buf.SplitSize(data, maxFramePayload)
		if packetIndex > 0 {
			b := buf.New()
			p := b.Extend(7)
			p[0] = cmdPSH
			binary.BigEndian.PutUint32(p[1:5], sid)
			binary.BigEndian.PutUint16(p[5:7], uint16(chunk.Len()))
			merge, _ := buf.MergeMulti(buf.MultiBuffer{b}, chunk)
			s.writeMu.Lock()
			if err := s.writePacketWithPadding(packetIndex, merge); err != nil {
				return err
			}
			s.writeMu.Unlock()
		} else {
			s.writeMu.Lock()
			err := s.fw.writeMultiBuffer(cmdPSH, sid, chunk)
			if err == nil {
				err = s.fw.flush()
			}
			s.writeMu.Unlock()
			if err != nil {
				buf.ReleaseMulti(data)
				return err
			}
		}

	}
	return nil
}

func (s *session) readLoop(ctx context.Context) error {
	var head [7]byte
	for {
		_, err := io.ReadFull(s.br, head[:])
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return err
		}

		cmd := head[0]
		sid := binary.BigEndian.Uint32(head[1:5])
		length := int(binary.BigEndian.Uint16(head[5:7]))
		//errors.LogDebug(ctx, "anytls: received frame cmd=", cmd, " streamId=", sid, " length=", length)
		switch cmd {
		case cmdWaste:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
		case cmdSettings:
			if s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected cmdSettings from server")
			}
			text, err := readText(s.br, length)
			if err != nil {
				return err
			}
			if s.handshakeDone {
				continue
			}
			if text != "" {
				lines := strings.Split(text, "\n")
				for _, line := range lines {
					if line == "" {
						continue
					}
					kv := strings.SplitN(line, "=", 2)
					if len(kv) != 2 {
						continue
					}
					switch kv[0] {
					case "v":
						if v, err := strconv.Atoi(kv[1]); err == nil {
							s.peerVersion = byte(v)
						}
					case "padding-md5":
						s.clientPaddingMD5 = strings.ToLower(kv[1])
					case "client":
						// fork 自身客户端标识,用于 UDP 分支(raw 透传 vs full-cone uot)。
						if kv[1] == "xray" {
							s.peerIsXrayClient = true
						}
					}
				}
			}
			if err := s.sendFrame(&frame{cmd: cmdServerSettings, sid: 0, data: []byte("v=2")}); err != nil {
				return err
			}
			if s.server != nil && s.server.paddingScheme != "" && s.clientPaddingMD5 != "" {
				sum := md5.Sum([]byte(s.server.paddingScheme))
				if strings.ToLower(hex.EncodeToString(sum[:])) != s.clientPaddingMD5 {
					if err := s.sendFrame(&frame{cmd: cmdUpdatePaddingScheme, sid: 0, data: []byte(s.server.paddingScheme)}); err != nil {
						return err
					}
				}
			}
			s.handshakeDone = true
		case cmdHeartRequest:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
			if err := s.sendFrame(newFrame(cmdHeartResponse, 0)); err != nil {
				return err
			}
		case cmdHeartResponse:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
		case cmdSYN:
			if s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected SYN from server")
			} else {
				if !s.handshakeDone {
					alert := newFrame(cmdAlert, 0)
					alert.data = []byte("client did not send its settings")
					_ = s.sendFrame(alert)
					return errors.New("anytls: client did not send its settings")
				}
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
					errors.LogWarning(ctx, "anytls: unexpected data in SYN, streamId=", sid)
					if err := s.sendFrame(&frame{cmd: cmdSYNACK, sid: sid, data: []byte("unexpected syn body")}); err != nil {
						return err
					}
					continue
				}
				s.streamsMu.Lock()
				if _, ok := s.streams[sid]; !ok {
					s.streams[sid] = &stream{sid: sid}
				}
				s.streamsMu.Unlock()
			}
		case cmdPSH:
			if length <= 0 {
				err := errors.New("anytls: PSH frame with empty payload, streamId=", sid)
				s.finishStream(sid, err)
				return err
			}
			s.streamsMu.Lock()
			st := s.streams[sid]
			s.streamsMu.Unlock()
			if st == nil || st.finRecv {
				// 流已经结束(FIN 过 / 被踢)后客户端还在路上的数据:丢掉这一帧接着读,同参考实现。
				// 从前这里 return nil 把整条会话拆了,同一会话上的其它流全部跟着断。
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
				continue
			} else if st.udpPipe {
				// canonical full-cone 路径:帧体进这条流的上行队列,由 handleUDPStream 解码。
				if err := s.feedUDPUplink(st, length); err != nil {
					return err
				}
				continue
			} else if st.isUDP && st.link == nil {
				if err := s.handleFirstUDPFrame(ctx, st, s.br); err != nil {
					return err
				}
				continue
			} else if st.link == nil {
				if err := s.handleNewStream(ctx, st, s.br, length); err != nil {
					return err
				}
				continue
			}
			readErr, writeErr := s.handlePSH(ctx, st, s.br, length)
			if readErr != nil {
				return readErr
			}
			if writeErr != nil {
				// 这条流的 link 已关(流结束 / 被限速踢掉),帧体已经读完:只结束这一条流,会话照常。
				s.finishStream(sid, writeErr)
			}
		case cmdFIN:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
			s.streamsMu.Lock()
			st := s.streams[sid]
			s.streamsMu.Unlock()
			if st != nil && st.up != nil {
				// 有上行队列的流:FIN 只表示不会再有新数据。已入队的先写完,由消费方(writeUplink /
				// handleUDPStream)取到 io.EOF 后自己 finishStream;在这里直接 finishStream 会把
				// 还没写出去的上行丢掉。
				if !st.finRecv {
					st.finRecv = true
					st.up.closeWrite()
				}
			} else {
				s.finishStream(sid, nil)
			}
		case cmdSYNACK:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected SYNACK from client")
			}
			s.synAckMu.Lock()
			ch := s.synAckCh[sid]
			s.synAckMu.Unlock()
			if length == 0 {
				if ch != nil {
					ch <- nil
				}
			} else {
				bodyText, err := readText(s.br, length)
				if err != nil {
					return err
				}
				errors.LogWarning(ctx, "anytls: stream handshake rejected, streamId=", sid, " err=", bodyText)
				s.finishStream(sid, errors.New(bodyText))
				if ch != nil {
					ch <- errors.New(bodyText)
				}
			}
		case cmdServerSettings:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected ServerSettings from client")
			}
			if length > 0 {
				bodyText, err := readText(s.br, length)
				if err != nil {
					return err
				}
				lines := strings.Split(bodyText, "\n")
				for _, line := range lines {
					kv := strings.SplitN(line, "=", 2)
					if len(kv) != 2 {
						continue
					}
					if kv[0] != "v" {
						continue
					}
					if v, err := strconv.Atoi(kv[1]); err == nil {
						s.peerVersion = byte(v)
					}
				}
			} else {
				errors.LogWarning(ctx, "anytls: empty ServerSettings from server")
			}
		case cmdUpdatePaddingScheme:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected UpdatePaddingScheme from client")
			}
			if length > 0 {
				bodyText, err := readText(s.br, length)
				if err != nil {
					return err
				}
				scheme, perr := parsePaddingScheme(bodyText)
				if perr == nil && scheme != nil {
					s.schemeMu.Lock()
					s.paddingScheme = scheme
					s.schemeMu.Unlock()
				}
			} else {
				errors.LogWarning(ctx, "anytls: empty UpdatePaddingScheme from server")
			}
		case cmdAlert:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected Alert from client")
			}
			var bodyText string
			if length > 0 {
				bodyText, err = readText(s.br, length)
				if err != nil {
					return err
				}
			}
			alertText := "anytls: server alert"
			if bodyText != "" {
				alertText += ": " + bodyText
			}
			return errors.New(alertText)
		default:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
			errors.LogWarning(ctx, "anytls: unknown cmd=", cmd, " streamId=", sid)
			return errors.New("anytls: unknown cmd")
		}
	}
}
