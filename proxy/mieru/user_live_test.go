// user_live_test.go:证明 per-user 热更新期间,该入站上**已经建立的连接不会断**。
//
// user_test.go 里的用例只证明了「用户表改完之后,新的握手按新表判定」;它们从头到尾
// 没有一条活着的连接。而 UserManager 存在的全部意义正是「改用户表时不碰在用连接」——
// 这里补的就是这一步:真的起一个 mieru server(Process + dispatcher),挂一条持续
// 双向收发的会话,并发地反复 AddUser / RemoveUser,断言那条流全程没断、序号连续。
//
// mieru 没有独立的 client 实现(线上是 mihomo/官方客户端在连),所以客户端按
// docs/protocol.md 在进程内现搭:nonce(末 4 字节带 userTag)→ openSessionRequest
// 携 socks5 CONNECT → 读 openSessionResponse + socks5 成功回复 → 之后收发 data 段。
package mieru

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// echoDispatcher 每次 Dispatch 返回一根新管道的两端。server 把客户端数据写进
// link.Writer、又从 link.Reader 读回程 —— 同一根管道即回显,于是「客户端发什么、
// 收回什么」可以逐字节核对,不必真的去连一个外部落地。
type echoDispatcher struct{}

func (echoDispatcher) Type() interface{} { return nil }
func (echoDispatcher) Start() error      { return nil }
func (echoDispatcher) Close() error      { return nil }

func (echoDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	r, w := pipe.New(pipe.WithoutSizeLimit())
	return &transport.Link{Reader: r, Writer: w}, nil
}

func (echoDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return nil
}

// startMieruServer 在本机随机端口上真的跑起这个 Server(走 Process,不是直接调 resolveUser)。
func startMieruServer(t *testing.T, srv *Server) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
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
				})
				_ = srv.Process(ictx, xnet.Network_TCP, c, echoDispatcher{})
			}()
		}
	}()
	return ln.Addr().String(), func() {
		cancel()
		_ = ln.Close()
	}
}

// socks5ConnectRequest 是会话内承载的 socks5 CONNECT 请求(目标 1.2.3.4:443)。
var socks5ConnectRequest = []byte{
	socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv4,
	1, 2, 3, 4,
	0x01, 0xbb,
}

// mieruStream 是一条建好的 mieru 客户端会话(已收到 openSessionResponse + socks5 成功回复)。
type mieruStream struct {
	conn    net.Conn
	sw      *segmentWriter
	sr      *segmentReader
	sid     uint32
	seq     uint32
	pending []byte
}

func (m *mieruStream) Close() { _ = m.conn.Close() }

// Write 把一段应用数据封成一个 dataClientToServer 段发出(满足 io.Writer,供 liveStream 用)。
func (m *mieruStream) Write(p []byte) (int, error) {
	m.seq++
	meta := dataMeta{
		protocolType: protoDataClientToServer,
		sessionID:    m.sid,
		seq:          m.seq,
		window:       defaultWindow,
		payloadLen:   uint16(len(p)),
	}.encode()
	if err := m.sw.write(meta, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read 读下一个 dataServerToClient 段的 payload。收到关闭段即 EOF —— 这正是
// 「连接断了」在客户端侧的样子,测试要能看见它。
func (m *mieruStream) Read(p []byte) (int, error) {
	for len(m.pending) == 0 {
		seg, err := m.sr.read()
		if err != nil {
			return 0, err
		}
		switch seg.protocolType {
		case protoCloseSessionRequest, protoCloseSessionResponse:
			return 0, io.EOF
		case protoDataServerToClient:
			m.pending = seg.payload
		default: // ack 等,忽略
		}
	}
	n := copy(p, m.pending)
	m.pending = m.pending[n:]
	return n, nil
}

// dialMieru 完整走一遍客户端流程,返回一条可收发的会话。
func dialMieru(addr, username, password string) (*mieruStream, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	// 握手期给个上限,免得服务端拒绝时客户端挂死(删掉的用户必然走到这条路)。
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	key, err := deriveKey(hashPassword(username, password), timeSalt(roundedUnixTime(time.Now().Unix())))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := crand.Read(nonce); err != nil {
		_ = conn.Close()
		return nil, err
	}
	applyUserTag(nonce, username)

	sw := newSegmentWriter(conn, aead, nonce)
	meta := sessionMeta{
		protocolType: protoOpenSessionRequest,
		sessionID:    1,
		seq:          0,
		payloadLen:   uint16(len(socks5ConnectRequest)),
	}.encode()
	if err := sw.write(meta, socks5ConnectRequest); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// server→client 方向的首段前置它自己选的 24 字节 nonce,先读出来。
	br := bufio.NewReader(conn)
	outNonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(br, outNonce); err != nil {
		_ = conn.Close()
		return nil, err
	}
	sr := newSegmentReader(br, aead, outNonce)

	seg, err := sr.read()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if seg.protocolType != protoOpenSessionResponse {
		_ = conn.Close()
		return nil, fmt.Errorf("首个回程段是 %d,want openSessionResponse", seg.protocolType)
	}
	seg, err = sr.read() // socks5 成功回复(首个 data 段)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if seg.protocolType != protoDataServerToClient || len(seg.payload) < 2 || seg.payload[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 回复不对: type=%d payload=%v", seg.protocolType, seg.payload)
	}

	_ = conn.SetDeadline(time.Time{})
	return &mieruStream{conn: conn, sw: sw, sr: sr, sid: 1}, nil
}

// probeMieru 用某个凭据完整建一次会话并回显一帧。返回 nil 即「这个用户此刻真的能用」。
func probeMieru(addr, username, password string) error {
	st, err := dialMieru(addr, username, password)
	if err != nil {
		return err
	}
	defer st.Close()
	_ = st.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := st.Write([]byte("probe\n")); err != nil {
		return err
	}
	line, err := bufio.NewReader(st).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "probe" {
		return fmt.Errorf("回显对不上: %q", line)
	}
	return nil
}

// ===== 活跃流的采样与断言(与 snell 那边同一套口径)=====

type arrival struct {
	seq int
	at  time.Time
}

type liveStream struct {
	mu       sync.Mutex
	arrivals []arrival
	readErr  error
	writeErr error
	sent     int

	stopped chan struct{}
}

const frameInterval = 20 * time.Millisecond

func startLiveStream(w io.Writer, r io.Reader) *liveStream {
	ls := &liveStream{stopped: make(chan struct{})}
	br := bufio.NewReader(r)

	go func() { // 写侧:按固定节奏发帧
		tk := time.NewTicker(frameInterval)
		defer tk.Stop()
		for i := 0; ; i++ {
			select {
			case <-ls.stopped:
				return
			case <-tk.C:
			}
			if _, err := w.Write([]byte(fmt.Sprintf("%08d\n", i))); err != nil {
				ls.mu.Lock()
				ls.writeErr = err
				ls.mu.Unlock()
				return
			}
			ls.mu.Lock()
			ls.sent = i + 1
			ls.mu.Unlock()
		}
	}()

	go func() { // 读侧:读回显,记序号与到达时刻
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				ls.mu.Lock()
				ls.readErr = err
				ls.mu.Unlock()
				return
			}
			n, cerr := strconv.Atoi(strings.TrimSpace(line))
			if cerr != nil {
				ls.mu.Lock()
				ls.readErr = fmt.Errorf("回显不是序号帧 %q: %v", line, cerr)
				ls.mu.Unlock()
				return
			}
			ls.mu.Lock()
			ls.arrivals = append(ls.arrivals, arrival{seq: n, at: time.Now()})
			ls.mu.Unlock()
		}
	}()
	return ls
}

func (ls *liveStream) stopWriting() { close(ls.stopped) }

func (ls *liveStream) snapshot() ([]arrival, error, error, int) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	out := make([]arrival, len(ls.arrivals))
	copy(out, ls.arrivals)
	return out, ls.readErr, ls.writeErr, ls.sent
}

// verifyUninterrupted 是本文件的核心断言:这条流从头到尾没断、没丢帧、没错序,
// 且在 [from, to] 这段(= 用户表变更发生的那段)确实有足够多的帧流过。
func verifyUninterrupted(t *testing.T, ls *liveStream, from, to time.Time) {
	t.Helper()
	arrivals, readErr, writeErr, sent := ls.snapshot()

	if writeErr != nil {
		t.Fatalf("发送侧中途出错 —— 连接断了: %v", writeErr)
	}
	if readErr != nil {
		t.Fatalf("接收侧中途出错 —— 连接断了: %v", readErr)
	}
	if len(arrivals) == 0 {
		t.Fatal("一帧都没收到,这条流根本没跑起来")
	}
	for i, a := range arrivals {
		if a.seq != i {
			t.Fatalf("第 %d 帧的序号是 %d —— 丢帧或错序", i, a.seq)
		}
	}
	if sent-len(arrivals) > 2 {
		t.Fatalf("发了 %d 帧只收回 %d 帧 —— 中间有一段没回来", sent, len(arrivals))
	}

	var before, during, after int
	for _, a := range arrivals {
		switch {
		case a.at.Before(from):
			before++
		case a.at.After(to):
			after++
		default:
			during++
		}
	}
	if before == 0 || during < 5 || after == 0 {
		t.Fatalf("帧没有充分跨过变更窗口(变更前 %d / 变更中 %d / 变更后 %d)—— 这样测不出「变更期间没断」",
			before, during, after)
	}

	maxGap := time.Duration(0)
	gapAt := 0
	for i := 1; i < len(arrivals); i++ {
		if g := arrivals[i].at.Sub(arrivals[i-1].at); g > maxGap {
			maxGap, gapAt = g, arrivals[i].seq
		}
	}
	t.Logf("收到 %d 帧(变更前 %d / 变更中 %d / 变更后 %d),最大到达间隔 %v(第 %d 帧)",
		len(arrivals), before, during, after, maxGap, gapAt)
	if maxGap > 100*frameInterval {
		t.Fatalf("到达间隔出现 %v 的空洞(第 %d 帧),远超帧间隔 %v —— 疑似连接被重建",
			maxGap, gapAt, frameInterval)
	}
}

const churnRounds = 30

// TestMieruLiveStreamHarnessDetectsBreak 是第一层的阴性对照。
//
// 「流没断」这个结论只有在「这套测量方法测得出断」的前提下才成立 —— 否则它永远 PASS,
// 什么也没证明。这里故意把连接掐掉(模拟 agent 退回整入站替换时那条流的遭遇),
// 采样侧必须察觉。
func TestMieruLiveStreamHarnessDetectsBreak(t *testing.T) {
	srv := &Server{
		policyManager: policy.DefaultManager{},
		users: []*protocol.MemoryUser{
			mieruUser(t, "keep@x", "ukeep", "pkeep"),
			mieruUser(t, "spare@x", "uspare", "pspare"),
		},
	}
	addr, stop := startMieruServer(t, srv)
	defer stop()

	stream, err := dialMieru(addr, "ukeep", "pkeep")
	if err != nil {
		t.Fatalf("建立会话失败: %v", err)
	}
	ls := startLiveStream(stream, stream)
	time.Sleep(10 * frameInterval)

	stream.Close() // ← 掐断
	time.Sleep(10 * frameInterval)
	ls.stopWriting()
	time.Sleep(5 * frameInterval)

	arrivals, readErr, writeErr, sent := ls.snapshot()
	if readErr == nil && writeErr == nil {
		t.Fatalf("连接已经掐断,采样侧却毫无察觉(发 %d 帧收 %d 帧)—— 这套测量方法测不出断线,"+
			"上面那些「没断」的结论全部作废", sent, len(arrivals))
	}
	t.Logf("阴性对照成立:掐断后被测出(发 %d 帧收 %d 帧,readErr=%v writeErr=%v)",
		sent, len(arrivals), readErr, writeErr)
}

// TestMieruLiveStreamSurvivesUserChurn:一条活跃会话 + 并发增删用户,会话必须全程不受影响。
func TestMieruLiveStreamSurvivesUserChurn(t *testing.T) {
	ctx := context.Background()
	srv := &Server{
		policyManager: policy.DefaultManager{},
		users: []*protocol.MemoryUser{
			mieruUser(t, "keep@x", "ukeep", "pkeep"),
			mieruUser(t, "spare@x", "uspare", "pspare"), // 占位,保证 RemoveUser 永远不会去删最后一个
		},
	}
	addr, stop := startMieruServer(t, srv)
	defer stop()

	stream, err := dialMieru(addr, "ukeep", "pkeep")
	if err != nil {
		t.Fatalf("用户 A 建立会话失败: %v", err)
	}
	defer stream.Close()

	ls := startLiveStream(stream, stream)

	// 先让流跑一会儿,拿到「变更之前」的样本。
	time.Sleep(10 * frameInterval)

	churnFrom := time.Now()

	// counts 收集期间观察到的用户数。只要它不止一个取值,就说明用户表**真的**在变 ——
	// 这是防止假阳性的关键:AddUser/RemoveUser 若被静默跳过,流当然不会断,
	// 但那样什么也没证明。
	var countMu sync.Mutex
	counts := map[int64]bool{}
	note := func(c int64) {
		countMu.Lock()
		counts[c] = true
		countMu.Unlock()
	}

	// hammer:另起一个 goroutine 不停增删**另一个**用户,让「活跃会话 / 主循环 / 写侧」
	// 三方真正并发,而不是主循环一个人串行地改。它只碰 hammer@x,不干扰主循环的断言。
	var hammerOps atomic.Int64
	hammerStop := make(chan struct{})
	var hammerWG sync.WaitGroup
	hammerUser := mieruUser(t, "hammer@x", "uhammer", "phammer")
	hammerWG.Add(1)
	go func() {
		defer hammerWG.Done()
		for {
			select {
			case <-hammerStop:
				return
			default:
			}
			if err := srv.AddUser(ctx, hammerUser); err == nil {
				hammerOps.Add(1)
			}
			note(srv.GetUsersCount(ctx))
			if err := srv.RemoveUser(ctx, "hammer@x"); err == nil {
				hammerOps.Add(1)
			}
			note(srv.GetUsersCount(ctx))
			time.Sleep(time.Millisecond)
		}
	}()

	for round := 0; round < churnRounds; round++ {
		email := fmt.Sprintf("churn%d@x", round)
		username := fmt.Sprintf("uchurn%d", round)
		password := fmt.Sprintf("pchurn%d", round)

		if err := srv.AddUser(ctx, mieruUser(t, email, username, password)); err != nil {
			t.Fatalf("第 %d 轮 AddUser(%s): %v", round, email, err)
		}
		if srv.GetUser(ctx, email) == nil {
			t.Fatalf("第 %d 轮 AddUser 之后 %s 不在用户表里 —— 用户表没被改到", round, email)
		}
		note(srv.GetUsersCount(ctx))
		if err := probeMieru(addr, username, password); err != nil {
			t.Fatalf("第 %d 轮:刚加的用户 %s 连不上 —— 加进去的用户不可用: %v", round, email, err)
		}

		if err := srv.RemoveUser(ctx, email); err != nil {
			t.Fatalf("第 %d 轮 RemoveUser(%s): %v", round, email, err)
		}
		if srv.GetUser(ctx, email) != nil {
			t.Fatalf("第 %d 轮 RemoveUser 之后 %s 还在用户表里", round, email)
		}
		note(srv.GetUsersCount(ctx))
		if err := probeMieru(addr, username, password); err == nil {
			t.Fatalf("第 %d 轮:已删的用户 %s 还能连上 —— 删的不是握手在读的那张表", round, email)
		}
		// 把变更摊开在时间轴上,好让足够多的帧落在变更窗口之内。
		time.Sleep(frameInterval)
	}
	close(hammerStop)
	hammerWG.Wait()
	churnTo := time.Now()

	countMu.Lock()
	seen := make([]int64, 0, len(counts))
	for c := range counts {
		seen = append(seen, c)
	}
	countMu.Unlock()
	sort.Slice(seen, func(i, j int) bool { return seen[i] < seen[j] })
	if len(seen) < 2 {
		t.Fatalf("整段期间 GetUsersCount 始终是 %v —— 用户表根本没变,这个测试在空转", seen)
	}
	if hammerOps.Load() == 0 {
		t.Fatal("并发 hammer 一次都没成功改过用户表")
	}
	t.Logf("增删 %d 轮 + 并发 hammer %d 次成功写入(%v ~ %v,共 %v),期间观察到的用户数取值 %v",
		churnRounds, hammerOps.Load(), churnFrom.Format("15:04:05.000"), churnTo.Format("15:04:05.000"),
		churnTo.Sub(churnFrom), seen)

	// 再跑一会儿,拿到「变更之后」的样本。
	time.Sleep(10 * frameInterval)
	ls.stopWriting()
	time.Sleep(5 * frameInterval) // 等最后几帧回来

	verifyUninterrupted(t, ls, churnFrom, churnTo)
}
