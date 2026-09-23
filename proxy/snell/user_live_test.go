// user_live_test.go:证明 per-user 热更新期间,该入站上**已经建立的连接不会断**。
//
// user_test.go 里的用例只证明了「用户表改完之后,新的握手按新表判定」;它们从头到尾
// 没有一条活着的连接。而 UserManager 存在的全部意义正是「改用户表时不碰在用连接」——
// 这一条此前只有间接证据(走了 per-user 增量、进程没重启、日志自称没中断),没有人
// 挂着一条正在收发的连接去实测它活过了变更。这个文件补的就是这一步:
//
//	真的起一个 snell server(Process + dispatcher,不是只调库函数)
//	→ 用户 A 建立连接并持续双向收发
//	→ 并发地反复 AddUser / RemoveUser
//	→ 断言 A 那条流全程没断、序号连续无缺口无错序
//
// 关键是别做成假阳性:如果 AddUser/RemoveUser 被静默跳过(比如被某个校验挡了),
// 流当然不会断,测试却什么也没证明。所以每一轮都查 GetUsersCount 真的在变,并且
// 拿新加的凭据真连一次(必须连上)、拿删掉的凭据再连一次(必须连不上)。
package snell

import (
	"bufio"
	"bytes"
	"context"
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

var testDest = xnet.TCPDestination(xnet.ParseAddress("1.2.3.4"), 443)

// startSnellServer 在本机随机端口上真的跑起这个 Server(走 Process,不是直接调 handshake)。
func startSnellServer(t *testing.T, srv *Server) (addr string, stop func()) {
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

// snellStream 是一条建好的 snell 客户端连接(已完成握手、已收到 ReplyTunnel)。
// w 用 io.Writer 而不是具体类型:v4/v5 是 *recordWriter,v6 是 snellWriter,这里只当写端用。
type snellStream struct {
	conn net.Conn
	w    io.Writer
	r    *bufio.Reader
}

func (s *snellStream) Close() { _ = s.conn.Close() }

// dialSnell 完整走一遍客户端流程:salt + 首个 record 里带 CONNECT 请求 → 读回程 ReplyTunnel。
func dialSnell(addr, psk string) (*snellStream, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	// 握手期给个上限,免得服务端拒绝时客户端挂死(删掉的用户必然走到这条路)。
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var reqBuf bytes.Buffer
	if err := (request{command: commandConnect, destination: testDest}).writeTo(&reqBuf); err != nil {
		_ = conn.Close()
		return nil, err
	}
	w := newRecordWriter(conn, []byte(psk))
	if _, err := w.Write(reqBuf.Bytes()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	rr := newRecordReader(conn, []byte(psk))
	if err := readServerReply(rr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &snellStream{conn: conn, w: w, r: bufio.NewReader(rr)}, nil
}

// probeSnell 用某个凭据完整连一次并回显一帧。返回 nil 即「这个用户此刻真的能用」。
//
// 只判断握手成不成是不够的:握手过了但请求/回显走不通,说明用户是加进去了却不可用。
func probeSnell(addr, psk string) error {
	st, err := dialSnell(addr, psk)
	if err != nil {
		return err
	}
	defer st.Close()
	_ = st.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := st.w.Write([]byte("probe\n")); err != nil {
		return err
	}
	line, err := st.r.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "probe" {
		return fmt.Errorf("回显对不上: %q", line)
	}
	return nil
}

// arrival 记一帧回显的序号与到达时刻 —— 时刻是用来看「变更前后有没有异常停顿」的。
type arrival struct {
	seq int
	at  time.Time
}

// liveStream 挂一条持续双向收发的流:每 frameInterval 发一帧带序号的行,另一个 goroutine
// 读回显并记下序号与到达时刻。任何一侧出错都会被记下来 —— 那就是「连接断了」。
type liveStream struct {
	mu       sync.Mutex
	arrivals []arrival
	readErr  error
	writeErr error
	sent     int

	stopped chan struct{}
	done    sync.WaitGroup
}

const frameInterval = 20 * time.Millisecond

func startLiveStream(w interface{ Write([]byte) (int, error) }, r *bufio.Reader) *liveStream {
	ls := &liveStream{stopped: make(chan struct{})}

	ls.done.Add(1)
	go func() { // 写侧:按固定节奏发帧
		defer ls.done.Done()
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

	ls.done.Add(1)
	go func() { // 读侧:读回显,记序号与到达时刻
		defer ls.done.Done()
		for {
			line, err := r.ReadString('\n')
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
// 且在 [from, to] 这段(= 用户表变更发生的那段)确实有帧流过。
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
	// 序号必须是 0,1,2,... 连续:缺一个=丢帧,乱一个=错序,两者都意味着流被动过。
	for i, a := range arrivals {
		if a.seq != i {
			t.Fatalf("第 %d 帧的序号是 %d —— 丢帧或错序", i, a.seq)
		}
	}
	// 发出去的帧最多只差最后一两帧还在路上(stopWriting 之后我们只等一小会儿)。
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
	// 变更窗口里必须有足够多的帧流过,否则「变更期间没断」无从谈起。
	if before == 0 || during < 5 || after == 0 {
		t.Fatalf("帧没有充分跨过变更窗口(变更前 %d / 变更中 %d / 变更后 %d)—— 这样测不出「变更期间没断」",
			before, during, after)
	}

	// 到达间隔的尖峰:不是硬性判据(-race 下调度本来就抖),但一旦出现秒级空洞,
	// 基本就是连接被重建了。阈值给到帧间隔的 100 倍(2s)。
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

// TestSnellLiveStreamSurvivesUserChurn:v4 入站,一条活跃连接 + 并发增删用户。
func TestSnellLiveStreamSurvivesUserChurn(t *testing.T) {
	srv := &Server{
		policyManager: policy.DefaultManager{},
		users: []*protocol.MemoryUser{
			snellUser("keep@x", "psk-keep", 4),
			snellUser("spare@x", "psk-spare", 4), // 占位,保证 RemoveUser 永远不会去删最后一个
		},
		version: 4,
	}
	runSnellChurn(t, srv, "psk-keep")
}

// TestSnellLiveStreamHarnessDetectsBreak 是第一层的阴性对照。
//
// 「流没断」这个结论只有在「这套测量方法测得出断」的前提下才成立 —— 否则它永远 PASS,
// 什么也没证明。这里故意把连接掐掉(模拟 agent 退回整入站替换时那条流的遭遇),
// 采样侧必须察觉。
func TestSnellLiveStreamHarnessDetectsBreak(t *testing.T) {
	srv := &Server{
		policyManager: policy.DefaultManager{},
		users: []*protocol.MemoryUser{
			snellUser("keep@x", "psk-keep", 4),
			snellUser("spare@x", "psk-spare", 4),
		},
		version: 4,
	}
	addr, stop := startSnellServer(t, srv)
	defer stop()

	stream, err := dialSnell(addr, "psk-keep")
	if err != nil {
		t.Fatalf("建立连接失败: %v", err)
	}
	ls := startLiveStream(stream.w, stream.r)
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

// TestSnellV6LiveStreamSurvivesUserChurn:v6(default 整形模式)走的是另一条识别路径
// (identifyV6Shaped)和另一套 reader/writer,一并钉住。
func TestSnellV6LiveStreamSurvivesUserChurn(t *testing.T) {
	srv := &Server{
		policyManager: policy.DefaultManager{},
		users: []*protocol.MemoryUser{
			snellUser("keep@x", "v6-psk-keep-000000", 6),
			snellUser("spare@x", "v6-psk-spare-00000", 6),
		},
		version: 6,
		v6Mode:  ModeDefault,
	}
	runSnellChurnWith(t, srv, "v6-psk-keep-000000", dialSnellV6, probeSnellV6,
		func(i int) string { return fmt.Sprintf("v6-psk-churn-%06d", i) }, 6)
}

func runSnellChurn(t *testing.T, srv *Server, keepPSK string) {
	t.Helper()
	runSnellChurnWith(t, srv, keepPSK, dialSnell, probeSnell,
		func(i int) string { return fmt.Sprintf("psk-churn-%d", i) }, 4)
}

// churnRounds 是增删轮数。每轮 = 加一个用户 + 用它真连一次 + 删掉 + 再连一次(必须失败)。
const churnRounds = 30

func runSnellChurnWith(
	t *testing.T,
	srv *Server,
	keepPSK string,
	dial func(addr, psk string) (*snellStream, error),
	probe func(addr, psk string) error,
	pskFor func(int) string,
	version uint32,
) {
	t.Helper()
	ctx := context.Background()
	addr, stop := startSnellServer(t, srv)
	defer stop()

	stream, err := dial(addr, keepPSK)
	if err != nil {
		t.Fatalf("用户 A 建立连接失败: %v", err)
	}
	defer stream.Close()

	ls := startLiveStream(stream.w, stream.r)

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

	// hammer:另起一个 goroutine 不停增删**另一个**用户,让「活跃连接 / 主循环 / 写侧」
	// 三方真正并发,而不是主循环一个人串行地改。它只碰 hammer@x,不干扰主循环的断言。
	var hammerOps atomic.Int64
	hammerStop := make(chan struct{})
	var hammerWG sync.WaitGroup
	hammerUser := snellUser("hammer@x", pskFor(9999), version)
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
		psk := pskFor(round)

		if err := srv.AddUser(ctx, snellUser(email, psk, version)); err != nil {
			t.Fatalf("第 %d 轮 AddUser(%s): %v", round, email, err)
		}
		// 身份层面的断言(与 hammer 无关,恒定成立):这个 email 必须真的进表了。
		if srv.GetUser(ctx, email) == nil {
			t.Fatalf("第 %d 轮 AddUser 之后 %s 不在用户表里 —— 用户表没被改到", round, email)
		}
		note(srv.GetUsersCount(ctx))
		if err := probe(addr, psk); err != nil {
			t.Fatalf("第 %d 轮:刚加的用户 %s 连不上 —— 加进去的用户不可用: %v", round, email, err)
		}

		if err := srv.RemoveUser(ctx, email); err != nil {
			t.Fatalf("第 %d 轮 RemoveUser(%s): %v", round, email, err)
		}
		if srv.GetUser(ctx, email) != nil {
			t.Fatalf("第 %d 轮 RemoveUser 之后 %s 还在用户表里", round, email)
		}
		note(srv.GetUsersCount(ctx))
		if err := probe(addr, psk); err == nil {
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

// ===== v6 客户端 =====

// dialSnellV6 与 dialSnell 同样流程,只是 record 层换成 v6 的整形读写器。
func dialSnellV6(addr, psk string) (*snellStream, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	profile := NewProfile([]byte(psk))
	w, err := newV6Writer(conn, ModeDefault, []byte(psk), profile)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	var reqBuf bytes.Buffer
	if err := (request{command: commandConnect, destination: testDest}).writeTo(&reqBuf); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := w.Write(reqBuf.Bytes()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	rr := newV6Reader(conn, ModeDefault, []byte(psk), profile)
	if err := readServerReply(rr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &snellStream{conn: conn, w: w, r: bufio.NewReader(rr)}, nil
}

func probeSnellV6(addr, psk string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	profile := NewProfile([]byte(psk))
	w, err := newV6Writer(conn, ModeDefault, []byte(psk), profile)
	if err != nil {
		return err
	}
	var reqBuf bytes.Buffer
	if err := (request{command: commandConnect, destination: testDest}).writeTo(&reqBuf); err != nil {
		return err
	}
	if _, err := w.Write(reqBuf.Bytes()); err != nil {
		return err
	}
	rr := newV6Reader(conn, ModeDefault, []byte(psk), profile)
	if err := readServerReply(rr); err != nil {
		return err
	}
	if _, err := w.Write([]byte("probe\n")); err != nil {
		return err
	}
	line, err := bufio.NewReader(rr).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "probe" {
		return fmt.Errorf("回显对不上: %q", line)
	}
	return nil
}
