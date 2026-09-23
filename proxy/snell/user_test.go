package snell

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
	"google.golang.org/protobuf/proto"
)

// Snell 入站必须是 proxy.UserManager —— agent 就是靠这个断言决定走 per-user 增量
// 还是整入站重建(后者会断掉该入站所有在用连接),它不看协议名。
var _ proxy.UserManager = (*Server)(nil)

func snellUser(email, psk string, version uint32) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Email:   email,
		Account: &MemoryAccount{PSK: []byte(psk), Version: version},
	}
}

func newSnellTestServer(users ...*protocol.MemoryUser) *Server {
	return &Server{users: users, version: 4}
}

// notSnellAccount 是一个别的协议的 account,用来验证 AddUser 会挡住类型不对的用户 ——
// 握手路径上 u.Account.(*MemoryAccount) 有无保护的断言,混进去就是 panic。
type notSnellAccount struct{}

func (notSnellAccount) Equals(protocol.Account) bool { return false }
func (notSnellAccount) ToProto() proto.Message       { return nil }

// readOnlyConn 把一段预先准备好的客户端字节伪装成 net.Conn 喂给 handshake。
type readOnlyConn struct{ r io.Reader }

func (c *readOnlyConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *readOnlyConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *readOnlyConn) Close() error                       { return nil }
func (c *readOnlyConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *readOnlyConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *readOnlyConn) SetDeadline(time.Time) error        { return nil }
func (c *readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

// snellClientHello 生成一个 v4/v5 客户端的开头字节:salt + 首个 record(带 header)。
func snellClientHello(t *testing.T, psk string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := newRecordWriter(&buf, []byte(psk))
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("写客户端首个 record: %v", err)
	}
	return buf.Bytes()
}

func TestSnellAddUser(t *testing.T) {
	s := newSnellTestServer(snellUser("a@x", "psk-a", 4))
	if err := s.AddUser(context.Background(), snellUser("b@x", "psk-b", 4)); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if got := s.GetUsersCount(context.Background()); got != 2 {
		t.Fatalf("GetUsersCount = %d, want 2", got)
	}
	if u := s.GetUser(context.Background(), "b@x"); u == nil || u.Email != "b@x" {
		t.Fatalf("GetUser(b@x) = %v, want 新加的那个用户", u)
	}
	// email 大小写不敏感:主控侧按 lower(email) 去重,这里必须对得上
	if u := s.GetUser(context.Background(), "B@X"); u == nil {
		t.Fatal("GetUser 应当忽略 email 大小写")
	}
	users := s.GetUsers(context.Background())
	if len(users) != 2 || users[0].Email != "a@x" || users[1].Email != "b@x" {
		t.Fatalf("GetUsers = %v", users)
	}
}

func TestSnellAddUserRejects(t *testing.T) {
	ctx := context.Background()
	cases := map[string]*protocol.MemoryUser{
		"重复 email":      snellUser("a@x", "psk-other", 4),
		"重复 email(大小写)": snellUser("A@X", "psk-other", 4),
		"空 email":       snellUser("", "psk-other", 4),
		"账号类型不对":        {Email: "c@x", Account: notSnellAccount{}},
		"没有 account":    {Email: "e@x"},
	}
	for name, u := range cases {
		s := newSnellTestServer(snellUser("a@x", "psk-a", 4))
		if err := s.AddUser(ctx, u); err == nil {
			t.Errorf("%s:AddUser 竟然成功了", name)
		}
		if got := s.GetUsersCount(ctx); got != 1 {
			t.Errorf("%s:被拒之后用户表不该变,GetUsersCount = %d", name, got)
		}
	}
	if err := newSnellTestServer(snellUser("a@x", "psk-a", 4)).AddUser(ctx, nil); err == nil {
		t.Error("AddUser(nil) 竟然成功了")
	}
}

// 用户自带的 version 与入站版本不一致**不能**拒绝。真机上撞见过:主控下发的套餐用户不带
// version(→ AsAccount 补默认 v4),而节点自建的管理员凭据是 v5,曾被这里拦下来打回整入站
// 替换(断连)。协议层只认 users[0].Version(NewServer 据此定 s.version),其余用户的这个字段
// 根本不读 —— 按配置路径加载本来就能正常工作,增量路径必须一致。
func TestSnellAddUserIgnoresPerUserVersion(t *testing.T) {
	s := newSnellTestServer(snellUser("a@x", "psk-a", 5))
	s.version = 5
	if err := s.AddUser(context.Background(), snellUser("b@x", "psk-b", 4)); err != nil {
		t.Fatalf("v4 用户加进 v5 入站被拒了: %v", err)
	}
	_, u, err := s.handshake(&readOnlyConn{r: bytes.NewReader(snellClientHello(t, "psk-b"))})
	if err != nil {
		t.Fatalf("加进来之后握手应当能通: %v", err)
	}
	if u.Email != "b@x" {
		t.Fatalf("握手命中 %s, want b@x", u.Email)
	}
}

func TestSnellRemoveUser(t *testing.T) {
	ctx := context.Background()
	srv := newSnellTestServer(snellUser("a@x", "psk-a", 4), snellUser("b@x", "psk-b", 4))
	if err := srv.RemoveUser(ctx, "a@x"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if srv.GetUser(ctx, "a@x") != nil {
		t.Fatal("删掉的用户还在")
	}
	if got := srv.GetUsersCount(ctx); got != 1 {
		t.Fatalf("GetUsersCount = %d, want 1", got)
	}
	// 幂等:再删一次不报错(与 anytls / wireguard 一致)
	if err := srv.RemoveUser(ctx, "a@x"); err != nil {
		t.Fatalf("重复 RemoveUser 应当幂等: %v", err)
	}
	if err := srv.RemoveUser(ctx, ""); err == nil {
		t.Fatal("空 email 应当被拒")
	}
}

// 删到只剩最后一个必须拒绝:NewServer 本身就不接受 0 用户,而 v6 unsafe-raw 模式
// 会直接索引 users[0] —— 删空之后下一条连接就是 index out of range,整个进程跟着 panic。
func TestSnellRemoveUserRefusesLastUser(t *testing.T) {
	ctx := context.Background()
	srv := newSnellTestServer(snellUser("only@x", "psk-a", 4))
	err := srv.RemoveUser(ctx, "only@x")
	if err == nil {
		t.Fatal("删最后一个用户竟然成功了 —— 用户表一旦删空,v6 raw 的 users[0] 就会 panic")
	}
	if !strings.Contains(err.Error(), "last user") {
		t.Errorf("错误信息没说清原因: %v", err)
	}
	if got := srv.GetUsersCount(ctx); got != 1 {
		t.Fatalf("被拒之后用户还该在,GetUsersCount = %d", got)
	}
}

// 兜底:即便用户表真的空了(不该发生),v6 unsafe-raw 也只能报错,不能 panic。
func TestSnellV6RawEmptyUsersDoesNotPanic(t *testing.T) {
	srv := &Server{version: 6, v6Mode: ModeUnsafeRaw}
	if _, _, _, err := srv.identifyV6User(bytes.NewReader(nil)); err == nil {
		t.Fatal("空用户表下 identifyV6User 应当报错")
	}
}

// 这条是整个改动的核心:改的必须是握手真正在读的那份用户表。
func TestSnellHandshakeFollowsUserTable(t *testing.T) {
	ctx := context.Background()
	srv := newSnellTestServer(snellUser("a@x", "psk-a", 4))

	handshakeAs := func(psk string) (*protocol.MemoryUser, error) {
		_, u, err := srv.handshake(&readOnlyConn{r: bytes.NewReader(snellClientHello(t, psk))})
		return u, err
	}

	if _, err := handshakeAs("psk-b"); err == nil {
		t.Fatal("还没加进来的用户就握上手了")
	}
	if err := srv.AddUser(ctx, snellUser("b@x", "psk-b", 4)); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	u, err := handshakeAs("psk-b")
	if err != nil {
		t.Fatalf("新加的用户握手失败: %v", err)
	}
	if u.Email != "b@x" {
		t.Fatalf("握手命中 %s, want b@x", u.Email)
	}

	if err := srv.RemoveUser(ctx, "a@x"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if _, err := handshakeAs("psk-a"); err == nil {
		t.Fatal("已删的用户还能握上手 —— 改到的不是握手在读的那份表")
	}
	if _, err := handshakeAs("psk-b"); err != nil {
		t.Fatalf("没被删的用户不该受影响: %v", err)
	}
}

// v6 走的是另一套识别路径(identifyV6Shaped),一并钉住。
func TestSnellV6ShapedHandshakeFollowsUserTable(t *testing.T) {
	ctx := context.Background()
	srv := &Server{version: 6, v6Mode: ModeDefault, users: []*protocol.MemoryUser{
		snellUser("a@x", "v6-psk-aaaaaaaaaaaa", 6),
	}}

	hello := func(t *testing.T, psk string) []byte {
		t.Helper()
		var buf bytes.Buffer
		w, err := newV6Writer(&buf, ModeDefault, []byte(psk), NewProfile([]byte(psk)))
		if err != nil {
			t.Fatalf("newV6Writer: %v", err)
		}
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Fatalf("写 v6 首个 record: %v", err)
		}
		return buf.Bytes()
	}

	newPSK := "v6-psk-bbbbbbbbbbbb"
	if _, _, _, err := srv.identifyV6User(bytes.NewReader(hello(t, newPSK))); err == nil {
		t.Fatal("还没加进来的 v6 用户就被识别了")
	}
	if err := srv.AddUser(ctx, snellUser("b@x", newPSK, 6)); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	u, _, _, err := srv.identifyV6User(bytes.NewReader(hello(t, newPSK)))
	if err != nil {
		t.Fatalf("新加的 v6 用户识别失败: %v", err)
	}
	if u.Email != "b@x" {
		t.Fatalf("识别到 %s, want b@x", u.Email)
	}
	if err := srv.RemoveUser(ctx, "a@x"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if _, _, _, err := srv.identifyV6User(bytes.NewReader(hello(t, "v6-psk-aaaaaaaaaaaa"))); err == nil {
		t.Fatal("已删的 v6 用户还能被识别")
	}
}

// TestSnellUserTableRace 要在 -race 下跑:一边不停增删用户,一边不停握手 / 遍历用户表。
//
// 加锁之前握手路径直接 range s.users(裸 slice、无锁),与 AddUser/RemoveUser 的整体替换
// 撞在一起就是 DATA RACE —— 现在不炸只是因为运行期从来没人改过这张表;实现 UserManager
// 之后主控每绑一个用户就会改一次,这条竞争会变成日常。
func TestSnellUserTableRace(t *testing.T) {
	ctx := context.Background()
	srv := newSnellTestServer(
		snellUser("keep@x", "psk-keep", 4),
		snellUser("churn@x", "psk-churn", 4),
	)
	hello := snellClientHello(t, "psk-keep")
	// 在测试 goroutine 里先建好,子 goroutine 里不能调 t.Fatalf。
	churn := snellUser("churn@x", "psk-churn", 4)

	var stop atomic.Bool
	var wg sync.WaitGroup

	// 写侧:不停地删掉 / 加回同一个用户
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = srv.RemoveUser(ctx, "churn@x")
			_ = srv.AddUser(ctx, churn)
		}
	}()

	// 读侧:握手(逐 PSK 试解,全程遍历用户表)+ 用户表查询
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_, _, _ = srv.handshake(&readOnlyConn{r: bytes.NewReader(hello)})
				_ = srv.GetUser(ctx, "keep@x")
				_ = srv.GetUsers(ctx)
				_ = srv.GetUsersCount(ctx)
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}
