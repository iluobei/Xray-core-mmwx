package mieru

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
	"google.golang.org/protobuf/proto"
)

// mieru 入站必须是 proxy.UserManager —— agent 就是靠这个断言决定走 per-user 增量
// 还是整入站重建(后者会断掉该入站所有在用连接),它不看协议名。
var _ proxy.UserManager = (*Server)(nil)

func mieruUser(t *testing.T, email, username, password string) *protocol.MemoryUser {
	t.Helper()
	acc, err := (&Account{Username: username, Password: password}).AsAccount()
	if err != nil {
		t.Fatalf("AsAccount: %v", err)
	}
	return &protocol.MemoryUser{Email: email, Account: acc}
}

func newMieruTestServer(users ...*protocol.MemoryUser) *Server {
	return &Server{users: users}
}

// notMieruAccount 是一个别的协议的 account,用来验证 AddUser 会挡住类型不对的用户 ——
// 握手路径上 u.Account.(*MemoryAccount) 是无保护的断言,混进去就是 panic。
type notMieruAccount struct{}

func (notMieruAccount) Equals(protocol.Account) bool { return false }
func (notMieruAccount) ToProto() proto.Message       { return nil }

// mieruClientHello 生成一个客户端的开头字节:nonce(末 4 字节带 userTag)+ 加密的首段元数据。
// 这正是 resolveUser 认人所依据的那一段。
func mieruClientHello(t *testing.T, username, password string) []byte {
	t.Helper()
	key, err := deriveKey(hashPassword(username, password), timeSalt(roundedUnixTime(time.Now().Unix())))
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatalf("newAEAD: %v", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := crand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	applyUserTag(nonce, username)

	var buf bytes.Buffer
	meta := sessionMeta{protocolType: protoOpenSessionRequest, sessionID: 1}.encode()
	if err := newSegmentWriter(&buf, aead, nonce).write(meta, nil); err != nil {
		t.Fatalf("写首段: %v", err)
	}
	return buf.Bytes()
}

func TestMieruAddUser(t *testing.T) {
	ctx := context.Background()
	s := newMieruTestServer(mieruUser(t, "a@x", "ua", "pa"))
	if err := s.AddUser(ctx, mieruUser(t, "b@x", "ub", "pb")); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if got := s.GetUsersCount(ctx); got != 2 {
		t.Fatalf("GetUsersCount = %d, want 2", got)
	}
	if u := s.GetUser(ctx, "b@x"); u == nil || u.Email != "b@x" {
		t.Fatalf("GetUser(b@x) = %v, want 新加的那个用户", u)
	}
	// email 大小写不敏感:主控侧按 lower(email) 去重,这里必须对得上
	if u := s.GetUser(ctx, "B@X"); u == nil {
		t.Fatal("GetUser 应当忽略 email 大小写")
	}
	users := s.GetUsers(ctx)
	if len(users) != 2 || users[0].Email != "a@x" || users[1].Email != "b@x" {
		t.Fatalf("GetUsers = %v", users)
	}
}

func TestMieruAddUserRejects(t *testing.T) {
	ctx := context.Background()
	cases := map[string]*protocol.MemoryUser{
		"重复 email":      mieruUser(t, "a@x", "uz", "pz"),
		"重复 email(大小写)": mieruUser(t, "A@X", "uz", "pz"),
		"空 email":       mieruUser(t, "", "uz", "pz"),
		"账号类型不对":        {Email: "c@x", Account: notMieruAccount{}},
		"没有 account":    {Email: "d@x"},
		// hashedPassword 只在 AsAccount() 里算,手工拼的 MemoryAccount 永远握不上手
		"account 没走 AsAccount": {Email: "e@x", Account: &MemoryAccount{Username: "ue", Password: "pe"}},
	}
	for name, u := range cases {
		s := newMieruTestServer(mieruUser(t, "a@x", "ua", "pa"))
		if err := s.AddUser(ctx, u); err == nil {
			t.Errorf("%s:AddUser 竟然成功了", name)
		}
		if got := s.GetUsersCount(ctx); got != 1 {
			t.Errorf("%s:被拒之后用户表不该变,GetUsersCount = %d", name, got)
		}
	}
	if err := newMieruTestServer(mieruUser(t, "a@x", "ua", "pa")).AddUser(ctx, nil); err == nil {
		t.Error("AddUser(nil) 竟然成功了")
	}
}

func TestMieruRemoveUser(t *testing.T) {
	ctx := context.Background()
	s := newMieruTestServer(mieruUser(t, "a@x", "ua", "pa"), mieruUser(t, "b@x", "ub", "pb"))
	if err := s.RemoveUser(ctx, "a@x"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if s.GetUser(ctx, "a@x") != nil {
		t.Fatal("删掉的用户还在")
	}
	if got := s.GetUsersCount(ctx); got != 1 {
		t.Fatalf("GetUsersCount = %d, want 1", got)
	}
	// 幂等:再删一次不报错(与 anytls / wireguard 一致)
	if err := s.RemoveUser(ctx, "a@x"); err != nil {
		t.Fatalf("重复 RemoveUser 应当幂等: %v", err)
	}
	if err := s.RemoveUser(ctx, ""); err == nil {
		t.Fatal("空 email 应当被拒")
	}
}

// 删到只剩最后一个必须拒绝:NewServer 本身就不接受 0 用户,运行期删成空等于让这个入站
// 从此谁都握不上手,而配置里它还好端端地在 —— 静默半死,不如报错退回整入站替换。
func TestMieruRemoveUserRefusesLastUser(t *testing.T) {
	ctx := context.Background()
	s := newMieruTestServer(mieruUser(t, "only@x", "uo", "po"))
	err := s.RemoveUser(ctx, "only@x")
	if err == nil {
		t.Fatal("删最后一个用户竟然成功了 —— 用户表删空之后这个入站谁都握不上手")
	}
	if !strings.Contains(err.Error(), "last user") {
		t.Errorf("错误信息没说清原因: %v", err)
	}
	if got := s.GetUsersCount(ctx); got != 1 {
		t.Fatalf("被拒之后用户还该在,GetUsersCount = %d", got)
	}
}

// 这条是整个改动的核心:改的必须是握手真正在读的那份用户表。
func TestMieruHandshakeFollowsUserTable(t *testing.T) {
	ctx := context.Background()
	s := newMieruTestServer(mieruUser(t, "a@x", "ua", "pa"))

	resolveAs := func(username, password string) (*protocol.MemoryUser, error) {
		br := bufio.NewReader(bytes.NewReader(mieruClientHello(t, username, password)))
		u, _, _, err := s.resolveUser(br)
		return u, err
	}

	if _, err := resolveAs("ub", "pb"); err == nil {
		t.Fatal("还没加进来的用户就握上手了")
	}
	if err := s.AddUser(ctx, mieruUser(t, "b@x", "ub", "pb")); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	u, err := resolveAs("ub", "pb")
	if err != nil {
		t.Fatalf("新加的用户握手失败: %v", err)
	}
	if u.Email != "b@x" {
		t.Fatalf("握手命中 %s, want b@x", u.Email)
	}

	if err := s.RemoveUser(ctx, "a@x"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if _, err := resolveAs("ua", "pa"); err == nil {
		t.Fatal("已删的用户还能握上手 —— 改到的不是握手在读的那份表")
	}
	if _, err := resolveAs("ub", "pb"); err != nil {
		t.Fatalf("没被删的用户不该受影响: %v", err)
	}
}

// UDP underlay 走的是另一条识别路径(resolveUDPUser),一并钉住。
func TestMieruUDPHandshakeFollowsUserTable(t *testing.T) {
	ctx := context.Background()
	s := newMieruTestServer(mieruUser(t, "a@x", "ua", "pa"))
	pkt := mieruClientHello(t, "ub", "pb")

	if _, _, err := s.resolveUDPUser(pkt); err == nil {
		t.Fatal("还没加进来的用户就被识别了")
	}
	if err := s.AddUser(ctx, mieruUser(t, "b@x", "ub", "pb")); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	u, _, err := s.resolveUDPUser(pkt)
	if err != nil {
		t.Fatalf("新加的用户 UDP 识别失败: %v", err)
	}
	if u.Email != "b@x" {
		t.Fatalf("识别到 %s, want b@x", u.Email)
	}
	if err := s.RemoveUser(ctx, "a@x"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if _, _, err := s.resolveUDPUser(mieruClientHello(t, "ua", "pa")); err == nil {
		t.Fatal("已删的用户还能被 UDP 路径识别")
	}
}

// TestMieruUserTableRace 要在 -race 下跑:一边不停增删用户,一边不停握手 / 遍历用户表。
//
// 加锁之前握手路径直接 range s.users(裸 slice、无锁),与 AddUser/RemoveUser 的整体替换
// 撞在一起就是 DATA RACE —— 现在不炸只是因为运行期从来没人改过这张表;实现 UserManager
// 之后主控每绑一个用户就会改一次,这条竞争会变成日常。
func TestMieruUserTableRace(t *testing.T) {
	ctx := context.Background()
	s := newMieruTestServer(
		mieruUser(t, "keep@x", "ukeep", "pkeep"),
		mieruUser(t, "churn@x", "uchurn", "pchurn"),
	)
	hello := mieruClientHello(t, "ukeep", "pkeep")
	// 在测试 goroutine 里先建好,子 goroutine 里不能调 t.Fatalf。
	churn := mieruUser(t, "churn@x", "uchurn", "pchurn")

	var stop atomic.Bool
	var wg sync.WaitGroup

	// 写侧:不停地删掉 / 加回同一个用户
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = s.RemoveUser(ctx, "churn@x")
			_ = s.AddUser(ctx, churn)
		}
	}()

	// 读侧:TCP / UDP 两条识别路径 + 用户表查询
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_, _, _, _ = s.resolveUser(bufio.NewReader(bytes.NewReader(hello)))
				_, _, _ = s.resolveUDPUser(hello)
				_ = s.GetUser(ctx, "keep@x")
				_ = s.GetUsers(ctx)
				_ = s.GetUsersCount(ctx)
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}
