// user.go:mieru 入站的 proxy.UserManager 实现。
//
// 没有它的时候,主控每次绑/解一个用户,agent 只能把整个 mieru 入站拆了重建
// (RemoveInbound + AddInbound)—— 该入站上**所有在用连接**跟着一起断,而改动
// 其实只涉及一个用户。实现 UserManager 之后 agent 会自动改走 per-user 增量
// (它按 proxy.UserManager 断言分档,不看协议名),只增删这一张用户表,连接不受影响。
//
// 并发模型与 snell/user.go 相同:users 是 copy-on-write,写侧持写锁整体替换,
// 读侧只在 RLock 里复制一次 slice header 就出锁,遍历发生在锁外的不可变快照上。
// 握手期要按 3 个 timeSalt × 每个候选用户做 PBKDF2 派生,这条路径绝不能持锁。
package mieru

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// snapshotUsers 取一份当前用户表的快照。只在锁里复制 slice header,遍历在锁外做。
func (s *Server) snapshotUsers() []*protocol.MemoryUser {
	s.userMu.RLock()
	users := s.users
	s.userMu.RUnlock()
	return users
}

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	if u == nil || u.Account == nil {
		return errors.New("mieru: invalid user")
	}
	acc, ok := u.Account.(*MemoryAccount)
	if !ok {
		// 握手路径对 Account 是无保护断言(热路径上省一次判断),
		// 类型不对的用户混进去 = 下一条连接直接 panic。这里是唯一的关口。
		return errors.New("mieru: invalid account type")
	}
	if len(acc.hashedPassword) == 0 {
		// hashedPassword 只在 AsAccount() 里算;为空说明这个 MemoryAccount 是手工
		// 拼出来的,它永远握不上手 —— 静默加进去比报错难查得多。
		return errors.New("mieru: account not built via AsAccount (empty hashed password)")
	}
	if strings.TrimSpace(u.Email) == "" {
		// 没有 email 的用户此后再也删不掉(RemoveUser 只按 email 定位),
		// 而且 per-user 流量统计/限速/限连接数全靠 email,加进来没有意义。
		return errors.New("mieru: empty email")
	}

	s.userMu.Lock()
	defer s.userMu.Unlock()

	for _, existing := range s.users {
		// 大小写不敏感:主控/agent 侧按 lower(email) 去重,这里若按字节比,
		// "A@x" 与 "a@x" 会在运行态变成两条、在目标集合里只算一条,从此对不上。
		if strings.EqualFold(existing.Email, u.Email) {
			return errors.New("mieru: user email already exists: ", u.Email)
		}
	}

	users := make([]*protocol.MemoryUser, len(s.users), len(s.users)+1)
	copy(users, s.users)
	s.users = append(users, u)
	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	if strings.TrimSpace(email) == "" {
		return errors.New("mieru: empty email")
	}

	s.userMu.Lock()
	defer s.userMu.Unlock()

	idx := -1
	for i, u := range s.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil // 幂等:已经不在了(与 anytls / wireguard 一致)
	}
	if len(s.users) == 1 {
		// 不能把用户表删空:NewServer 本身就拒绝 0 用户,运行期删成空等于让这个入站
		// 从此谁都握不上手,而配置里它还好端端地在 —— 静默半死。宁可在这里报错,
		// 让调用方退回整入站替换/重启,按新配置重新收敛。
		return errors.New("mieru: refusing to remove the last user: ", email)
	}

	users := make([]*protocol.MemoryUser, 0, len(s.users)-1)
	users = append(users, s.users[:idx]...)
	users = append(users, s.users[idx+1:]...)
	s.users = users
	return nil
}

// GetUser implements proxy.UserManager.GetUser().
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	for _, u := range s.snapshotUsers() {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetUsers implements proxy.UserManager.GetUsers().
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	// 返回副本:快照底层数组是共享的,直接交出去被调用方改一个元素就是数据竞争。
	users := s.snapshotUsers()
	out := make([]*protocol.MemoryUser, len(users))
	copy(out, users)
	return out
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (s *Server) GetUsersCount(ctx context.Context) int64 {
	return int64(len(s.snapshotUsers()))
}
