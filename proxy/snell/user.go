// user.go:Snell 入站的 proxy.UserManager 实现。
//
// 没有它的时候,主控每次绑/解一个用户,agent 只能把整个 snell 入站拆了重建
// (RemoveInbound + AddInbound)—— 该入站上**所有在用连接**跟着一起断,而改动
// 其实只涉及一个用户。实现 UserManager 之后 agent 会自动改走 per-user 增量
// (它按 proxy.UserManager 断言分档,不看协议名),只增删这一张用户表,连接不受影响。
//
// 并发模型:users 是 copy-on-write。写侧持写锁,且永远新建一份 slice 再整体替换,
// 绝不原地 append/删除;读侧(握手路径)只在 RLock 里复制一次 slice header 就出锁,
// 之后遍历的是一份此后不会再被任何人改写的快照。握手期要逐 PSK 试解
// (每个候选一次 Argon2id,不便宜),这样做才能保证它全程不持锁:加删用户不会被
// 在途握手堵住,在途握手也不会看见改到一半的用户表。
//
// 用 RWMutex + 快照而不是 atomic.Pointer:AddUser 要「先查重 email 再写」,是一个
// 读-改-写事务,atomic.Pointer 还得另外配一把写锁,不如直接 RWMutex 一把管到底。
package snell

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
		return errors.New("snell: invalid user")
	}
	acc, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("snell: invalid account type")
	}
	if strings.TrimSpace(u.Email) == "" {
		// 没有 email 的用户此后再也删不掉(RemoveUser 只按 email 定位),
		// 而且 per-user 流量统计/限速/限连接数全靠 email,加进来没有意义。
		return errors.New("snell: empty email")
	}
	// 这里**故意不校验** acc.Version 与入站版本是否一致。版本是入站级设置:NewServer 只读
	// users[0].Version 定下 s.version,其余用户的 Version 字段协议层从头到尾不看。主控下发的
	// 套餐用户又普遍不带 version(为空 → AsAccount 补默认 v4),真机上就撞见过
	// 「inbound is v5, user is v4」—— 拦下来只会把本可以增量的改动打回整入站替换(断连),
	// 而这些用户按配置路径加载本来是好好工作的。判定必须与配置路径一致。
	//
	// v6 的 PSK 长度则要查:NewServer 对 v6 入站的**每个**用户都查这一条。
	if s.version == 6 && (len(acc.PSK) < 12 || len(acc.PSK) > 255) {
		return errors.New("snell: v6 psk length must be 12..255 bytes")
	}

	s.userMu.Lock()
	defer s.userMu.Unlock()

	for _, existing := range s.users {
		// 大小写不敏感:主控/agent 侧按 lower(email) 去重,这里若按字节比,
		// "A@x" 与 "a@x" 会在运行态变成两条、在目标集合里只算一条,从此对不上。
		if strings.EqualFold(existing.Email, u.Email) {
			return errors.New("snell: user email already exists: ", u.Email)
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
		return errors.New("snell: empty email")
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
		// 不能把用户表删空。NewServer 本身就拒绝 0 用户;更要命的是 v6 unsafe-raw
		// 模式会直接索引 users[0] 回落,删空之后下一条连接就是 index out of range,
		// **整个 agent 进程**跟着 panic。宁可在这里报错让调用方退回整入站替换/重启:
		// 那条路最多断这一个入站(或这一台),不会把进程带走。
		return errors.New("snell: refusing to remove the last user: ", email)
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
