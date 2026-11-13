// user.go:SSH 入站的 proxy.UserManager 实现。
//
// 有了它,agent 增删用户走 per-user 增量(它按 proxy.UserManager 断言分档),
// 不必整入站重建 —— 后者会经 Close 断开这个入站上所有人的 SSH 连接。
//
// 与其它协议不同的一点:SSH 只在建连时认证一次,删掉用户只拦得住下一次握手,
// 所以 RemoveUser 会顺手断开该用户的全部存量 SSH 连接(客户端重连时就认证不过了)。
package ssh

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
		return errors.New("ssh: invalid user")
	}
	if _, ok := u.Account.(*MemoryAccount); !ok {
		// 认证路径对 Account 是无保护断言,类型不对的用户混进去 = 下一条连接直接 panic。
		return errors.New("ssh: invalid account type")
	}
	if strings.TrimSpace(u.Email) == "" {
		// 没有 email 的用户此后删不掉(RemoveUser 按 email 定位),统计/限速也都按 email。
		return errors.New("ssh: empty email")
	}

	s.userMu.Lock()
	defer s.userMu.Unlock()
	for _, existing := range s.users {
		if strings.EqualFold(existing.Email, u.Email) {
			return errors.New("ssh: user email already exists: ", u.Email)
		}
	}
	users := make([]*protocol.MemoryUser, len(s.users), len(s.users)+1)
	copy(users, s.users)
	s.users = append(users, u)
	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser()。摘掉之后立刻断开该用户的全部 SSH 连接。
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	if strings.TrimSpace(email) == "" {
		return errors.New("ssh: empty email")
	}

	s.userMu.Lock()
	idx := -1
	for i, u := range s.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			break
		}
	}
	if idx >= 0 {
		users := make([]*protocol.MemoryUser, 0, len(s.users)-1)
		users = append(users, s.users[:idx]...)
		users = append(users, s.users[idx+1:]...)
		s.users = users
	}
	s.userMu.Unlock()

	// 不管表里有没有(幂等),都把这个 email 的连接断干净。
	if n := s.kickEmail(email); n > 0 {
		errors.LogInfo(ctx, "ssh: user ", email, " removed, closed ", n, " connection(s)")
	}
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
	users := s.snapshotUsers()
	out := make([]*protocol.MemoryUser, len(users))
	copy(out, users)
	return out
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (s *Server) GetUsersCount(ctx context.Context) int64 {
	return int64(len(s.snapshotUsers()))
}
