package ssh

import (
	"bytes"
	"crypto/subtle"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount 是运行期的 SSH 用户凭据。公钥在 AsAccount 里一次解析好,认证时只比字节。
type MemoryAccount struct {
	Username       string
	Password       string
	AuthorizedKeys []string
	keys           [][]byte // 每把公钥的 wire 格式(ssh.PublicKey.Marshal)
}

func (a *Account) AsAccount() (protocol.Account, error) {
	if strings.TrimSpace(a.Username) == "" {
		return nil, errors.New("ssh: empty username")
	}
	m := &MemoryAccount{
		Username:       a.Username,
		Password:       a.Password,
		AuthorizedKeys: append([]string(nil), a.AuthorizedKeys...),
	}
	for _, line := range a.AuthorizedKeys {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, errors.New("ssh: invalid authorized key for user ", a.Username).Base(err)
		}
		m.keys = append(m.keys, pk.Marshal())
	}
	if m.Password == "" && len(m.keys) == 0 {
		return nil, errors.New("ssh: user ", a.Username, " has neither password nor authorized key")
	}
	return m, nil
}

// checkPassword 常数时间比较密码。没配密码的用户一律不接受密码登录。
func (m *MemoryAccount) checkPassword(user string, password []byte) bool {
	if m.Password == "" || user != m.Username {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(m.Password), password) == 1
}

func (m *MemoryAccount) hasKey(user string, key []byte) bool {
	if user != m.Username {
		return false
	}
	for _, k := range m.keys {
		if bytes.Equal(k, key) {
			return true
		}
	}
	return false
}

// Equals 比凭据本身(用户名 + 密码 + 公钥)。agent 的 dispatcher 用它判断「同 email 的用户凭据换过没有」,
// 换过就拒掉旧凭据会话上新开的流;只比用户名的话,重置密码之后旧连接还能一直开新 channel。
func (m *MemoryAccount) Equals(another protocol.Account) bool {
	o, ok := another.(*MemoryAccount)
	if !ok {
		return false
	}
	if m.Username != o.Username || m.Password != o.Password || len(m.keys) != len(o.keys) {
		return false
	}
	for i := range m.keys {
		if !bytes.Equal(m.keys[i], o.keys[i]) {
			return false
		}
	}
	return true
}

func (m *MemoryAccount) ToProto() proto.Message {
	return &Account{Username: m.Username, Password: m.Password, AuthorizedKeys: append([]string(nil), m.AuthorizedKeys...)}
}
