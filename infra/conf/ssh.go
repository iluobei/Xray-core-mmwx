package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/ssh"
	"google.golang.org/protobuf/proto"
)

type SSHUser struct {
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	AuthorizedKeys []string `json:"authorizedKeys"`
	Level          byte     `json:"level"`
	Email          string   `json:"email"`
}

type SSHServerConfig struct {
	HostKey       string     `json:"hostKey"`
	ServerVersion string     `json:"serverVersion"`
	Users         []*SSHUser `json:"users"`
}

func (c *SSHServerConfig) Build() (proto.Message, error) {
	cfg := &ssh.ServerConfig{
		HostKey:       c.HostKey,
		ServerVersion: c.ServerVersion,
		Users:         make([]*protocol.User, 0, len(c.Users)),
	}
	for _, u := range c.Users {
		if u == nil {
			continue
		}
		if u.Username == "" {
			return nil, errors.New("SSH: user username is required")
		}
		if u.Password == "" && len(u.AuthorizedKeys) == 0 {
			return nil, errors.New("SSH: user ", u.Username, " needs a password or authorizedKeys")
		}
		cfg.Users = append(cfg.Users, &protocol.User{
			Level: uint32(u.Level),
			Email: u.Email,
			Account: serial.ToTypedMessage(&ssh.Account{
				Username:       u.Username,
				Password:       u.Password,
				AuthorizedKeys: u.AuthorizedKeys,
			}),
		})
	}
	return cfg, nil
}
