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

// SSHClientConfig 是 SSH 出站的 JSON 配置。字段含义对齐 sing-box 的 ssh 出站
// (server / server_port / user / password / private_key / host_key …),写法按本项目的驼峰风格。
type SSHClientConfig struct {
	Address              *Address   `json:"address"`
	Port                 uint16     `json:"port"`
	User                 string     `json:"user"`
	Password             string     `json:"password"`
	PrivateKey           string     `json:"privateKey"`
	PrivateKeyPassphrase string     `json:"privateKeyPassphrase"`
	HostKey              StringList `json:"hostKey"`
	HostKeyAlgorithms    StringList `json:"hostKeyAlgorithms"`
	ClientVersion        string     `json:"clientVersion"`
	Ciphers              StringList `json:"ciphers"`
	MACs                 StringList `json:"macs"`
	KexAlgorithms        StringList `json:"kexAlgorithms"`
}

func (c *SSHClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("SSH: server address is required")
	}
	if c.Password == "" && c.PrivateKey == "" {
		return nil, errors.New("SSH: password or privateKey is required")
	}
	return &ssh.ClientConfig{
		Address:              c.Address.Build(),
		Port:                 uint32(c.Port),
		User:                 c.User,
		Password:             c.Password,
		PrivateKey:           c.PrivateKey,
		PrivateKeyPassphrase: c.PrivateKeyPassphrase,
		HostKey:              c.HostKey,
		HostKeyAlgorithms:    c.HostKeyAlgorithms,
		ClientVersion:        c.ClientVersion,
		Ciphers:              c.Ciphers,
		Macs:                 c.MACs,
		KexAlgorithms:        c.KexAlgorithms,
	}, nil
}
