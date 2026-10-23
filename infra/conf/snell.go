package conf

import (
	"net"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/snell"
	"google.golang.org/protobuf/proto"
)

type SnellUser struct {
	PSK      string `json:"psk"`
	Version  uint32 `json:"version"`
	ObfsMode string `json:"obfsMode"`
	ObfsHost string `json:"obfsHost"`
	V6Mode   string `json:"v6Mode"`
	ClientID string `json:"clientId"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

// SnellShadowTLS 入站的 ShadowTLS v3 外壳(见 proxy/snell 的 ShadowTLSConfig)。
type SnellShadowTLS struct {
	Password string `json:"password"`
	// Handshake 握手服务器,host 或 host:port(默认 443)。
	Handshake string `json:"handshake"`
	// Strict 只接受协商出 TLS 1.3 的握手服务器,默认 true。
	Strict *bool `json:"strict"`
}

type SnellServerConfig struct {
	Users     []*SnellUser    `json:"users"`
	ShadowTLS *SnellShadowTLS `json:"shadowTls"`
}

func (c *SnellServerConfig) Build() (proto.Message, error) {
	cfg := &snell.ServerConfig{
		Users: make([]*protocol.User, 0, len(c.Users)),
	}
	for _, u := range c.Users {
		if u.PSK == "" {
			return nil, errors.New("SNELL: user psk is required")
		}
		cfg.Users = append(cfg.Users, &protocol.User{
			Level: uint32(u.Level),
			Email: u.Email,
			Account: serial.ToTypedMessage(&snell.Account{
				Psk:      u.PSK,
				Version:  u.Version,
				ObfsMode: u.ObfsMode,
				ObfsHost: u.ObfsHost,
				V6Mode:   u.V6Mode,
				ClientId: u.ClientID,
			}),
		})
	}
	if c.ShadowTLS != nil {
		st, err := c.ShadowTLS.build(c.Users)
		if err != nil {
			return nil, err
		}
		cfg.ShadowTls = st
	}
	return cfg, nil
}

func (c *SnellShadowTLS) build(users []*SnellUser) (*snell.ShadowTLSConfig, error) {
	if c.Password == "" {
		return nil, errors.New("SNELL: shadowTls.password is required")
	}
	host := strings.TrimSpace(c.Handshake)
	if host == "" {
		return nil, errors.New("SNELL: shadowTls.handshake is required")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	for _, u := range users {
		if u.Version == 6 {
			return nil, errors.New("SNELL: shadowTls only supports snell v4/v5")
		}
		if m := strings.ToLower(u.ObfsMode); m != "" && m != "none" {
			return nil, errors.New("SNELL: shadowTls cannot be combined with obfs ", u.ObfsMode)
		}
	}
	strict := true
	if c.Strict != nil {
		strict = *c.Strict
	}
	return &snell.ShadowTLSConfig{Password: c.Password, Handshake: host, Strict: strict}, nil
}

// SnellClientShadowTLS 出站的 ShadowTLS v3 外壳(见 proxy/snell 的 ShadowTLSClientConfig)。
type SnellClientShadowTLS struct {
	Password string `json:"password"`
	// ServerName 握手 SNI,即服务端 handshake 的域名;只写 host,不带端口。
	ServerName string `json:"serverName"`
}

type SnellClientConfig struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Email    string   `json:"email"`
	PSK      string   `json:"psk"`
	Version  uint32   `json:"version"`
	ObfsMode string   `json:"obfsMode"`
	ObfsHost string   `json:"obfsHost"`
	V6Mode   string   `json:"v6Mode"`
	ClientID string   `json:"clientId"`
	Level    uint32   `json:"level"`

	ShadowTLS *SnellClientShadowTLS `json:"shadowTls"`
}

func (c *SnellClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("SNELL: server address is required")
	}
	if c.PSK == "" {
		return nil, errors.New("SNELL: psk is required")
	}
	var st *snell.ShadowTLSClientConfig
	if c.ShadowTLS != nil {
		var err error
		if st, err = c.ShadowTLS.build(c.Version, c.ObfsMode); err != nil {
			return nil, err
		}
	}
	return &snell.ClientConfig{
		ShadowTls: st,
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
			User: &protocol.User{
				Level: c.Level,
				Email: c.Email,
				Account: serial.ToTypedMessage(&snell.Account{
					Psk:      c.PSK,
					Version:  c.Version,
					ObfsMode: c.ObfsMode,
					ObfsHost: c.ObfsHost,
					V6Mode:   c.V6Mode,
					ClientId: c.ClientID,
				}),
			},
		},
	}, nil
}

func (c *SnellClientShadowTLS) build(version uint32, obfsMode string) (*snell.ShadowTLSClientConfig, error) {
	if c.Password == "" {
		return nil, errors.New("SNELL: shadowTls.password is required")
	}
	name := strings.TrimSpace(c.ServerName)
	if name == "" {
		return nil, errors.New("SNELL: shadowTls.serverName is required")
	}
	if strings.ContainsAny(name, ":/ ") {
		return nil, errors.New("SNELL: shadowTls.serverName must be a host name without port: ", c.ServerName)
	}
	if version == 6 {
		return nil, errors.New("SNELL: shadowTls only supports snell v4/v5")
	}
	if m := strings.ToLower(obfsMode); m != "" && m != "none" {
		return nil, errors.New("SNELL: shadowTls cannot be combined with obfs ", obfsMode)
	}
	return &snell.ShadowTLSClientConfig{Password: c.Password, ServerName: name}, nil
}
