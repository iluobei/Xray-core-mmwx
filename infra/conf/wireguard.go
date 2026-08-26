package conf

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/wireguard"
	"google.golang.org/protobuf/proto"
)

type WireGuardPeerConfig struct {
	// Email 仅服务端(入站)模式有意义:填了才会被建成一个带身份的用户,
	// 限速、并发连接数与 per-user 流量统计都以它为键。
	// 留空则退化成匿名 peer —— 能连通,但计不了费、限不了速。
	Email        string   `json:"email"`
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    uint32   `json:"keepAlive"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
}

func (c *WireGuardPeerConfig) Build() (proto.Message, error) {
	var err error
	config := new(wireguard.PeerConfig)

	if c.PublicKey != "" {
		config.PublicKey, err = ParseWireGuardKey(c.PublicKey)
		if err != nil {
			return nil, err
		}
	}

	if c.PreSharedKey != "" {
		config.PreSharedKey, err = ParseWireGuardKey(c.PreSharedKey)
		if err != nil {
			return nil, err
		}
	}

	config.Endpoint = c.Endpoint
	// default 0
	config.KeepAlive = c.KeepAlive
	if c.AllowedIPs == nil {
		config.AllowedIps = []string{"0.0.0.0/0", "::0/0"}
	} else {
		config.AllowedIps = c.AllowedIPs
	}

	return config, nil
}

type WireGuardConfig struct {
	IsClient bool `json:""`

	NoKernelTun    bool                   `json:"noKernelTun"`
	SecretKey      string                 `json:"secretKey"`
	Address        []string               `json:"address"`
	Peers          []*WireGuardPeerConfig `json:"peers"`
	MTU            int32                  `json:"mtu"`
	NumWorkers     int32                  `json:"workers"`
	Reserved       []byte                 `json:"reserved"`
	DomainStrategy string                 `json:"domainStrategy"`
}

func (c *WireGuardConfig) Build() (proto.Message, error) {
	config := new(wireguard.DeviceConfig)

	var err error
	config.SecretKey, err = ParseWireGuardKey(c.SecretKey)
	if err != nil {
		return nil, errors.New("invalid WireGuard secret key: %w", err)
	}

	if c.Address == nil {
		// bogon ips
		config.Endpoint = []string{"10.0.0.1", "fd59:7153:2388:b5fd:0000:0000:0000:0001"}
	} else {
		config.Endpoint = c.Address
	}

	seenEmail := make(map[string]bool, len(c.Peers))
	for _, p := range c.Peers {
		msg, err := p.Build()
		if err != nil {
			return nil, err
		}
		peer := msg.(*wireguard.PeerConfig)

		// 客户端模式下 peers 是「上游服务器」而不是「用户」,不做用户化处理。
		if c.IsClient || p.Email == "" {
			config.Peers = append(config.Peers, peer)
			continue
		}

		// allowedIPs 缺省会被填成 0.0.0.0/0 + ::0/0。对匿名 peer 无所谓,
		// 但对带 email 的用户是致命的:隧道内所有源地址都会命中它,
		// 整个节点的流量和配额都算到这一个用户头上,且此后再也加不进第二个用户。
		if len(p.AllowedIPs) == 0 {
			return nil, errors.New("wireguard peer ", p.Email, ": allowedIPs is required for a peer with email")
		}
		if seenEmail[p.Email] {
			return nil, errors.New("wireguard: duplicated peer email ", p.Email)
		}
		seenEmail[p.Email] = true

		config.Users = append(config.Users, &protocol.User{
			Email:   p.Email,
			Account: serial.ToTypedMessage(peer),
		})
	}

	if c.MTU == 0 {
		config.Mtu = 1420
	} else {
		config.Mtu = c.MTU
	}
	// these a fallback code exists in wireguard-go code,
	// we don't need to process fallback manually
	config.NumWorkers = c.NumWorkers

	if len(c.Reserved) != 0 && len(c.Reserved) != 3 {
		return nil, errors.New(`"reserved" should be empty or 3 bytes`)
	}
	config.Reserved = c.Reserved

	switch strings.ToLower(c.DomainStrategy) {
	case "forceip", "":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP
	case "forceipv4":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP4
	case "forceipv6":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP6
	case "forceipv4v6":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP46
	case "forceipv6v4":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP64
	default:
		return nil, errors.New("unsupported domain strategy: ", c.DomainStrategy)
	}

	config.IsClient = c.IsClient
	config.NoKernelTun = c.NoKernelTun

	return config, nil
}

func ParseWireGuardKey(str string) (string, error) {
	var err error

	if str == "" {
		return "", errors.New("key must not be empty")
	}

	if len(str) == 64 {
		_, err = hex.DecodeString(str)
		if err == nil {
			return str, nil
		}
	}

	var dat []byte
	str = strings.TrimSuffix(str, "=")
	if strings.ContainsRune(str, '+') || strings.ContainsRune(str, '/') {
		dat, err = base64.RawStdEncoding.DecodeString(str)
	} else {
		dat, err = base64.RawURLEncoding.DecodeString(str)
	}
	if err == nil {
		return hex.EncodeToString(dat), nil
	}

	return "", errors.New("failed to deserialize key").Base(err)
}
