package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/netip"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// 以下 MemoryAccount / AsAccount 移植自上游 XTLS/Xray-core 345c76f9
// ("WireGuard inbound: Support dynamic peer management", #6360)。
// 目的:让每个 peer 成为标准的 protocol.MemoryUser,从而携带 email ——
// 限速、并发连接数与 per-user 流量统计全部依赖 si.User.Email。
//
// 与上游的差异(本 fork 的既有形态所致):
//   - KeepAlive 在本 fork 的 PeerConfig 里是 uint32,上游那版是 string
//   - PublicKey 到达 proxy 层时已由 infra/conf.ParseWireGuardKey 统一成 hex,
//     所以这里直接 hex 解码,不需要上游的 ParseKey

// parsePubKey 解析 peer 公钥。正常路径是 hex(infra/conf 已转好),
// 兼容直接构造 config 的调用方仍传 base64 的情况。
func parsePubKey(s string) (*[32]byte, error) {
	var out [32]byte
	if len(s) == 64 {
		if dat, err := hex.DecodeString(s); err == nil {
			copy(out[:], dat)
			return &out, nil
		}
	}
	for _, dec := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding, base64.StdEncoding, base64.URLEncoding} {
		if dat, err := dec.DecodeString(s); err == nil && len(dat) == 32 {
			copy(out[:], dat)
			return &out, nil
		}
	}
	return nil, errors.New("invalid wireguard public key: ", s)
}

func (p *PeerConfig) AsAccount() (protocol.Account, error) {
	pub, err := parsePubKey(p.PublicKey)
	if err != nil {
		return nil, err
	}

	allowedIPs := make([]netip.Prefix, 0, len(p.AllowedIps))
	for i := range p.AllowedIps {
		prefix, err := netip.ParsePrefix(p.AllowedIps[i])
		if err != nil {
			return nil, err
		}
		allowedIPs = append(allowedIPs, prefix)
	}

	return &MemoryAccount{
		Pub:          *pub,
		AllowedIPs:   allowedIPs,
		PreSharedKey: p.PreSharedKey,
		KeepAlive:    p.KeepAlive,
	}, nil
}

type MemoryAccount struct {
	Pub          [32]byte
	AllowedIPs   []netip.Prefix
	PreSharedKey string
	KeepAlive    uint32
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	if b, ok := other.(*MemoryAccount); ok {
		return a.Pub == b.Pub
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	allowedIPs := make([]string, 0, len(a.AllowedIPs))
	for i := range a.AllowedIPs {
		allowedIPs = append(allowedIPs, a.AllowedIPs[i].String())
	}

	return &PeerConfig{
		PublicKey:    hex.EncodeToString(a.Pub[:]),
		AllowedIps:   allowedIPs,
		PreSharedKey: a.PreSharedKey,
		KeepAlive:    a.KeepAlive,
	}
}

func (c *DeviceConfig) preferIP4() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP ||
		c.DomainStrategy == DeviceConfig_FORCE_IP4 ||
		c.DomainStrategy == DeviceConfig_FORCE_IP46
}

func (c *DeviceConfig) preferIP6() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP ||
		c.DomainStrategy == DeviceConfig_FORCE_IP6 ||
		c.DomainStrategy == DeviceConfig_FORCE_IP64
}

func (c *DeviceConfig) hasFallback() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP46 || c.DomainStrategy == DeviceConfig_FORCE_IP64
}

func (c *DeviceConfig) fallbackIP4() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP64
}

func (c *DeviceConfig) fallbackIP6() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP46
}

func (c *DeviceConfig) createTun() tunCreator {
	if !c.IsClient {
		// See tun_linux.go createKernelTun()
		errors.LogWarning(context.Background(), "Using gVisor TUN. WG inbound doesn't support kernel TUN yet.")
		return createGVisorTun
	}
	if c.NoKernelTun {
		errors.LogWarning(context.Background(), "Using gVisor TUN. NoKernelTun is set to true.")
		return createGVisorTun
	}
	kernelTunSupported, err := KernelTunSupported()
	if err != nil {
		errors.LogWarning(context.Background(), "Using gVisor TUN. Failed to check kernel TUN support:", err)
		return createGVisorTun
	}
	if !kernelTunSupported {
		errors.LogWarning(context.Background(), "Using gVisor TUN. Kernel TUN is not supported on your OS, or your permission is insufficient.")
		return createGVisorTun
	}
	errors.LogWarning(context.Background(), "Using kernel TUN.")
	return createKernelTun
}
