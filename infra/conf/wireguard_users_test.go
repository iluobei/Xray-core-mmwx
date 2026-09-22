package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/wireguard"
)

func buildWG(t *testing.T, raw string, isClient bool) (*wireguard.DeviceConfig, error) {
	t.Helper()
	c := new(conf.WireGuardConfig)
	if err := json.Unmarshal([]byte(raw), c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c.IsClient = isClient
	msg, err := c.Build()
	if err != nil {
		return nil, err
	}
	return msg.(*wireguard.DeviceConfig), nil
}

const wgSecret = `"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`

// 带 email 的 peer 变成用户(计费/限速/连接数的载体),不带的仍是匿名 peer。
func TestWireGuardServerPeersWithEmailBecomeUsers(t *testing.T) {
	cfg, err := buildWG(t, `{`+wgSecret+`,"peers":[
		{"email":"alice","publicKey":"ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=","allowedIPs":["10.7.0.2/32"]},
		{"publicKey":"ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze9=","allowedIPs":["10.7.0.3/32"]}
	]}`, false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Email != "alice" {
		t.Fatalf("Users = %v, want one user alice", cfg.Users)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("Peers = %d, want 1 anonymous peer", len(cfg.Peers))
	}
}

// 客户端模式下 peers 是上游服务器,绝不能被当成用户 —— 否则出站会被错误地按用户归属。
func TestWireGuardClientPeersNeverBecomeUsers(t *testing.T) {
	cfg, err := buildWG(t, `{`+wgSecret+`,"peers":[
		{"email":"alice","publicKey":"ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=","endpoint":"1.2.3.4:51820"}
	]}`, true)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(cfg.Users) != 0 {
		t.Fatalf("Users = %v, want none in client mode", cfg.Users)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("Peers = %d, want 1", len(cfg.Peers))
	}
}

// 省略 allowedIPs 会被默认成 0.0.0.0/0,对计费用户是致命的,必须报错而不是静默放行。
func TestWireGuardUserRequiresAllowedIPs(t *testing.T) {
	_, err := buildWG(t, `{`+wgSecret+`,"peers":[
		{"email":"alice","publicKey":"ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8="}
	]}`, false)
	if err == nil {
		t.Fatal("expected error for emailed peer without allowedIPs")
	}
}

func TestWireGuardRejectsDuplicateEmail(t *testing.T) {
	_, err := buildWG(t, `{`+wgSecret+`,"peers":[
		{"email":"alice","publicKey":"ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=","allowedIPs":["10.7.0.2/32"]},
		{"email":"alice","publicKey":"ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze9=","allowedIPs":["10.7.0.3/32"]}
	]}`, false)
	if err == nil {
		t.Fatal("expected error for duplicated email")
	}
}

// 以下几类坏配置过去只在 NewServer 才被拒:写盘前的 LoadJSONConfig 拦不住,整入站替换时
// 旧入站已被删掉、新的加不回来,下次重启整机 xray 起不来。现在 Build 就必须报错。
func TestWireGuardServerRejectsDuplicatePublicKey(t *testing.T) {
	// 同一把公钥,一个写 base64、一个写 hex —— 比较的是解码后的字节。
	_, err := buildWG(t, `{`+wgSecret+`,"peers":[
		{"email":"alice","publicKey":"ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=","allowedIPs":["10.7.0.2/32"]},
		{"email":"bob","publicKey":"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF","allowedIPs":["10.7.0.3/32"]}
	]}`, false)
	if err == nil {
		t.Fatal("expected duplicated public key to be rejected at build time")
	}
}

func TestWireGuardServerRejectsOverlappingAllowedIPs(t *testing.T) {
	_, err := buildWG(t, `{`+wgSecret+`,"peers":[
		{"email":"alice","publicKey":"`+wgHexKey(2)+`","allowedIPs":["10.7.0.0/24"]},
		{"email":"bob","publicKey":"`+wgHexKey(3)+`","allowedIPs":["10.7.0.3/32"]}
	]}`, false)
	if err == nil {
		t.Fatal("expected overlapping allowedIPs to be rejected at build time")
	}
}

func TestWireGuardServerRejectsNonCanonicalAllowedIPs(t *testing.T) {
	_, err := buildWG(t, `{`+wgSecret+`,"peers":[
		{"email":"alice","publicKey":"`+wgHexKey(2)+`","allowedIPs":["10.7.0.5/24"]}
	]}`, false)
	if err == nil {
		t.Fatal("expected non-canonical allowedIPs to be rejected at build time")
	}
}

// 有带 email 的用户时,省略 allowedIPs 的匿名 peer 会被补成 0.0.0.0/0,吞掉所有用户的流量。
func TestWireGuardServerRejectsAnonymousCatchAllBesideUser(t *testing.T) {
	_, err := buildWG(t, `{`+wgSecret+`,"peers":[
		{"email":"alice","publicKey":"`+wgHexKey(2)+`","allowedIPs":["10.7.0.2/32"]},
		{"publicKey":"`+wgHexKey(3)+`"}
	]}`, false)
	if err == nil {
		t.Fatal("expected anonymous catch-all peer beside an emailed user to be rejected")
	}
}

// 下面几种是 NewServer 接受的配置,Build 绝不能比它更严。
func TestWireGuardServerBuildNotStricterThanNewServer(t *testing.T) {
	for name, peers := range map[string]string{
		// 纯匿名旧配置,allowedIPs 省略 → 0.0.0.0/0 + ::0/0
		"legacy-anonymous": `{"publicKey":"` + wgHexKey(2) + `"}`,
		// 两个匿名 peer 都是 0.0.0.0/0:没有用户身份,不查重叠
		"legacy-two-anonymous": `{"publicKey":"` + wgHexKey(2) + `"},{"publicKey":"` + wgHexKey(3) + `"}`,
		// 匿名 peer 与用户公钥相同:NewServer 静默丢弃它,丢弃之后才查重叠
		"anonymous-duplicate-of-user": `{"email":"alice","publicKey":"ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=","allowedIPs":["10.7.0.2/32"]},
			{"publicKey":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
		// 主控下发的形态:用户、探测 peer、中转 peer 各自 /32 + /128
		"panel-shape": `{"email":"alice__wg-in","publicKey":"` + wgHexKey(2) + `","allowedIPs":["10.66.0.2/32","fd66::2/128"]},
			{"email":"__wgprobe__","publicKey":"` + wgHexKey(3) + `","allowedIPs":["10.66.3.254/32","fd66::3fe/128"]},
			{"email":"__wgtransit__1","publicKey":"` + wgHexKey(4) + `","allowedIPs":["10.66.0.5/32","fd66::5/128"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildWG(t, `{`+wgSecret+`,"peers":[`+peers+`]}`, false); err != nil {
				t.Fatalf("build rejected a config NewServer accepts: %v", err)
			}
		})
	}
}

// 客户端模式的 peers 是上游服务器:都是 0.0.0.0/0 很正常,不做用户化校验。
func TestWireGuardClientPeersSkipServerValidation(t *testing.T) {
	_, err := buildWG(t, `{`+wgSecret+`,"peers":[
		{"email":"a","publicKey":"`+wgHexKey(2)+`","endpoint":"1.2.3.4:51820"},
		{"email":"a","publicKey":"`+wgHexKey(2)+`","endpoint":"5.6.7.8:51820","allowedIPs":["10.0.0.5/24"]}
	]}`, true)
	if err != nil {
		t.Fatalf("client mode must not run server peer validation: %v", err)
	}
}

func wgHexKey(b byte) string {
	return strings.Repeat(string("0123456789abcdef"[b&0xf]), 64)
}
