package conf_test

import (
	"encoding/json"
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
