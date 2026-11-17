package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/ssh"
)

func TestSSHClientConfig(t *testing.T) {
	var c SSHClientConfig
	raw := `{"address":"ssh.example.com","port":2222,"user":"u","password":"p",
		"hostKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		"hostKeyAlgorithms":["ssh-ed25519"],"clientVersion":"SSH-2.0-OpenSSH_9.6",
		"ciphers":["aes128-gcm@openssh.com"],"macs":["hmac-sha2-256"],"kexAlgorithms":["curve25519-sha256"]}`
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	m, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.(*ssh.ClientConfig)
	if cfg.Address.GetDomain() != "ssh.example.com" || cfg.Port != 2222 || cfg.User != "u" || cfg.Password != "p" ||
		len(cfg.HostKey) != 1 || cfg.HostKeyAlgorithms[0] != "ssh-ed25519" || cfg.ClientVersion != "SSH-2.0-OpenSSH_9.6" ||
		cfg.Ciphers[0] != "aes128-gcm@openssh.com" || cfg.Macs[0] != "hmac-sha2-256" || cfg.KexAlgorithms[0] != "curve25519-sha256" {
		t.Fatalf("字段没对上: %+v", cfg)
	}

	for name, bad := range map[string]string{
		"缺地址": `{"password":"p"}`,
		"缺凭据": `{"address":"1.2.3.4"}`,
	} {
		var c SSHClientConfig
		if err := json.Unmarshal([]byte(bad), &c); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Build(); err == nil {
			t.Errorf("%s:应报错", name)
		}
	}
}

// outbound 加载器认得 "ssh"
func TestSSHOutboundRegistered(t *testing.T) {
	var ob OutboundDetourConfig
	if err := json.Unmarshal([]byte(`{"protocol":"ssh","tag":"s","settings":{"address":"1.2.3.4","password":"p"}}`), &ob); err != nil {
		t.Fatal(err)
	}
	if _, err := ob.Build(); err != nil {
		t.Fatalf("ssh 出站应能构建: %v", err)
	}
}
