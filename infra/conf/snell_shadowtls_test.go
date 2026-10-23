package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/snell"
)

func buildSnellServer(t *testing.T, raw string) (*snell.ServerConfig, error) {
	t.Helper()
	var c SnellServerConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	m, err := c.Build()
	if err != nil {
		return nil, err
	}
	return m.(*snell.ServerConfig), nil
}

func TestSnellShadowTLSConfig(t *testing.T) {
	cfg, err := buildSnellServer(t, `{"users":[{"psk":"p","version":5,"email":"a"}],
		"shadowTls":{"password":"pw","handshake":"www.apple.com"}}`)
	if err != nil {
		t.Fatal(err)
	}
	st := cfg.GetShadowTls()
	if st.Password != "pw" || st.Handshake != "www.apple.com:443" || !st.Strict {
		t.Fatalf("默认端口 443、默认 strict: %+v", st)
	}

	cfg, err = buildSnellServer(t, `{"users":[{"psk":"p","version":4}],
		"shadowTls":{"password":"pw","handshake":"example.com:8443","strict":false}}`)
	if err != nil {
		t.Fatal(err)
	}
	if st := cfg.GetShadowTls(); st.Handshake != "example.com:8443" || st.Strict {
		t.Fatalf("显式端口与 strict=false 应保留: %+v", st)
	}

	if cfg, err := buildSnellServer(t, `{"users":[{"psk":"p","version":5}]}`); err != nil || cfg.GetShadowTls() != nil {
		t.Fatalf("不配 shadowTls 时不应带上: %v %+v", err, cfg)
	}

	for name, raw := range map[string]string{
		"v6":        `{"users":[{"psk":"p","version":6}],"shadowTls":{"password":"pw","handshake":"a.com"}}`,
		"obfs":      `{"users":[{"psk":"p","version":5,"obfsMode":"tls"}],"shadowTls":{"password":"pw","handshake":"a.com"}}`,
		"no-pass":   `{"users":[{"psk":"p","version":5}],"shadowTls":{"handshake":"a.com"}}`,
		"no-server": `{"users":[{"psk":"p","version":5}],"shadowTls":{"password":"pw"}}`,
	} {
		if _, err := buildSnellServer(t, raw); err == nil || !strings.Contains(err.Error(), "shadowTls") {
			t.Errorf("%s 应被拒绝,得到 %v", name, err)
		}
	}
}

func buildSnellClient(t *testing.T, raw string) (*snell.ClientConfig, error) {
	t.Helper()
	var c SnellClientConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	m, err := c.Build()
	if err != nil {
		return nil, err
	}
	return m.(*snell.ClientConfig), nil
}

func TestSnellClientShadowTLSConfig(t *testing.T) {
	cfg, err := buildSnellClient(t, `{"address":"1.2.3.4","port":443,"psk":"p","version":5,
		"shadowTls":{"password":"pw","serverName":"www.apple.com"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if st := cfg.GetShadowTls(); st == nil || st.Password != "pw" || st.ServerName != "www.apple.com" {
		t.Fatalf("shadowTls 应原样带上: %+v", st)
	}
	if cfg, err := buildSnellClient(t, `{"address":"1.2.3.4","port":443,"psk":"p","version":4}`); err != nil || cfg.GetShadowTls() != nil {
		t.Fatalf("不配 shadowTls 时不应带上: %v %+v", err, cfg)
	}
	for name, raw := range map[string]string{
		"v6":        `{"address":"1.2.3.4","port":1,"psk":"p","version":6,"shadowTls":{"password":"pw","serverName":"a.com"}}`,
		"obfs":      `{"address":"1.2.3.4","port":1,"psk":"p","version":5,"obfsMode":"http","shadowTls":{"password":"pw","serverName":"a.com"}}`,
		"no-pass":   `{"address":"1.2.3.4","port":1,"psk":"p","version":5,"shadowTls":{"serverName":"a.com"}}`,
		"no-name":   `{"address":"1.2.3.4","port":1,"psk":"p","version":5,"shadowTls":{"password":"pw"}}`,
		"with-port": `{"address":"1.2.3.4","port":1,"psk":"p","version":5,"shadowTls":{"password":"pw","serverName":"a.com:443"}}`,
	} {
		if _, err := buildSnellClient(t, raw); err == nil || !strings.Contains(err.Error(), "shadowTls") {
			t.Errorf("%s 应被拒绝,得到 %v", name, err)
		}
	}
}
