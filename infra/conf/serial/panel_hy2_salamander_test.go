package serial

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 面板为「HY2 + salamander」生成的配置,fork 必须能原样解析。
//
// salamander 不在 hysteriaSettings 里(HysteriaConfig 只有 version/auth/congestion/
// up/down/udphop),而是 streamSettings.finalmask.udp[] 这一层。schema 写错了面板不会报错,
// 是 agent 起 xray 的时候才炸 —— 所以让 core 自己解析一遍,别靠读代码判断。
func TestPanelHysteria2SalamanderConfigParses(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	if _, err := LoadJSONConfig(strings.NewReader(panelHy2Config(certFile, keyFile, "s3cret"))); err != nil {
		t.Fatalf("fork 拒绝了面板生成的配置: %v", err)
	}
}

// 不配 salamander 的 HY2 也要照常能解析(别把可选项做成必填)。
func TestPanelHysteria2WithoutSalamanderStillParses(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	if _, err := LoadJSONConfig(strings.NewReader(panelHy2Config(certFile, keyFile, ""))); err != nil {
		t.Fatalf("没配 salamander 的 HY2 也被拒了: %v", err)
	}
}

func panelHy2Config(certFile, keyFile, salamanderPwd string) string {
	finalMask := ""
	if salamanderPwd != "" {
		finalMask = fmt.Sprintf(`,
      "finalmask": { "udp": [{ "type": "salamander", "settings": { "password": %q } }] }`, salamanderPwd)
	}
	return fmt.Sprintf(`{
  "inbounds": [{
    "tag": "hy2-in",
    "port": 443,
    "protocol": "hysteria",
    "settings": { "version": 2, "clients": [{ "auth": "user-pass", "email": "u@x" }] },
    "streamSettings": {
      "network": "hysteria",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{ "certificateFile": %q, "keyFile": %q }],
        "alpn": ["h3"],
        "serverName": "example.com"
      },
      "hysteriaSettings": { "version": 2 }%s
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}`, certFile, keyFile, finalMask)
}

func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
