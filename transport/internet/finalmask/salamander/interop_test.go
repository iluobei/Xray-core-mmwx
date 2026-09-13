package salamander

import (
	"encoding/hex"
	"testing"
)

// 与 hysteria2 官方 Salamander 的互通性:用**独立实现**(Python hashlib.blake2b)
// 造的报文,这里必须能原样解出来。
//
// 口径 = 8 字节随机 salt 前缀 + BLAKE2b-256(PSK ‖ salt) 当密钥流 XOR 载荷,
// 报文格式 [salt][payload]。派生顺序(PSK 在前、salt 在后)错了就不互通,
// 而单测自己加解密一轮是发现不了顺序错的 —— 必须拿外部实现对。
func TestSalamanderInteropWithOfficialVector(t *testing.T) {
	const (
		psk       = "mmwx-test-psk"
		packetHex = "0001020304050607791c67057330f846e012dcfed136e5f9982856c51168d6ed86e01e"
		wantPlain = "hello hysteria2 salamander!"
	)
	packet, err := hex.DecodeString(packetHex)
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewSalamanderObfuscator([]byte(psk))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(packet))
	n := o.Deobfuscate(packet, out)
	if n <= 0 {
		t.Fatalf("解不开外部实现造的报文(n=%d)", n)
	}
	if got := string(out[:n]); got != wantPlain {
		t.Fatalf("解出 %q, want %q —— 与官方 salamander 不互通", got, wantPlain)
	}
}
