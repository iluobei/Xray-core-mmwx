package mieru

import "testing"

// #673:HANDSHAKE_NO_WAIT 的客户端手上还没有应用数据时,会先发一个 payload 为空的
// openSessionRequest,把 socks5 请求放进随后的第一个 data 段。服务端原先假定
// socks5 请求一定在 openSessionRequest 里,解析失败就静默丢掉整条会话 ——
// 客户端于是永远等不到 socks5 回复(mihomo 日志:failed to read socks5 response: TIMEOUT)。
//
// 能把「还没到齐」和「压根不是 socks5」分开,是让服务端敢继续攒字节的前提:
// 前者继续等,后者立刻丢。分不开就只能二选一 —— 要么丢掉合法会话(现在这个 bug),
// 要么给乱发数据的连接无限攒下去。
func TestParseSocks5DistinguishesIncompleteFromInvalid(t *testing.T) {
	full := []byte{0x05, 0x01, 0x00, 0x03, 0x0f}
	full = append(full, []byte("www.gstatic.com")...)
	full = append(full, 0x01, 0xbb) // 443

	// 逐字节截断:每一个前缀都必须报“不完整”,而不是“非法”
	for n := 0; n < len(full); n++ {
		_, _, _, err := parseSocks5Request(full[:n])
		if err != errSocks5Incomplete {
			t.Errorf("前 %d 字节 err = %v, want errSocks5Incomplete —— "+
				"被判成非法的话服务端会丢掉这条本来合法的会话", n, err)
		}
	}

	// 完整则应解析成功
	dest, cmd, consumed, err := parseSocks5Request(full)
	if err != nil {
		t.Fatalf("完整请求解析失败: %v", err)
	}
	if cmd != socks5CmdConnect {
		t.Errorf("cmd = %d, want CONNECT", cmd)
	}
	if got := dest.String(); got != "tcp:www.gstatic.com:443" {
		t.Errorf("dest = %q", got)
	}
	if consumed != len(full) {
		t.Errorf("consumed = %d, want %d", consumed, len(full))
	}

	// 后面跟着应用数据时,consumed 要正好停在 socks5 头结束处
	withData := append(append([]byte(nil), full...), 0x16, 0x03, 0x01)
	_, _, consumed2, err := parseSocks5Request(withData)
	if err != nil || consumed2 != len(full) {
		t.Errorf("带初始数据: consumed = %d err = %v, want %d/nil", consumed2, err, len(full))
	}
}

// 真正非法的东西必须立刻被判死,不能挂在“不完整”上让服务端一直攒。
func TestParseSocks5RejectsInvalid(t *testing.T) {
	cases := map[string][]byte{
		"版本号不对":   {0x04, 0x01, 0x00, 0x03, 0x01, 'a', 0x00, 0x50},
		"atyp 未知": {0x05, 0x01, 0x00, 0x09, 0x01, 0x02, 0x03, 0x04},
		"看着像 TLS": {0x16, 0x03, 0x01, 0x02, 0x00, 0x01},
	}
	for name, b := range cases {
		_, _, _, err := parseSocks5Request(b)
		if err == nil {
			t.Errorf("%s:竟然解析成功了", name)
			continue
		}
		if err == errSocks5Incomplete {
			t.Errorf("%s:被判成“不完整”,服务端会一直攒到上限才放弃", name)
		}
	}
}
