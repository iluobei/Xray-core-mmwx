//go:build !(linux || darwin)

package proxy

import (
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// 分段直通只在 Linux / Android 上启用(见 CopyRawConnIfExist),别的平台走不到这里。
func readableBytes(net.Conn) (int64, error) {
	return 0, errors.New("readableBytes: unsupported platform")
}

func readableAtLeast(net.Conn, int64, time.Time) (int64, error) {
	return 0, errors.New("readableAtLeast: unsupported platform")
}

func peekBytes(net.Conn, []byte) (int, error) {
	return 0, errors.New("peekBytes: unsupported platform")
}
