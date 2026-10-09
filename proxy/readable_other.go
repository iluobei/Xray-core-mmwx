//go:build !(linux || darwin)

package proxy

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// 分段直通只在 Linux / Android 上启用(见 CopyRawConnIfExist),别的平台走不到这里。
func readableBytes(net.Conn) (int64, error) {
	return 0, errors.New("readableBytes: unsupported platform")
}
