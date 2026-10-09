//go:build linux || darwin

package proxy

import (
	"io"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

// readableBytes 等到 conn 可读,返回它的接收缓冲里现有的字节数,不取走任何数据。
// 对端已经关闭写方向(且缓冲已空)时返回 io.EOF。
func readableBytes(conn net.Conn) (int64, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.New("readableBytes: not a syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int64
	var ferr error
	rerr := rc.Read(func(fd uintptr) bool {
		v, e := unix.IoctlGetInt(int(fd), ioctlReadable)
		if e != nil {
			ferr = e
			return true
		}
		if v > 0 {
			n = int64(v)
			return true
		}
		// 缓冲是空的:要么还没来数据(等),要么对端已经关了。
		var b [1]byte
		r, _, e := unix.Recvfrom(int(fd), b[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		switch {
		case e == unix.EAGAIN || e == unix.EINTR:
			return false
		case e != nil:
			ferr = e
		case r == 0:
			ferr = io.EOF
		default:
			n = int64(r) // 刚好在两次调用之间到了数据
		}
		return true
	})
	if ferr == nil {
		ferr = rerr
	}
	return n, ferr
}
