//go:build linux || darwin

package proxy

import (
	"io"
	"syscall"
	"time"

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

// readableAtLeast 等到 conn 的接收缓冲里至少有 min 个字节,返回现有的字节数,不取走任何数据。
// deadline 先到时返回 os.ErrDeadlineExceeded;对端已经关闭写方向且缓冲已空时返回 io.EOF。
func readableAtLeast(conn net.Conn, min int64, deadline time.Time) (int64, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.New("readableAtLeast: not a syscall.Conn")
	}
	if !deadline.IsZero() {
		_ = conn.SetReadDeadline(deadline)
		// 必须清掉:过期的读期限会让之后每一次读都立刻失败。
		defer conn.SetReadDeadline(time.Time{})
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int64
	var ferr error
	rerr := rc.Read(func(fd uintptr) bool {
		v, e := unix.IoctlGetInt(int(fd), ioctlReadable)
		switch {
		case e != nil:
			ferr = e
			return true
		case int64(v) >= min:
			n = int64(v)
			return true
		case v > 0:
			return false // 不够,等下一批
		}
		var b [1]byte
		r, _, e := unix.Recvfrom(int(fd), b[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		switch {
		case e == unix.EAGAIN || e == unix.EINTR:
			return false
		case e != nil:
			ferr = e
		case r == 0:
			ferr = io.EOF
		case int64(r) >= min:
			n = int64(r)
		default:
			return false
		}
		return true
	})
	if ferr == nil {
		ferr = rerr
	}
	return n, ferr
}

// peekBytes 把 conn 接收缓冲里等着的字节拷进 p(至多 len(p) 个),不取走。
func peekBytes(conn net.Conn, p []byte) (int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.New("peekBytes: not a syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var ferr error
	rerr := rc.Read(func(fd uintptr) bool {
		r, _, e := unix.Recvfrom(int(fd), p, unix.MSG_PEEK|unix.MSG_DONTWAIT)
		switch {
		case e == unix.EAGAIN || e == unix.EINTR:
			return false
		case e != nil:
			ferr = e
		case r == 0:
			ferr = io.EOF
		default:
			n = r
		}
		return true
	})
	if ferr == nil {
		ferr = rerr
	}
	return n, ferr
}
