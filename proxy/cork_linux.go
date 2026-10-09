package proxy

import (
	"io"
	"syscall"

	"golang.org/x/sys/unix"
)

// setCork 塞住 / 放开 w 的发送(TCP_CORK):塞住期间写进去的小块不单独成包,放开时一并发出。
// w 不是 TCP 连接时什么也不做。
func setCork(w io.Writer, on bool) {
	sc, ok := w.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	v := 0
	if on {
		v = 1
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_CORK, v)
	})
}
