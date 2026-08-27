package singbridge

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common/bufio"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
)

func CopyConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, serverConn net.Conn) error {
	conn := &PipeConnWrapper{
		W:    link.Writer,
		Conn: inboundConn,
	}
	if ir, ok := link.Reader.(io.Reader); ok {
		conn.R = ir
	} else {
		conn.R = &buf.BufferedReader{Reader: link.Reader}
	}
	return ReturnError(bufio.CopyConn(ctx, conn, serverConn))
}

type PipeConnWrapper struct {
	R io.Reader
	W buf.Writer
	net.Conn
}

// Close 必须真的把 link 两端拆掉。
//
// 原实现返回 nil 什么都不做,于是 sing 的 CopyConn 在一个方向出错时调的
// common.Close(source) 完全落空 —— 另一个方向仍卡在下面 Read 里那个
// 硬编码 300s 超时上,inbound worker 的 ctx 也就跟着 300s 不 cancel。
func (w *PipeConnWrapper) Close() error {
	common.Interrupt(w.R)
	common.Close(w.W)
	return nil
}

// CloseWrite 上行方向读完(客户端不再发数据)时被 sing 的 CopyConn 调到,
// 必须把 link.Writer 关掉,出站才知道请求已发完、进而对目标 CloseWrite,
// 目标关闭连接后下行才拿得到 EOF。
//
// 不实现它的后果不是"少个优化":PipeConnWrapper 只嵌了 net.Conn(客户端连接),
// sing 的 N.CloseWrite 会解包到客户端连接的写端 —— 关的是**反方向**,link 毫发无损。
// 于是下行 Read 干等满 300s,期间 ctx 不 cancel,依赖 ctx 释放的连接数计数
// (dispatcher 里的 context.AfterFunc → ReleaseConn)整整滞后 5 分钟:
// 面板连接数虚高,用户的并发连接上限被已关闭的连接占着,短连接一密集就被误判超限。
func (w *PipeConnWrapper) CloseWrite() error {
	return common.Close(w.W)
}

// This Read implemented a timeout to avoid goroutine leak.
// as a temporarily solution
func (w *PipeConnWrapper) Read(b []byte) (n int, err error) {
	type readResult struct {
		n   int
		err error
	}
	c := make(chan readResult, 1)
	go func() {
		n, err := w.R.Read(b)
		c <- readResult{n: n, err: err}
	}()
	select {
	case result := <-c:
		return result.n, result.err
	case <-time.After(300 * time.Second):
		common.Close(w.R)
		common.Interrupt(w.R)
		return 0, buf.ErrReadTimeout
	}
}

func (w *PipeConnWrapper) Write(p []byte) (n int, err error) {
	n = len(p)
	var mb buf.MultiBuffer
	pLen := len(p)
	for pLen > 0 {
		buffer := buf.New()
		if pLen > buf.Size {
			_, err = buffer.Write(p[:buf.Size])
			p = p[buf.Size:]
		} else {
			buffer.Write(p)
		}
		pLen -= int(buffer.Len())
		mb = append(mb, buffer)
	}
	err = w.W.WriteMultiBuffer(mb)
	if err != nil {
		n = 0
		buf.ReleaseMulti(mb)
	}
	return
}
