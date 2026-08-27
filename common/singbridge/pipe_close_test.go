package singbridge

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

// 上行读完时,sing 的 CopyConn 会对 source 调 CloseWrite。它必须真的关掉 link.Writer:
// 关不掉的话,出站永远等不到"请求发完"的信号,目标不关连接,下行 Read 就干等满
// 硬编码的 300s —— inbound worker 的 ctx 跟着 300s 不 cancel,依赖 ctx 释放的
// 连接数计数整整滞后 5 分钟(面板虚高 + 并发上限被已关闭的连接占着)。
func TestCloseWriteClosesLinkWriter(t *testing.T) {
	upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
	w := &PipeConnWrapper{W: upWriter, R: nopReader{}}

	if err := w.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := upReader.ReadMultiBuffer()
		done <- err
	}()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("出站侧应立刻读到 EOF,实得 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CloseWrite 没有关掉 link.Writer —— 出站还在等,这正是 300s 卡死的起点")
	}
}

// Close 用于异常路径(一个方向出错时 sing 调 common.Close(source))。
// 它必须把两端都拆掉,否则同样落空。
func TestCloseTearsDownBothEnds(t *testing.T) {
	upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
	downReader, downWriter := pipe.New(pipe.WithoutSizeLimit())
	w := &PipeConnWrapper{W: upWriter, R: &buf.BufferedReader{Reader: downReader}}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := upReader.ReadMultiBuffer(); err == nil {
		t.Fatal("Close 后出站侧仍可读,link.Writer 没被关")
	}
	// 卡住 300s 的正是下行这个 Read,Close 后它必须立刻返回错误。
	_ = downWriter
	done := make(chan error, 1)
	go func() {
		b := make([]byte, 32)
		_, err := w.R.Read(b)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Close 后下行 Read 仍成功返回")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close 没能中断下行 Read —— 300s 卡死依旧")
	}
}

type nopReader struct{}

func (nopReader) Read([]byte) (int, error) { return 0, io.EOF }
