package proxy

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// splice 分段记账:验证「长连接进行中就能看到字节数」,而不是等连接结束才一次性入账。
// 这里不依赖真正的 splice syscall(darwin 上没有),只验证 io.CopyN 分段循环的记账语义。
func TestSpliceChunkedAccounting(t *testing.T) {
	srv, cli := net.Pipe()
	dstR, dstW := net.Pipe()

	var counted atomic.Int64
	// 模拟 CopyRawConnIfExist 里的分段循环
	go func() {
		for {
			n, err := io.CopyN(dstW, srv, spliceAccountChunk)
			if n > 0 {
				counted.Add(n)
			}
			if err != nil {
				return
			}
		}
	}()
	// 排空目的端
	go func() { io.Copy(io.Discard, dstR) }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1<<20)
		// 写 3 个 chunk 的量,但**不关闭连接**
		for written := int64(0); written < 3*spliceAccountChunk; written += int64(len(buf)) {
			if _, err := cli.Write(buf); err != nil {
				return
			}
		}
	}()
	wg.Wait()

	// 连接仍然开着 —— 此时就应该已经记到至少 2 个 chunk
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if counted.Load() >= 2*spliceAccountChunk {
			t.Logf("连接进行中已记账 %d 字节(%d 个 chunk),连接尚未关闭 ✅",
				counted.Load(), counted.Load()/spliceAccountChunk)
			cli.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cli.Close()
	t.Fatalf("连接进行中只记到 %d 字节,期望 >= %d —— 分段记账没生效", counted.Load(), 2*spliceAccountChunk)
}
