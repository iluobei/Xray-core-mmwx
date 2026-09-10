package proxy

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// 用户实报「用户网速超出服务器带宽十几倍」。真机定位:agent 每 3 秒采样一次 per-user
// 计数器算速度,而 splice 路径固定 8MiB 才记一次账 —— 一条 300KB/s 的连接 27 秒才涨
// 一次计数器,采样看到的是「0,0,0,…,8MiB」,除以 3 秒就是 5.8MB/s。
// 治本:段大小按实测速率自适应,让记账间隔与速度无关地稳定在半秒左右。

func TestNextSpliceChunkIsClampedProportional(t *testing.T) {
	const MiB = 1 << 20
	cases := []struct {
		name string
		cur  int64
		n    int64
		took time.Duration
		want int64
	}{
		// 正好命中目标(500ms):保持不变
		{"命中目标", 1 * MiB, 1 * MiB, 500 * time.Millisecond, 1 * MiB},
		// 段太快(250ms,速率翻倍):按比例想 ×2,正好落在单步上限
		{"太快则增大", 1 * MiB, 1 * MiB, 250 * time.Millisecond, 2 * MiB},
		// 段太慢(1s,速率减半):按比例想 ÷2
		{"太慢则缩小", 1 * MiB, 1 * MiB, time.Second, 512 << 10},
		// **关键**:缓冲区瞬时尖峰(60ms 搬完 → 速率 ×8.3),单步只能翻倍,
		// 不会一步跳到 8MiB 上限再阻塞几十秒
		{"瞬时尖峰被夹住", 1 * MiB, 1 * MiB, 60 * time.Millisecond, 2 * MiB},
		// 极慢一段(速率暴跌):单步只能减半,不会瞬间掉到下限
		{"暴跌被夹住", 1 * MiB, 1 * MiB, 30 * time.Second, 512 << 10},
		// 增大不越过绝对上限
		{"不越上限", spliceAccountChunk, spliceAccountChunk, 100 * time.Millisecond, spliceAccountChunk},
		// 缩小不越过绝对下限
		{"不越下限", spliceAccountChunkMin, spliceAccountChunkMin, 10 * time.Second, spliceAccountChunkMin},
		// 信息不足:沿用当前值
		{"n=0 沿用", 3 * MiB, 0, time.Second, 3 * MiB},
		{"took=0 沿用", 3 * MiB, 1 * MiB, 0, 3 * MiB},
	}
	for _, c := range cases {
		got := nextSpliceChunk(c.cur, c.n, c.took)
		if got != c.want {
			t.Errorf("%s: nextSpliceChunk(%d, %d, %v) = %d, want %d", c.name, c.cur, c.n, c.took, got, c.want)
		}
	}
}

// 控制器必须能从一次瞬时尖峰后自我校正,几段之内回到稳态。
// 这是与第一版的本质区别:第一版一次尖峰就把段顶到 8MiB 再阻塞几十秒。
func TestChunkRecoversFromSpikeWithinFewSteps(t *testing.T) {
	const steadyRate = 300 << 10 // 300 KB/s
	chunk := int64(spliceAccountChunkInit)
	// 先跑一次瞬时尖峰(缓冲区一次性吐出大量数据)
	chunk = nextSpliceChunk(chunk, 8<<20, 60*time.Millisecond)
	// 之后每段都按真实 300KB/s 结算,看多少步回到「段耗时接近 500ms」
	settled := -1
	for step := 0; step < 8; step++ {
		took := time.Duration(float64(chunk) / float64(steadyRate) * float64(time.Second))
		if took >= 350*time.Millisecond && took <= 650*time.Millisecond {
			settled = step
			break
		}
		chunk = nextSpliceChunk(chunk, chunk, took)
	}
	if settled < 0 {
		t.Errorf("8 步内没回到 350~650ms 的记账间隔 —— 控制器收敛太慢")
	} else {
		t.Logf("尖峰后 %d 步回到稳态记账间隔 ✅", settled)
	}
}

// 记账间隔必须与速度无关:一条 ~2MB/s 的连接,固定 8MiB 段要 4 秒才记第一笔账,
// 自适应后应该半秒一笔。这条测试跑的就是生产用的 spliceCopyAccounted。
//
// net.Pipe 是同步管道,读端跟着写端的节奏走 —— 写端按 32ms 一片 64KiB 限速,
// 读端看到的就是一条 2MB/s 的"连接"。
func TestSpliceAccountingCadenceIsSpeedIndependent(t *testing.T) {
	srv, cli := net.Pipe()
	dstR, dstW := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, dstR) }()

	var calls atomic.Int64
	var counted atomic.Int64
	done := make(chan error, 1)
	go func() {
		done <- spliceCopyAccounted(dstW, srv, func(n int64) {
			calls.Add(1)
			counted.Add(n)
		})
	}()

	// 写端:64KiB / 32ms ≈ 2MB/s,持续 3 秒,连接不关
	const slice = 64 << 10
	buf := make([]byte, slice)
	var written int64
	stop := time.After(3 * time.Second)
	tick := time.NewTicker(32 * time.Millisecond)
	defer tick.Stop()
writeLoop:
	for {
		select {
		case <-stop:
			break writeLoop
		case <-tick.C:
			if _, err := cli.Write(buf); err != nil {
				t.Fatalf("写入失败: %v", err)
			}
			written += slice
		}
	}

	// 3 秒内至少记了 4 笔账(半秒一笔的话应有 ~6 笔;固定 8MiB 段这里是 0 笔)
	if got := calls.Load(); got < 4 {
		t.Errorf("3 秒内只记了 %d 笔账,期望 ≥ 4 —— 记账间隔没有随速度自适应,"+
			"agent 采样到的还是「长期为 0、偶尔一大坨」", got)
	}
	// 账目滞后不能超过一段:已写 written,已记 counted,差值应小于当前段大小的量级。
	// 2MB/s 下自适应段约 1MiB,放宽到 2MiB。
	if lag := written - counted.Load(); lag > 2<<20 {
		t.Errorf("账目滞后 %d 字节(已写 %d,已记 %d),期望 < 2MiB", lag, written, counted.Load())
	}
	t.Logf("3 秒内记账 %d 笔,已写 %d 已记 %d,滞后 %d", calls.Load(), written, counted.Load(), written-counted.Load())

	cli.Close()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Errorf("连接正常结束应返回 io.EOF,实得 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("关闭连接后 spliceCopyAccounted 没有退出")
	}
}
