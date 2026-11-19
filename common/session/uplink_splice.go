package session

import (
	gonet "net"
	"sync"
)

// UplinkSplice 让分段直通的入站(Miu)把上行的裸段直接 splice 到目标连接,不经 link —— 下行 SpliceFramer 的反方向。
//
// 下行是出站一路搬目标连接,入站在段之间写自己的分段头;上行反过来:入站在读自己的连接时认出一段不用再看的字节,
// 直接搬进目标连接。三方各管一段:
//
//   - 入站在 Dispatch 之前放一个空的 UplinkSplice 进自己那份 Inbound。
//   - dispatcher 判断这条连接的上行可以绕过 link 时装上 Account(用户统计、审计这些挂在 link 上的计数)
//     与 Gate(限速,语义同 Inbound.SpliceGate)并把 Enabled 置真;绕不过去(限速只能在 link 上做)就留着 Enabled = false。
//     官方语义的 dispatcher 不认识它,Enabled 就一直是 false,入站照旧走 link。
//   - 出站(freedom)直接写一个裸 TCP 目标时用 SetTarget 登记目标,每把 link 里的数据写进目标就报 Wrote,
//     不再写(上行结束、出错、流被取消)时 Close。
//
// 入站每段之前用 Wait 等出站把排在前面、已经交给 link 的字节全部写进目标:那时出站闲着(link 里没有新数据,
// 新数据只能来自入站自己),splice 就是目标上唯一的写者,上行字节的顺序不会乱。搬完用 Spliced 记下,
// 让之后的 Wait 把这些字节也算进「已经在目标里」。
type UplinkSplice struct {
	// Enabled 由 dispatcher 置真:这条连接的上行可以绕过 link。
	Enabled bool
	// Account 记下绕过 link 的字节(nil = 不用记)。
	Account func(n int64)
	// Gate 非 nil 时每段之前调用:参数是想搬的字节数,返回允许搬的字节数(<= 0 = 不搬了,入站改走 link)。
	Gate func(n int64) int64

	mu       sync.Mutex
	changed  chan struct{} // 每次 written / closed 变了就关掉换新的,Wait 借它醒
	target   *gonet.TCPConn
	counter  interface{ Add(int64) int64 }
	activity func()
	written  int64
	closed   bool
}

func (u *UplinkSplice) notify() {
	if u.changed != nil {
		close(u.changed)
		u.changed = nil
	}
}

// SetTarget 由出站在开始写目标之前调用。counter 是出站连接的写计数(splice 绕过了它,入站手工记),
// activity 是出站的活动计时器(上行只走 splice 时出站自己看不到数据,不喂它的话一次长上传会被当成空闲断掉)。
func (u *UplinkSplice) SetTarget(target *gonet.TCPConn, counter interface{ Add(int64) int64 }, activity func()) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return
	}
	u.target, u.counter, u.activity = target, counter, activity
	u.notify()
}

// Target 返回登记的目标;出站还没登记或已经 Close 时返回 nil。
func (u *UplinkSplice) Target() (target *gonet.TCPConn, counter interface{ Add(int64) int64 }, activity func()) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil, nil, nil
	}
	return u.target, u.counter, u.activity
}

// Wrote 由出站在把 link 里的 n 个字节写进目标之后调用。
func (u *UplinkSplice) Wrote(n int64) {
	u.mu.Lock()
	u.written += n
	u.notify()
	u.mu.Unlock()
}

// Spliced 由入站在直接搬进目标 n 个字节之后调用。
func (u *UplinkSplice) Spliced(n int64) { u.Wrote(n) }

// Close 由出站在不再写目标时调用:之后 Target 返回 nil,等着的 Wait 返回 false。
func (u *UplinkSplice) Close() {
	u.mu.Lock()
	u.closed = true
	u.notify()
	u.mu.Unlock()
}

// Wait 等到目标里已经有 n 个上行字节(出站写的加上入站 splice 的),返回 true;出站先 Close 了或 cancel 先关了
// 返回 false。入站传进来的 n 是它交给 link 的与它自己 splice 的字节总数。
func (u *UplinkSplice) Wait(n int64, cancel <-chan struct{}) bool {
	for {
		u.mu.Lock()
		if u.closed {
			u.mu.Unlock()
			return false
		}
		if u.written >= n {
			u.mu.Unlock()
			return true
		}
		if u.changed == nil {
			u.changed = make(chan struct{})
		}
		ch := u.changed
		u.mu.Unlock()
		select {
		case <-ch:
		case <-cancel:
			return false
		}
	}
}
