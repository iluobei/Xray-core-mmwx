// guard.go:按来源 IP 的认证失败限频。
//
// 公网上的 SSH 端口一开就会被扫描器成批爆破。防线分三层:
//  1. 每次认证失败都拖一会儿再回(失败越多拖得越久),单条连接上的穷举慢到没有意义;
//  2. 同一 IP 在窗口内失败到阈值就封一段时间,封禁期内新连接在握手前直接关掉(连密钥交换的 CPU 都不花),
//     屡犯翻倍;
//  3. 最近认证成功过的 IP 永不封禁,只吃拖延 —— 一家人共用一个出口 IP、其中一台客户端还拿着旧密码
//     狂重试时,不能把同 IP 下凭据正确的其他人一起封掉。扫描器从来不会成功,不受这条豁免影响。
//
// 日志只在「封禁」这一刻打一行,单次失败只进 debug,不会被扫描器刷屏。
package ssh

import (
	"sync"
	"time"
)

const (
	guardWindow       = 10 * time.Minute // 失败计数窗口
	guardThreshold    = 10               // 窗口内失败这么多次就封
	guardBanBase      = 2 * time.Minute  // 首次封禁时长,之后每次翻倍
	guardBanMax       = time.Hour        // 封禁时长上限
	guardSuccessGrace = 24 * time.Hour   // 这么久内成功过的 IP 不封
	guardSweepEvery   = 5 * time.Minute
)

// 每次失败的拖延步长与上限。是变量只为测试能调成 0。
var (
	guardDelayStep = 250 * time.Millisecond
	guardDelayMax  = 3 * time.Second
)

type ipState struct {
	fails       int
	windowStart time.Time
	bannedUntil time.Time
	bans        int
	lastSuccess time.Time
	lastSeen    time.Time
}

type authGuard struct {
	mu        sync.Mutex
	m         map[string]*ipState
	lastSweep time.Time
	now       func() time.Time // 测试替换
}

func newAuthGuard() *authGuard {
	return &authGuard{m: make(map[string]*ipState), now: time.Now}
}

// allowed 报告该 IP 当前是否允许建连。
func (g *authGuard) allowed(ip string) bool {
	if ip == "" {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.m[ip]
	return st == nil || !g.now().Before(st.bannedUntil)
}

// fail 记一次认证失败,返回本次应拖延的时长,以及这次是否刚触发封禁(调用方据此打一行日志)。
func (g *authGuard) fail(ip string) (delay time.Duration, banned time.Duration) {
	if ip == "" {
		return guardDelayStep, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.sweepLocked(now)
	st := g.m[ip]
	if st == nil {
		st = &ipState{}
		g.m[ip] = st
	}
	st.lastSeen = now
	if now.Sub(st.windowStart) > guardWindow {
		st.windowStart = now
		st.fails = 0
	}
	st.fails++
	delay = time.Duration(st.fails) * guardDelayStep
	if delay > guardDelayMax {
		delay = guardDelayMax
	}
	trusted := !st.lastSuccess.IsZero() && now.Sub(st.lastSuccess) < guardSuccessGrace
	if st.fails >= guardThreshold && !trusted {
		st.bans++
		d := guardBanBase << (st.bans - 1)
		if d > guardBanMax || d <= 0 {
			d = guardBanMax
		}
		st.bannedUntil = now.Add(d)
		st.fails = 0
		st.windowStart = now
		return delay, d
	}
	return delay, 0
}

// success 记一次认证成功:清掉失败计数,并让该 IP 在一段时间内免于封禁。
func (g *authGuard) success(ip string) {
	if ip == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	st := g.m[ip]
	if st == nil {
		st = &ipState{}
		g.m[ip] = st
	}
	st.fails = 0
	st.lastSuccess = now
	st.lastSeen = now
}

// sweepLocked 定期清掉早已过期的条目,免得被大量来源 IP 撑大。
func (g *authGuard) sweepLocked(now time.Time) {
	if now.Sub(g.lastSweep) < guardSweepEvery {
		return
	}
	g.lastSweep = now
	for ip, st := range g.m {
		idle := now.Sub(st.lastSeen)
		keep := guardWindow
		if st.bans > 0 {
			keep = 2 * guardBanMax // 封过的多记一阵,屡犯才翻得了倍
		}
		if now.After(st.bannedUntil) && idle > keep &&
			(st.lastSuccess.IsZero() || now.Sub(st.lastSuccess) > guardSuccessGrace) {
			delete(g.m, ip)
		}
	}
}
