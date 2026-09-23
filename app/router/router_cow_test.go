package router

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// 运行期换路由规则时,判定路径不能读到"改了一半"的规则集。
//
// 以前 rules 是普通 slice:pickRouteInternal(每条连接都走)不持锁地 range 它,
// 而 ReloadRules / RemoveRule 持锁原地改同一个 slice。之所以一直没炸,只是因为
// **agent 从来不在运行期改路由,一律重启整个 xray 进程** —— 一旦开始用 AddRule
// 热更新路由,这就是货真价实的数据竞争(-race 下必报)。
//
// 这条测试带 -race 跑才验得出竞争;不带 -race 时它仍然验证:并发读写不 panic,
// 且每次判定读到的都是某一次完整发布的规则集(要么命中 a,要么命中 b,不会两边都不是)。
func TestRouterRulesAreRaceFreeUnderReload(t *testing.T) {
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		Rule: []*RoutingRule{ruleForDomain("direct", "a.example.com")},
	}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	var (
		wg      sync.WaitGroup
		stop    atomic.Bool
		reloads atomic.Int64
		reads   atomic.Int64
		bad     atomic.Int64
	)

	// 写侧:不停整份替换规则集。两种形状交替,但 a.example.com 那条始终在 ——
	// 所以读侧任何一次判定都必须命中它。命不中就说明读到了残缺的规则集。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			cfg := &Config{Rule: []*RoutingRule{ruleForDomain("direct", "a.example.com")}}
			if i%2 == 1 {
				cfg.Rule = append(cfg.Rule, ruleForDomain("proxy", "b.example.com"))
			}
			if err := r.ReloadRules(cfg, false); err != nil {
				t.Errorf("ReloadRules: %v", err)
				return
			}
			reloads.Add(1)
		}
	}()

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
					Target: net.TCPDestination(net.DomainAddress("a.example.com"), 80),
				}})
				route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
				if err != nil || route.GetOutboundTag() != "direct" {
					bad.Add(1)
				}
				reads.Add(1)
			}
		}()
	}

	for reloads.Load() < 300 || reads.Load() < 300 {
		if stop.Load() {
			break
		}
	}
	stop.Store(true)
	wg.Wait()

	if reloads.Load() == 0 || reads.Load() == 0 {
		t.Fatalf("并发压力没跑起来: reloads=%d reads=%d", reloads.Load(), reads.Load())
	}
	if bad.Load() != 0 {
		t.Fatalf("%d/%d 次判定读到了残缺的规则集(始终存在的那条规则没命中)", bad.Load(), reads.Load())
	}
}

// 换规则的两趟判定必须看同一份快照:第一趟没命中、第二趟规则已经被换掉,
// 会把"本该走 direct"的连接判成无规则可用。
func TestRouterReloadDoesNotLoseAlwaysPresentRule(t *testing.T) {
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		Rule: []*RoutingRule{ruleForDomain("direct", "a.example.com")},
	}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	// 整份换成两条,原来那条仍在。
	if err := r.ReloadRules(&Config{Rule: []*RoutingRule{
		ruleForDomain("direct", "a.example.com"),
		ruleForDomain("proxy", "b.example.com"),
	}}, false); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ domain, want string }{
		{"a.example.com", "direct"},
		{"b.example.com", "proxy"},
	} {
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.DomainAddress(tc.domain), 80),
		}})
		route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
		if err != nil {
			t.Fatalf("%s: %v", tc.domain, err)
		}
		if got := route.GetOutboundTag(); got != tc.want {
			t.Fatalf("%s: 命中 %q,期望 %q", tc.domain, got, tc.want)
		}
	}
}

func ruleForDomain(tag, domain string) *RoutingRule {
	return &RoutingRule{
		TargetTag: &RoutingRule_Tag{Tag: tag},
		Domain:    []*Domain{{Type: Domain_Full, Value: domain}},
	}
}
