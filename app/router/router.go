package router

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
)

// Router is an implementation of routing.Router.
type Router struct {
	domainStrategy Config_DomainStrategy
	// rules 用 copy-on-write 发布。
	//
	// pickRouteInternal 每条连接都要遍历它,而 ReloadRules / RemoveRule 会在运行期整份换掉。
	// 原先读侧不持锁、写侧持 mu 原地改同一个 slice —— 读到半截的 slice header 就是数据竞争。
	// 之所以一直没炸,只是因为**从来没有人在运行期改过路由规则**(agent 一律重启进程)。
	// 现在写侧在锁内构造一份全新的 slice、一次性 Store,读侧 Load 一份快照遍历:
	// 读侧零锁、零阻塞,换规则对在跑的连接不可见。
	rules     atomic.Pointer[[]*Rule]
	balancers map[string]*Balancer
	dns       dns.Client

	ctx        context.Context
	ohm        outbound.Manager
	dispatcher routing.Dispatcher
	mu         sync.Mutex
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
	ruleTag           string
}

// ruleSnapshot 取当前发布的规则快照。返回的 slice 是只读的,调用方绝不能就地改。
func (r *Router) ruleSnapshot() []*Rule {
	if p := r.rules.Load(); p != nil {
		return *p
	}
	return nil
}

// storeRules 发布一份新的规则集。只能在持有 r.mu 时调用。
func (r *Router) storeRules(rules []*Rule) {
	r.rules.Store(&rules)
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	r.domainStrategy = config.DomainStrategy
	r.dns = d
	r.ctx = ctx
	r.ohm = ohm
	r.dispatcher = dispatcher

	r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
	for _, rule := range config.BalancingRule {
		balancer, err := rule.Build(ohm, dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(ctx)
		r.balancers[rule.Tag] = balancer
	}

	rules := make([]*Rule, 0, len(config.Rule))
	// 出错时要关掉**本次已经建出来的**通知器,不能用 r.closeWebhooks()(那读的是已发布的快照,
	// 此刻还是空的),否则每条失败路径都漏一个 webhook。
	closeBuilt := func() {
		for _, rr := range rules {
			if rr.Webhook != nil {
				rr.Webhook.Close()
			}
		}
	}
	for _, rule := range config.Rule {
		cond, err := rule.BuildCondition()
		if err != nil {
			closeBuilt()
			return err
		}
		rr := &Rule{
			Condition: cond,
			Tag:       rule.GetTag(),
			RuleTag:   rule.GetRuleTag(),
		}
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				closeBuilt()
				return err
			}
			rr.Webhook = notifier
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				if rr.Webhook != nil {
					rr.Webhook.Close()
				}
				closeBuilt()
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
		}
		rules = append(rules, rr)
	}
	r.storeRules(rules)

	return nil
}

// PickRoute implements routing.Router.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	originalCtx := ctx
	rule, ctx, err := r.pickRouteInternal(ctx)
	if err != nil {
		return nil, err
	}
	tag, err := rule.GetTag()
	if err != nil {
		return nil, err
	}
	if rule.Webhook != nil {
		rule.Webhook.Fire(originalCtx, tag)
	}
	return &Route{Context: ctx, outboundTag: tag, ruleTag: rule.RuleTag}, nil
}

// AddRule implements routing.Router.
func (r *Router) AddRule(config *serial.TypedMessage, shouldAppend bool) error {

	inst, err := config.GetInstance()
	if err != nil {
		return err
	}
	if c, ok := inst.(*Config); ok {
		return r.ReloadRules(c, shouldAppend)
	}
	return errors.New("AddRule: config type error")
}

func (r *Router) ReloadRules(config *Config, shouldAppend bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 全程在本地 newRules 上构造,成功才一次性发布;任何一条失败都直接返回,
	// 已发布的那份规则原样不动 —— 读侧永远看不到"改了一半"的状态。
	var newRules []*Rule
	if !shouldAppend {
		for _, rule := range r.ruleSnapshot() {
			if rule.Webhook != nil {
				rule.Webhook.Close()
			}
		}
		r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
		newRules = make([]*Rule, 0, len(config.Rule))
	} else {
		newRules = append([]*Rule(nil), r.ruleSnapshot()...)
	}
	for _, rule := range config.BalancingRule {
		_, found := r.balancers[rule.Tag]
		if found {
			return errors.New("duplicate balancer tag")
		}
		balancer, err := rule.Build(r.ohm, r.dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(r.ctx)
		r.balancers[rule.Tag] = balancer
	}

	startIdx := len(newRules)
	closeNewWebhooks := func() {
		for i := startIdx; i < len(newRules); i++ {
			if newRules[i].Webhook != nil {
				newRules[i].Webhook.Close()
			}
		}
		newRules = newRules[:startIdx]
	}
	// 重名检查要对着**正在构造的**这份查,不能查已发布的快照:append 模式下本次新加的
	// 规则还没发布,查快照会漏掉"同一批里自己跟自己重名"。
	ruleTagTaken := func(tag string) bool {
		if tag == "" {
			return false
		}
		for _, rule := range newRules {
			if rule.RuleTag == tag {
				return true
			}
		}
		return false
	}

	for _, rule := range config.Rule {
		if ruleTagTaken(rule.GetRuleTag()) {
			closeNewWebhooks()
			return errors.New("duplicate ruleTag ", rule.GetRuleTag())
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			closeNewWebhooks()
			return err
		}
		rr := &Rule{
			Condition: cond,
			Tag:       rule.GetTag(),
			RuleTag:   rule.GetRuleTag(),
		}
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				closeNewWebhooks()
				return err
			}
			rr.Webhook = notifier
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				if rr.Webhook != nil {
					rr.Webhook.Close()
				}
				closeNewWebhooks()
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
		}
		newRules = append(newRules, rr)
	}
	r.storeRules(newRules)

	return nil
}

func (r *Router) RuleExists(tag string) bool {
	if tag != "" {
		for _, rule := range r.ruleSnapshot() {
			if rule.RuleTag == tag {
				return true
			}
		}
	}
	return false
}

// RemoveRule implements routing.Router.
func (r *Router) RemoveRule(tag string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	newRules := []*Rule{}
	if tag != "" {
		for _, rule := range r.ruleSnapshot() {
			if rule.RuleTag != tag {
				newRules = append(newRules, rule)
			} else if rule.Webhook != nil {
				rule.Webhook.Close()
			}
		}
		r.storeRules(newRules)
		return nil
	}
	return errors.New("empty tag name!")

}

// ListRule implements routing.Router
func (r *Router) ListRule() []routing.Route {
	r.mu.Lock()
	defer r.mu.Unlock()
	ruleList := make([]routing.Route, 0)
	for _, rule := range r.ruleSnapshot() {
		ruleList = append(ruleList, &Route{
			outboundTag: rule.Tag,
			ruleTag:     rule.RuleTag,
		})
	}
	return ruleList
}

func (r *Router) pickRouteInternal(ctx routing.Context) (*Rule, routing.Context, error) {
	// SkipDNSResolve is set from DNS module.
	// the DOH remote server maybe a domain name,
	// this prevents cycle resolving dead loop
	skipDNSResolve := ctx.GetSkipDNSResolve()

	if r.domainStrategy == Config_IpOnDemand && !skipDNSResolve {
		ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)
	}

	rules := r.ruleSnapshot()
	for _, rule := range rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	if r.domainStrategy != Config_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 || skipDNSResolve {
		return nil, ctx, common.ErrNoClue
	}

	ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)

	// Try applying rules again if we have IPs。用上面取的同一份快照:
	// 两趟必须看同一组规则,中途被换掉会出现"第一趟没匹配、第二趟规则已经变了"。
	for _, rule := range rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	return nil, ctx, common.ErrNoClue
}

// Start implements common.Runnable.
func (r *Router) Start() error {
	return nil
}

// closeWebhooks closes all webhook notifiers in the current rule set.
func (r *Router) closeWebhooks() {
	for _, rule := range r.ruleSnapshot() {
		if rule.Webhook != nil {
			rule.Webhook.Close()
		}
	}
}

// Close implements common.Closable.
func (r *Router) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeWebhooks()
	return nil
}

// Type implements common.HasType.
func (*Router) Type() interface{} {
	return routing.RouterType()
}

// GetOutboundGroupTags implements routing.Route.
func (r *Route) GetOutboundGroupTags() []string {
	return r.outboundGroupTags
}

// GetOutboundTag implements routing.Route.
func (r *Route) GetOutboundTag() string {
	return r.outboundTag
}

func (r *Route) GetRuleTag() string {
	return r.ruleTag
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Router)
		if err := core.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
			return r.Init(ctx, config.(*Config), d, ohm, dispatcher)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}
