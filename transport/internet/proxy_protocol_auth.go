package internet

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/ppauth"
)

// proxyProtocolAuthFor 配了 trusted_proxy_protocol_auth_keys 时返回验签钩子,否则 nil。
//
// 只用于「可信来源」模式(转发链出口):老语义的 accept_proxy_protocol 不验签,行为不变;只认 TOA 的出口
// 本来就把所有头读掉忽略,验不验都一样。
//
// 签名不对时**不断连接**:把头的命令改成 LOCAL,go-proxyproto 的 RemoteAddr / LocalAddr 遇到 LOCAL 头
// 就回到连接本身的地址 —— 等于把这个头当成没有。连接仍是 *proxyproto.Conn,splice、REALITY 那几处
// 按这个类型取底层连接的代码不受影响。
func proxyProtocolAuthFor(sockopt *SocketConfig) proxyproto.Validator {
	if sockopt == nil || sockopt.AcceptProxyProtocol || sockopt.TrustedProxyProtocolToaOnly {
		return nil
	}
	v := ppauth.NewVerifier(sockopt.TrustedProxyProtocolAuthContext, ppauth.ParseKeys(sockopt.TrustedProxyProtocolAuthKeys))
	if v == nil {
		return nil
	}
	var lastLog atomic.Int64
	return func(h *proxyproto.Header) error {
		if h == nil || h.Command.IsLocal() {
			return nil
		}
		if err := v.Verify(h); err != nil {
			h.Command = proxyproto.LOCAL
			// 日志一分钟最多一条
			now := time.Now().Unix()
			if last := lastLog.Load(); now-last >= 60 && lastLog.CompareAndSwap(last, now) {
				errors.LogWarning(context.Background(), "PROXY header ignored (", sockopt.TrustedProxyProtocolAuthContext, "): ", err)
			}
		}
		return nil
	}
}
