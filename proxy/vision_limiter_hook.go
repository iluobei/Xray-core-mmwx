package proxy

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// VisionLimiterFunc 是 vision splice 触发时的 conn-wrap 钩子。
// 触发时机:VisionReader.ReadMultiBuffer / VisionWriter.WriteMultiBuffer 切换到 directCopy 那一刻,
// xray-core 调 UnwrapRawConn 拿到底层 net.Conn 后会调本钩子;
// 实现方(mmw-agent)可以根据 email 查 per-user rate limiter,把 rawConn 包一层 throttling conn 返回。
//
// 钩子返回 nil 或返回 rawConn 本身 → vision 走原路径(零拷贝、不限速)。
// 返回新 conn → vision 后续 raw IO 全部经过该 conn,逃不掉 user-space 节流。
//
// 这个钩子只对启用 xtls-rprx-vision 的连接生效,且只作用于 vless 入站面向客户端的那条连接
// (见 maybeWrapVisionConn 的 clientSide);其他协议的限速仍走 mmw-agent dispatcher 标准 RateWriter 路径。
type VisionLimiterFunc func(email string, rawConn net.Conn) net.Conn

var visionLimiterHook VisionLimiterFunc

// SetVisionLimiterHook 安装 vision splice 时的 conn wrap 钩子。覆盖式注册,nil 表示卸载。
//
// xray:api:beta
func SetVisionLimiterHook(fn VisionLimiterFunc) { visionLimiterHook = fn }

// maybeWrapVisionConn 在 ctx 能解出 user.Email 且 hook 已注册时,把 rawConn 包成限速 conn;
// 否则原样返回。
//
// clientSide:rawConn 是否是面向客户端的那条连接(vless 入站侧:VisionReader 且 isUplink、
// 或 VisionWriter 且 !isUplink)。只有这一侧才包。出站侧(vless-vision 出站连落地/路由出站)
// 的 Vision 读写器拿到的 ctx 里同样带着入站用户的 email,过去也会被包 —— 于是任何非 vision
// 入站(WG、无 flow 的 VLESS、HY2……)经 vision 出站出去时,dispatcher 的 RateWriter 和
// 这里用的是同一个 bucket,同一份流量被扣两次,实际速率只剩限速值的一半;vision 入站接
// vision 出站同样双扣。入站侧本身的 vision 连接由入站侧这一次包装负责,不受影响。
func maybeWrapVisionConn(ctx context.Context, conn net.Conn, clientSide bool) net.Conn {
	if visionLimiterHook == nil || conn == nil || !clientSide {
		return conn
	}
	inb := session.InboundFromContext(ctx)
	if inb == nil || inb.User == nil || inb.User.Email == "" {
		return conn
	}
	if wrapped := visionLimiterHook(inb.User.Email, conn); wrapped != nil {
		return wrapped
	}
	return conn
}
