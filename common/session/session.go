// Package session provides functions for sessions of incoming requests.
package session // import "github.com/xtls/xray-core/common/session"

import (
	"context"
	"math/rand"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
)

// NewID generates a new ID. The generated ID is high likely to be unique, but not cryptographically secure.
// The generated ID will never be 0.
func NewID() c.ID {
	for {
		id := c.ID(rand.Uint32())
		if id != 0 {
			return id
		}
	}
}

// ExportIDToError transfers session.ID into an error object, for logging purpose.
// This can be used with error.WriteToLog().
func ExportIDToError(ctx context.Context) errors.ExportOption {
	id := c.IDFromContext(ctx)
	return func(h *errors.ExportOptionHolder) {
		h.SessionID = uint32(id)
	}
}

// Inbound is the metadata of an inbound connection.
type Inbound struct {
	// Source address of the inbound connection.
	Source net.Destination
	// Local address of the inbound connection.
	Local net.Destination
	// Gateway address.
	Gateway net.Destination
	// Tag of the inbound proxy that handles the connection.
	Tag string
	// Name of the inbound proxy that handles the connection.
	Name string
	// User is the user that authenticates for the inbound. May be nil if the protocol allows anonymous traffic.
	User *protocol.MemoryUser
	// VlessRoute is the user-sent VLESS UUID's 7th<<8 | 8th bytes.
	VlessRoute net.Port
	// Used by splice copy. Conn is actually internet.Connection. May be nil.
	Conn net.Conn
	// Used by splice copy. Timer of the inbound buf copier. May be nil.
	Timer *signal.ActivityTimer
	// CanSpliceCopy is a property for this connection
	// 1 = can, 2 = after processing protocol info should be able to, 3 = cannot
	CanSpliceCopy int
	// SpliceFramer 非 nil 时,splice 直通按「段」进行,每段之前先问它。见 SpliceFramer。
	SpliceFramer SpliceFramer
}

// SpliceFramer 让「同一条连接上先后跑很多条流」的入站也能用 splice 直通。
//
// 普通的直通是出站把目标连接一路搬到入站连接上、直到结束,入站没有机会在连接上划出流的边界,
// 连接只能用完即弃。入站设了 SpliceFramer 之后,出站改成一段一段地搬:每段之前先告诉入站这一段
// 有多少字节,由入站在连接上写出自己的分段头;目标读完后入站还能接着在这条连接上写别的。
type SpliceFramer interface {
	// Handoff 在出站第一次直接写入站连接之前调用。closeLink 关掉出站往 link 写数据的那一端;
	// 入站应当先调用它,再把 link 里剩下的数据全部写上线,然后返回。此后直到 Finish,入站不得再写连接。
	Handoff(closeLink func()) error
	// Segment 在出站直接往入站连接写 n 个字节(n > 0)之前调用。返回 false 表示入站不要了(这条流被中止):
	// 出站不再写,直通到此为止。
	Segment(n int64) (ok bool, err error)
	// Written 在 Segment 声明的那一段写完之后调用。入站要中止时靠它知道「现在不在段中间」——
	// 段写到一半时把源连接关掉,这一段就永远补不齐了。
	Written()
	// Finish 在直通结束时调用。err 为 nil 表示每一段都按声明的字节数写完了(目标读完、入站叫停,或者在两段之间出的错)——
	// 连接上的分段是完整的,入站可以接着用;否则某一段没写完,连接上的字节数已经对不上分段头。
	Finish(err error)
}

// Outbound is the metadata of an outbound connection.
type Outbound struct {
	// Target address of the outbound connection.
	OriginalTarget net.Destination
	Target         net.Destination
	RouteTarget    net.Destination
	// Gateway address
	Gateway net.Address
	// Tag of the outbound proxy that handles the connection.
	Tag string
	// Name of the outbound proxy that handles the connection.
	Name string
	// Unused. Conn is actually internet.Connection. May be nil. It is currently nil for outbound with proxySettings
	Conn net.Conn
	// CanSpliceCopy is a property for this connection
	// 1 = can, 2 = after processing protocol info should be able to, 3 = cannot
	CanSpliceCopy int
}

// SniffingRequest controls the behavior of content sniffing. They are from inbound config. Read-only
type SniffingRequest struct {
	ExcludeForDomain               []string
	OverrideDestinationForProtocol []string
	Enabled                        bool
	MetadataOnly                   bool
	RouteOnly                      bool
}

// Content is the metadata of the connection content. Mainly used for routing.
type Content struct {
	// Protocol of current content.
	Protocol string

	SniffingRequest SniffingRequest

	// HTTP traffic sniffed headers
	Attributes map[string]string

	// SkipDNSResolve is set from DNS module. the DOH remote server maybe a domain name, this prevents cycle resolving dead loop
	SkipDNSResolve bool
}

// Sockopt is the settings for socket connection.
type Sockopt struct {
	// Mark of the socket connection.
	Mark int32
}

// SetAttribute attaches additional string attributes to content.
func (c *Content) SetAttribute(name string, value string) {
	if c.Attributes == nil {
		c.Attributes = make(map[string]string)
	}
	c.Attributes[name] = value
}

// Attribute retrieves additional string attributes from content.
func (c *Content) Attribute(name string) string {
	if c.Attributes == nil {
		return ""
	}
	return c.Attributes[name]
}
