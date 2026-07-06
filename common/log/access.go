package log

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/serial"
)

type logKey int

const (
	accessMessageKey logKey = iota
)

type AccessStatus string

const (
	AccessAccepted = AccessStatus("accepted")
	AccessRejected = AccessStatus("rejected")
)

// AccessDestination is a typed destination that can be included in an access
// message without coupling the log package to common/net.
type AccessDestination interface {
	String() string
}

// SniffedProtocol identifies the domain-bearing sniffer result used for an
// extended access message.
type SniffedProtocol string

const (
	SniffedProtocolHTTP          SniffedProtocol = "http"
	SniffedProtocolTLS           SniffedProtocol = "tls"
	SniffedProtocolQUIC          SniffedProtocol = "quic"
	SniffedProtocolFakeDNS       SniffedProtocol = "fakedns"
	SniffedProtocolFakeDNSOthers SniffedProtocol = "fakedns+others"
)

type AccessMessage struct {
	From                interface{}
	To                  interface{}
	Status              AccessStatus
	Reason              interface{}
	Email               string
	Detour              string
	OriginalDestination AccessDestination
	SniffedProtocol     SniffedProtocol
}

func (m *AccessMessage) String() string {
	builder := strings.Builder{}
	builder.WriteString("from")
	builder.WriteByte(' ')
	builder.WriteString(serial.ToString(m.From))
	builder.WriteByte(' ')
	builder.WriteString(string(m.Status))
	builder.WriteByte(' ')
	builder.WriteString(serial.ToString(m.To))

	if len(m.Detour) > 0 {
		builder.WriteString(" [")
		builder.WriteString(m.Detour)
		builder.WriteByte(']')
	}

	if reason := serial.ToString(m.Reason); len(reason) > 0 {
		builder.WriteString(" ")
		builder.WriteString(reason)
	}

	if len(m.Email) > 0 {
		builder.WriteString(" email: ")
		builder.WriteString(m.Email)
	}

	if m.OriginalDestination != nil && len(m.SniffedProtocol) > 0 {
		builder.WriteString(" original: ")
		builder.WriteString(m.OriginalDestination.String())
		builder.WriteString(" sniffed: ")
		builder.WriteString(string(m.SniffedProtocol))
	}

	return builder.String()
}

func ContextWithAccessMessage(ctx context.Context, accessMessage *AccessMessage) context.Context {
	return context.WithValue(ctx, accessMessageKey, accessMessage)
}

func AccessMessageFromContext(ctx context.Context) *AccessMessage {
	if accessMessage, ok := ctx.Value(accessMessageKey).(*AccessMessage); ok {
		return accessMessage
	}
	return nil
}
