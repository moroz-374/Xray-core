package dispatcher

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func auditContext(enabled, logSniffed bool, message *log.AccessMessage) context.Context {
	ctx := session.ContextWithContent(context.Background(), &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:               enabled,
			LogSniffedDestination: logSniffed,
		},
	})
	if message != nil {
		ctx = log.ContextWithAccessMessage(ctx, message)
	}
	return ctx
}

func TestUpdateAuditDestination(t *testing.T) {
	original := net.TCPDestination(net.ParseAddress("203.0.113.20"), 443)
	sniffed := net.TCPDestination(net.DomainAddress("EXAMPLE.COM."), 443)
	message := &log.AccessMessage{Status: log.AccessAccepted, To: original}

	updateAuditDestination(auditContext(true, true, message), original, sniffed, "tls")

	if got, want := message.To.(net.Destination).String(), "tcp:example.com:443"; got != want {
		t.Fatalf("destination = %q, want %q", got, want)
	}
	if got, want := message.OriginalDestination.String(), original.String(); got != want {
		t.Fatalf("original destination = %q, want %q", got, want)
	}
	if got, want := message.SniffedProtocol, log.SniffedProtocolTLS; got != want {
		t.Fatalf("sniffed protocol = %q, want %q", got, want)
	}
}

func TestUpdateAuditDestinationNoOp(t *testing.T) {
	original := net.UDPDestination(net.ParseAddress("2001:db8::20"), 443)
	validSniffed := net.UDPDestination(net.DomainAddress("example.com"), 443)

	tests := []struct {
		name     string
		ctx      func(*log.AccessMessage) context.Context
		sniffed  net.Destination
		protocol string
	}{
		{"disabled sniffing", func(m *log.AccessMessage) context.Context { return auditContext(false, true, m) }, validSniffed, "quic"},
		{"disabled audit option", func(m *log.AccessMessage) context.Context { return auditContext(true, false, m) }, validSniffed, "quic"},
		{"missing content", func(m *log.AccessMessage) context.Context {
			return log.ContextWithAccessMessage(context.Background(), m)
		}, validSniffed, "quic"},
		{"missing access message", func(*log.AccessMessage) context.Context { return auditContext(true, true, nil) }, validSniffed, "quic"},
		{"rejected access message", func(m *log.AccessMessage) context.Context {
			m.Status = log.AccessRejected
			return auditContext(true, true, m)
		}, validSniffed, "quic"},
		{"IP sniff result", func(m *log.AccessMessage) context.Context { return auditContext(true, true, m) }, net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), "quic"},
		{"mismatched network", func(m *log.AccessMessage) context.Context { return auditContext(true, true, m) }, net.TCPDestination(net.DomainAddress("example.com"), 443), "quic"},
		{"mismatched port", func(m *log.AccessMessage) context.Context { return auditContext(true, true, m) }, net.UDPDestination(net.DomainAddress("example.com"), 8443), "quic"},
		{"non-domain protocol", func(m *log.AccessMessage) context.Context { return auditContext(true, true, m) }, validSniffed, "bittorrent"},
		{"invalid domain", func(m *log.AccessMessage) context.Context { return auditContext(true, true, m) }, net.UDPDestination(net.DomainAddress("bad domain"), 443), "quic"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := &log.AccessMessage{Status: log.AccessAccepted, To: original}
			updateAuditDestination(test.ctx(message), original, test.sniffed, test.protocol)
			if got := message.To.(net.Destination); got != original {
				t.Fatalf("destination changed to %v", got)
			}
			if message.OriginalDestination != nil || message.SniffedProtocol != "" {
				t.Fatalf("audit fields changed: original=%v protocol=%q", message.OriginalDestination, message.SniffedProtocol)
			}
		})
	}
}

func TestNormalizeAuditDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{"EXAMPLE.COM.", "example.com", true},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", true},
		{"localhost", "localhost", true},
		{"", "", false},
		{"example.com..", "", false},
		{"-example.com", "", false},
		{"example-.com", "", false},
		{"example..com", "", false},
		{"example_underscore.com", "", false},
		{"example com", "", false},
		{"bücher.example", "", false},
		{string(make([]byte, 64)) + ".com", "", false},
	}

	for _, test := range tests {
		if got, ok := normalizeAuditDomain(test.input); got != test.want || ok != test.ok {
			t.Errorf("normalizeAuditDomain(%q) = (%q, %v), want (%q, %v)", test.input, got, ok, test.want, test.ok)
		}
	}
}

func TestAuditSniffedProtocolCanonicalizesHTTP(t *testing.T) {
	for _, protocol := range []string{"http", "http1", "http2"} {
		if got, ok := auditSniffedProtocol(protocol); !ok || got != log.SniffedProtocolHTTP {
			t.Errorf("auditSniffedProtocol(%q) = (%q, %v)", protocol, got, ok)
		}
	}
}
