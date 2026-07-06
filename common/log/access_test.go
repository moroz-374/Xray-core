package log_test

import (
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
)

func TestAccessMessageLegacyFormat(t *testing.T) {
	tests := []struct {
		name     string
		message  log.AccessMessage
		expected string
	}{
		{
			name: "accepted",
			message: log.AccessMessage{
				From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				To:     net.TCPDestination(net.ParseAddress("203.0.113.20"), 443),
				Status: log.AccessAccepted,
			},
			expected: "from tcp:198.51.100.10:50000 accepted tcp:203.0.113.20:443",
		},
		{
			name: "accepted with detour and email",
			message: log.AccessMessage{
				From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				To:     net.UDPDestination(net.ParseAddress("203.0.113.20"), 443),
				Status: log.AccessAccepted,
				Detour: "vless-in >> direct",
				Email:  "1001",
			},
			expected: "from tcp:198.51.100.10:50000 accepted udp:203.0.113.20:443 [vless-in >> direct] email: 1001",
		},
		{
			name: "accepted with email only",
			message: log.AccessMessage{
				From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				To:     net.TCPDestination(net.DomainAddress("example.com"), 443),
				Status: log.AccessAccepted,
				Email:  "alice@example.com",
			},
			expected: "from tcp:198.51.100.10:50000 accepted tcp:example.com:443 email: alice@example.com",
		},
		{
			name: "accepted field order",
			message: log.AccessMessage{
				From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				To:     net.TCPDestination(net.DomainAddress("example.com"), 443),
				Status: log.AccessAccepted,
				Detour: "http-in >> direct",
				Reason: "policy note",
				Email:  "alice@example.com",
			},
			expected: "from tcp:198.51.100.10:50000 accepted tcp:example.com:443 [http-in >> direct] policy note email: alice@example.com",
		},
		{
			name: "rejected with reason",
			message: log.AccessMessage{
				From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				Status: log.AccessRejected,
				Reason: errors.New("invalid request"),
			},
			expected: "from tcp:198.51.100.10:50000 rejected  invalid request",
		},
		{
			name:     "zero value",
			message:  log.AccessMessage{},
			expected: "from   ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := test.message.String(); actual != test.expected {
				t.Fatalf("unexpected access message\nexpected: %q\nactual:   %q", test.expected, actual)
			}
		})
	}
}

func TestAccessMessageExtendedFormat(t *testing.T) {
	tests := []struct {
		name     string
		to       net.Destination
		original net.Destination
		protocol log.SniffedProtocol
		expected string
	}{
		{
			name:     "tcp ipv4 original",
			to:       net.TCPDestination(net.DomainAddress("example.com"), 443),
			original: net.TCPDestination(net.ParseAddress("203.0.113.20"), 443),
			protocol: log.SniffedProtocolTLS,
			expected: "from tcp:198.51.100.10:50000 accepted tcp:example.com:443 [vless-in >> direct] email: 1001 original: tcp:203.0.113.20:443 sniffed: tls",
		},
		{
			name:     "tcp ipv6 original",
			to:       net.TCPDestination(net.DomainAddress("example.com"), 80),
			original: net.TCPDestination(net.ParseAddress("2001:db8::20"), 80),
			protocol: log.SniffedProtocolHTTP,
			expected: "from tcp:198.51.100.10:50000 accepted tcp:example.com:80 [vless-in >> direct] email: 1001 original: tcp:[2001:db8::20]:80 sniffed: http",
		},
		{
			name:     "udp domain original",
			to:       net.UDPDestination(net.DomainAddress("example.com"), 443),
			original: net.UDPDestination(net.DomainAddress("origin.example"), 443),
			protocol: log.SniffedProtocolQUIC,
			expected: "from tcp:198.51.100.10:50000 accepted udp:example.com:443 [vless-in >> direct] email: 1001 original: udp:origin.example:443 sniffed: quic",
		},
		{
			name:     "udp ipv4 original",
			to:       net.UDPDestination(net.DomainAddress("example.com"), 443),
			original: net.UDPDestination(net.ParseAddress("203.0.113.20"), 443),
			protocol: log.SniffedProtocolFakeDNS,
			expected: "from tcp:198.51.100.10:50000 accepted udp:example.com:443 [vless-in >> direct] email: 1001 original: udp:203.0.113.20:443 sniffed: fakedns",
		},
		{
			name:     "udp ipv6 fakedns original",
			to:       net.UDPDestination(net.DomainAddress("example.com"), 443),
			original: net.UDPDestination(net.ParseAddress("2001:db8::20"), 443),
			protocol: log.SniffedProtocolFakeDNSOthers,
			expected: "from tcp:198.51.100.10:50000 accepted udp:example.com:443 [vless-in >> direct] email: 1001 original: udp:[2001:db8::20]:443 sniffed: fakedns+others",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := log.AccessMessage{
				From:                net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				To:                  test.to,
				Status:              log.AccessAccepted,
				Detour:              "vless-in >> direct",
				Email:               "1001",
				OriginalDestination: test.original,
				SniffedProtocol:     test.protocol,
			}

			if actual := message.String(); actual != test.expected {
				t.Fatalf("unexpected access message\nexpected: %q\nactual:   %q", test.expected, actual)
			}
		})
	}
}

func TestAccessMessageExtendedFormatWithoutOptionalLegacyFields(t *testing.T) {
	message := log.AccessMessage{
		From:                net.UDPDestination(net.ParseAddress("198.51.100.10"), 50000),
		To:                  net.UDPDestination(net.DomainAddress("example.com"), 443),
		Status:              log.AccessAccepted,
		OriginalDestination: net.UDPDestination(net.ParseAddress("203.0.113.20"), 443),
		SniffedProtocol:     log.SniffedProtocolQUIC,
	}
	expected := "from udp:198.51.100.10:50000 accepted udp:example.com:443 original: udp:203.0.113.20:443 sniffed: quic"
	if actual := message.String(); actual != expected {
		t.Fatalf("unexpected access message\nexpected: %q\nactual:   %q", expected, actual)
	}
}

func TestAccessMessageExtendedFieldsAreAtomic(t *testing.T) {
	base := log.AccessMessage{
		From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
		To:     net.TCPDestination(net.ParseAddress("203.0.113.20"), 443),
		Status: log.AccessAccepted,
		Email:  "1001",
	}
	expected := base.String()

	withOriginalOnly := base
	withOriginalOnly.OriginalDestination = net.TCPDestination(net.ParseAddress("203.0.113.20"), 443)
	if actual := withOriginalOnly.String(); actual != expected {
		t.Fatalf("original-only field changed legacy output: %q", actual)
	}

	withProtocolOnly := base
	withProtocolOnly.SniffedProtocol = log.SniffedProtocolTLS
	if actual := withProtocolOnly.String(); actual != expected {
		t.Fatalf("protocol-only field changed legacy output: %q", actual)
	}
}
