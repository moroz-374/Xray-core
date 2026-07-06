package dispatcher

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// updateAuditDestination records an accepted, domain-bearing sniff result in
// the contextual access message. Routing and outbound session state are not
// read or changed here.
func updateAuditDestination(ctx context.Context, original, sniffed net.Destination, protocol string) {
	content := session.ContentFromContext(ctx)
	if content == nil || !content.SniffingRequest.Enabled || !content.SniffingRequest.LogSniffedDestination {
		return
	}

	accessMessage := log.AccessMessageFromContext(ctx)
	if accessMessage == nil || accessMessage.Status != log.AccessAccepted {
		return
	}

	if !original.IsValid() || original.Address == nil || original.Port == 0 ||
		!sniffed.IsValid() || sniffed.Address == nil || !sniffed.Address.Family().IsDomain() ||
		sniffed.Network != original.Network || sniffed.Port != original.Port {
		return
	}

	domain, ok := normalizeAuditDomain(sniffed.Address.Domain())
	if !ok {
		return
	}

	source, ok := auditSniffedProtocol(protocol)
	if !ok {
		return
	}

	sniffed.Address = net.DomainAddress(domain)
	accessMessage.To = sniffed
	accessMessage.OriginalDestination = original
	accessMessage.SniffedProtocol = source
}

func normalizeAuditDomain(domain string) (string, bool) {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	if len(domain) == 0 || len(domain) > 253 {
		return "", false
	}

	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}

	return domain, true
}

func auditSniffedProtocol(protocol string) (log.SniffedProtocol, bool) {
	switch protocol {
	case string(log.SniffedProtocolHTTP):
		return log.SniffedProtocolHTTP, true
	case string(log.SniffedProtocolTLS):
		return log.SniffedProtocolTLS, true
	case string(log.SniffedProtocolQUIC):
		return log.SniffedProtocolQUIC, true
	case string(log.SniffedProtocolFakeDNS):
		return log.SniffedProtocolFakeDNS, true
	case string(log.SniffedProtocolFakeDNSOthers):
		return log.SniffedProtocolFakeDNSOthers, true
	default:
		return "", false
	}
}
