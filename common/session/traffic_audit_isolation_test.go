package session_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestTrafficAuditSpecialPathContextsAreIsolated(t *testing.T) {
	tests := []struct {
		path        string
		destination net.Destination
		source      log.SniffedProtocol
	}{
		{"mux tcp ipv4", net.TCPDestination(net.ParseAddress("203.0.113.20"), 443), log.SniffedProtocolTLS},
		{"xudp packet ipv6", net.UDPDestination(net.ParseAddress("2001:db8::20"), 443), log.SniffedProtocolQUIC},
		{"tun system dns", net.UDPDestination(net.ParseAddress("1.1.1.1"), 53), log.SniffedProtocolFakeDNS},
		{"tun fakedns ipv4", net.TCPDestination(net.ParseAddress("198.18.0.20"), 443), log.SniffedProtocolFakeDNS},
		{"wireguard ipv4", net.TCPDestination(net.ParseAddress("10.0.0.2"), 443), log.SniffedProtocolTLS},
		{"wireguard ipv6", net.UDPDestination(net.ParseAddress("fd00::2"), 443), log.SniffedProtocolQUIC},
	}

	baseContent := &session.Content{SniffingRequest: session.SniffingRequest{
		Enabled:               true,
		LogSniffedDestination: true,
	}}
	base := session.ContextWithContent(context.Background(), baseContent)
	base = session.ContextWithOutbounds(base, []*session.Outbound{{Tag: "parent"}})

	type result struct {
		content  *session.Content
		outbound *session.Outbound
		message  *log.AccessMessage
	}
	results := make(chan result, len(tests))
	var wg sync.WaitGroup
	for index, test := range tests {
		wg.Add(1)
		go func(index int, test struct {
			path        string
			destination net.Destination
			source      log.SniffedProtocol
		}) {
			defer wg.Done()
			ctx := session.SubContextFromMuxInbound(base)
			message := &log.AccessMessage{
				To:                  test.destination,
				Status:              log.AccessAccepted,
				Email:               fmt.Sprintf("user-%d", index),
				OriginalDestination: test.destination,
				SniffedProtocol:     test.source,
			}
			ctx = log.ContextWithAccessMessage(ctx, message)
			outbound := session.OutboundsFromContext(ctx)[0]
			outbound.Tag = test.path
			results <- result{session.ContentFromContext(ctx), outbound, log.AccessMessageFromContext(ctx)}
		}(index, test)
	}
	wg.Wait()
	close(results)

	seenContent := map[*session.Content]bool{}
	seenOutbound := map[*session.Outbound]bool{}
	seenMessage := map[*log.AccessMessage]bool{}
	seenEmail := map[string]bool{}
	for result := range results {
		if result.content == baseContent || seenContent[result.content] {
			t.Fatal("content context was shared between special paths")
		}
		if seenOutbound[result.outbound] {
			t.Fatal("outbound state was shared between special paths")
		}
		if seenMessage[result.message] {
			t.Fatal("access message was shared between special paths")
		}
		if seenEmail[result.message.Email] {
			t.Fatalf("identity crossed contexts: %q", result.message.Email)
		}
		if !result.content.SniffingRequest.LogSniffedDestination {
			t.Fatal("audit option was not copied into sub-context")
		}
		seenContent[result.content] = true
		seenOutbound[result.outbound] = true
		seenMessage[result.message] = true
		seenEmail[result.message.Email] = true
	}

	if session.OutboundsFromContext(base)[0].Tag != "parent" || !baseContent.SniffingRequest.LogSniffedDestination {
		t.Fatal("child mutation changed parent context")
	}
}
