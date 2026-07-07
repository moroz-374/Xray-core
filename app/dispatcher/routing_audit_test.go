package dispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

func TestDispatchDomainsExcludedSuppressesAuditAndRoutingOverride(t *testing.T) {
	tests := []struct {
		name     string
		excluded []string
		override bool
	}{
		{"exact match", []string{"excluded.example.com"}, false},
		{"anchored regexp match", []string{`regexp:^excluded\.example\.com$`}, false},
		{"unanchored regexp match", []string{`regexp:example\.com`}, false},
		{"exact no match", []string{"other.example.com"}, true},
		{"regexp no match", []string{`regexp:^other\.`}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := net.TCPDestination(net.ParseAddress("203.0.113.20"), 80)
			message, outboundSession := dispatchHTTPWithSniffingRequest(t, original, session.SniffingRequest{
				Enabled:                        true,
				OverrideDestinationForProtocol: []string{"http"},
				ExcludeForDomain:               test.excluded,
				LogSniffedDestination:          true,
			})
			if !test.override {
				if outboundSession.Target != original || outboundSession.RouteTarget.IsValid() {
					t.Fatalf("excluded domain changed routing: target=%v routeTarget=%v", outboundSession.Target, outboundSession.RouteTarget)
				}
				if message.OriginalDestination != nil || message.SniffedProtocol != "" {
					t.Fatalf("excluded domain added audit fields: %+v", message)
				}
				return
			}

			expectedTarget := net.TCPDestination(net.DomainAddress("excluded.example.com"), 80)
			if outboundSession.Target != expectedTarget {
				t.Fatalf("no-match target = %v, want %v", outboundSession.Target, expectedTarget)
			}
			if got, want := message.SniffedProtocol, log.SniffedProtocolHTTP; got != want {
				t.Fatalf("no-match source = %q, want %q", got, want)
			}
		})
	}
}

func TestDispatchMetadataOnlyDoesNotReadHTTPPayloadForAudit(t *testing.T) {
	original := net.TCPDestination(net.ParseAddress("203.0.113.20"), 80)
	message, outboundSession := dispatchHTTPWithSniffingRequest(t, original, session.SniffingRequest{
		Enabled:                        true,
		OverrideDestinationForProtocol: []string{"http"},
		MetadataOnly:                   true,
		LogSniffedDestination:          true,
	})
	if outboundSession.Target != original || outboundSession.RouteTarget.IsValid() {
		t.Fatalf("metadata-only changed routing: target=%v routeTarget=%v", outboundSession.Target, outboundSession.RouteTarget)
	}
	if message.OriginalDestination != nil || message.SniffedProtocol != "" {
		t.Fatalf("metadata-only payload added audit fields: %+v", message)
	}
}

func dispatchHTTPWithSniffingRequest(t *testing.T, original net.Destination, request session.SniffingRequest) (*log.AccessMessage, *session.Outbound) {
	t.Helper()
	handler := &auditOutboundHandler{dispatched: make(chan context.Context, 1)}
	dispatcher := &DefaultDispatcher{ohm: &auditOutboundManager{handler: handler}}
	outboundSession := &session.Outbound{}
	message := &log.AccessMessage{
		From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
		To:     original,
		Status: log.AccessAccepted,
		Email:  "1001",
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outboundSession})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: request})
	ctx = log.ContextWithAccessMessage(ctx, message)
	inbound, err := dispatcher.Dispatch(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(inbound.Reader)
	defer common.Close(inbound.Writer)
	if err := inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("GET / HTTP/1.1\r\nHost: excluded.example.com\r\n\r\n"))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.dispatched:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for routing regression dispatch")
	}
	return message, outboundSession
}
