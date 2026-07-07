package dispatcher

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dns/fakedns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

func TestDispatchFakeDNSHitIPv4AndIPv6(t *testing.T) {
	engine := newAuditFakeDNS(t, 4)
	for _, test := range []struct {
		name string
		ipv4 bool
	}{
		{"ipv4", true},
		{"ipv6", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			addresses := engine.GetFakeIPForDomain3("mapped.example.com", test.ipv4, !test.ipv4)
			if len(addresses) != 1 {
				t.Fatalf("fake address count = %d", len(addresses))
			}
			original := net.TCPDestination(addresses[0], 443)
			message, outboundSession := dispatchFakeDNSPayload(t, engine, original, "1001", nil, false)
			expectedTarget := net.TCPDestination(net.DomainAddress("mapped.example.com"), 443)
			if outboundSession.OriginalTarget != original || outboundSession.Target != expectedTarget {
				t.Fatalf("unexpected targets: original=%v target=%v", outboundSession.OriginalTarget, outboundSession.Target)
			}
			expected := "from tcp:198.51.100.10:50000 accepted tcp:mapped.example.com:443 [direct] email: 1001 original: " + original.String() + " sniffed: fakedns"
			if got := message.String(); got != expected {
				t.Fatalf("access message = %q, want %q", got, expected)
			}
		})
	}
}

func TestDispatchFakeDNSMissFallsBackToTLSAndQUIC(t *testing.T) {
	engine := newAuditFakeDNS(t, 4)
	tests := []struct {
		name     string
		original net.Destination
		payload  func(*testing.T) []byte
		domain   string
	}{
		{"ipv4 tls fallback", net.TCPDestination(net.ParseAddress("198.18.0.250"), 443), func(t *testing.T) []byte { return captureTLSClientHello(t, "tls.example.com") }, "tls.example.com"},
		{"ipv6 quic fallback", net.UDPDestination(net.ParseAddress("fd00::fa"), 443), validQUICInitial, "www.google.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, outboundSession := dispatchFakeDNSPayload(t, engine, test.original, "1001", test.payload(t), false)
			expectedTarget := test.original
			expectedTarget.Address = net.DomainAddress(test.domain)
			if outboundSession.OriginalTarget != test.original || outboundSession.Target != expectedTarget {
				t.Fatalf("unexpected targets: original=%v target=%v", outboundSession.OriginalTarget, outboundSession.Target)
			}
			expected := "from " + sourceForNetwork(test.original.Network).String() + " accepted " + expectedTarget.String() + " [direct] email: 1001 original: " + test.original.String() + " sniffed: fakedns+others"
			if got := message.String(); got != expected {
				t.Fatalf("access message = %q, want %q", got, expected)
			}
		})
	}
}

func TestDispatchFakeDNSLRUMissStaysOriginal(t *testing.T) {
	engine := newAuditFakeDNS(t, 1)
	oldAddress := engine.GetFakeIPForDomain3("evicted.example.com", true, false)[0]
	for i := 0; i < 10 && engine.GetDomainFromFakeDNS(oldAddress) != ""; i++ {
		time.Sleep(time.Millisecond)
		engine.GetFakeIPForDomain3(fmt.Sprintf("replacement-%d.example.com", i), true, false)
	}
	if got := engine.GetDomainFromFakeDNS(oldAddress); got != "" {
		t.Fatalf("mapping was not evicted: %q", got)
	}

	original := net.UDPDestination(oldAddress, 443)
	message, outboundSession := dispatchFakeDNSPayload(t, engine, original, "1001", []byte{0x00, 0x01, 0x02}, false)
	if outboundSession.OriginalTarget != original || outboundSession.Target != original || outboundSession.RouteTarget.IsValid() {
		t.Fatalf("LRU miss changed routing: original=%v target=%v routeTarget=%v", outboundSession.OriginalTarget, outboundSession.Target, outboundSession.RouteTarget)
	}
	if message.OriginalDestination != nil || message.SniffedProtocol != "" {
		t.Fatalf("LRU miss added audit fields: %+v", message)
	}
}

func newAuditFakeDNS(t *testing.T, lruSize int64) *fakedns.HolderMulti {
	t.Helper()
	engine, err := fakedns.NewFakeDNSHolderMulti(&fakedns.FakeDnsPoolMulti{Pools: []*fakedns.FakeDnsPool{
		{IpPool: "198.18.0.0/24", LruSize: lruSize},
		{IpPool: "fd00::/120", LruSize: lruSize},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

func TestDispatchFakeDNSMetadataOnlyHit(t *testing.T) {
	engine := newAuditFakeDNS(t, 4)
	fakeAddress := engine.GetFakeIPForDomain3("metadata.example.com", true, false)[0]
	original := net.TCPDestination(fakeAddress, 443)
	message, outboundSession := dispatchFakeDNSPayload(t, engine, original, "1001", nil, true)
	expectedTarget := net.TCPDestination(net.DomainAddress("metadata.example.com"), 443)
	if outboundSession.Target != expectedTarget || message.SniffedProtocol != log.SniffedProtocolFakeDNS {
		t.Fatalf("metadata-only FakeDNS hit: target=%v source=%q", outboundSession.Target, message.SniffedProtocol)
	}
}

func dispatchFakeDNSPayload(t *testing.T, engine *fakedns.HolderMulti, original net.Destination, email string, payload []byte, metadataOnly bool) (*log.AccessMessage, *session.Outbound) {
	t.Helper()
	handler := &auditOutboundHandler{dispatched: make(chan context.Context, 1)}
	dispatcher := &DefaultDispatcher{ohm: &auditOutboundManager{handler: handler}, fdns: engine}
	outboundSession := &session.Outbound{}
	message := &log.AccessMessage{From: sourceForNetwork(original.Network), To: original, Status: log.AccessAccepted, Email: email}
	instance := &core.Instance{}
	if err := instance.AddFeature(engine); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outboundSession})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
		Enabled:                        true,
		OverrideDestinationForProtocol: []string{"fakedns"},
		MetadataOnly:                   metadataOnly,
		LogSniffedDestination:          true,
	}})
	ctx = log.ContextWithAccessMessage(ctx, message)

	inbound, err := dispatcher.Dispatch(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(inbound.Reader)
	defer common.Close(inbound.Writer)
	if len(payload) > 0 {
		if err := inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
			t.Fatal(err)
		}
		common.Close(inbound.Writer)
	}
	select {
	case <-handler.dispatched:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for FakeDNS dispatch")
	}
	return message, outboundSession
}

func sourceForNetwork(network net.Network) net.Destination {
	if network == net.Network_UDP {
		return net.UDPDestination(net.ParseAddress("198.51.100.10"), 50000)
	}
	return net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000)
}
