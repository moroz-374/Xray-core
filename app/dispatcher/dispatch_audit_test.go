package dispatcher

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type auditOutboundManager struct {
	handler outbound.Handler
}

func (*auditOutboundManager) Type() interface{}                                  { return outbound.ManagerType() }
func (*auditOutboundManager) Start() error                                       { return nil }
func (*auditOutboundManager) Close() error                                       { return nil }
func (m *auditOutboundManager) GetHandler(string) outbound.Handler               { return nil }
func (m *auditOutboundManager) GetDefaultHandler() outbound.Handler              { return m.handler }
func (*auditOutboundManager) AddHandler(context.Context, outbound.Handler) error { return nil }
func (*auditOutboundManager) RemoveHandler(context.Context, string) error        { return nil }
func (m *auditOutboundManager) ListHandlers(context.Context) []outbound.Handler {
	return []outbound.Handler{m.handler}
}

type auditOutboundHandler struct {
	dispatched chan context.Context
}

func (*auditOutboundHandler) Start() error                         { return nil }
func (*auditOutboundHandler) Close() error                         { return nil }
func (*auditOutboundHandler) Tag() string                          { return "direct" }
func (*auditOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*auditOutboundHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *auditOutboundHandler) Dispatch(ctx context.Context, link *transport.Link) {
	h.dispatched <- ctx
	common.Interrupt(link.Reader)
	common.Close(link.Writer)
}

var _ outbound.Handler = (*auditOutboundHandler)(nil)

func TestDispatchUpdatesAuditDestinationWithoutChangingRoutingBehavior(t *testing.T) {
	for _, routeOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "target override", true: "route-only override"}[routeOnly], func(t *testing.T) {
			handler := &auditOutboundHandler{dispatched: make(chan context.Context, 1)}
			manager := &auditOutboundManager{handler: handler}

			dispatcher := &DefaultDispatcher{ohm: manager}
			original := net.TCPDestination(net.ParseAddress("203.0.113.20"), 80)
			routedSniffed := net.TCPDestination(net.DomainAddress("example.com."), 80)
			outboundSession := &session.Outbound{}
			message := &log.AccessMessage{
				From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				To:     original,
				Status: log.AccessAccepted,
				Email:  "3",
			}
			ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outboundSession})
			ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
				Enabled:                        true,
				OverrideDestinationForProtocol: []string{"http"},
				RouteOnly:                      routeOnly,
				LogSniffedDestination:          true,
			}})
			ctx = log.ContextWithAccessMessage(ctx, message)

			inbound, err := dispatcher.Dispatch(ctx, original)
			if err != nil {
				t.Fatal(err)
			}
			defer common.Interrupt(inbound.Reader)
			defer common.Close(inbound.Writer)
			if err := inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("GET / HTTP/1.1\r\nHost: EXAMPLE.COM.\r\n\r\n"))); err != nil {
				t.Fatal(err)
			}

			select {
			case <-handler.dispatched:
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for asynchronous dispatch")
			}

			if got, want := message.String(), "from tcp:198.51.100.10:50000 accepted tcp:example.com:80 [direct] email: 3 original: tcp:203.0.113.20:80 sniffed: http"; got != want {
				t.Fatalf("access message = %q, want %q", got, want)
			}
			if outboundSession.OriginalTarget != original {
				t.Fatalf("original target = %v, want %v", outboundSession.OriginalTarget, original)
			}
			if routeOnly {
				if outboundSession.Target != original || outboundSession.RouteTarget != routedSniffed {
					t.Fatalf("route-only targets: target=%v routeTarget=%v", outboundSession.Target, outboundSession.RouteTarget)
				}
			} else if outboundSession.Target != routedSniffed || outboundSession.RouteTarget.IsValid() {
				t.Fatalf("override targets: target=%v routeTarget=%v", outboundSession.Target, outboundSession.RouteTarget)
			}
		})
	}
}

func TestDispatchLinkMatchesDispatchAuditBehavior(t *testing.T) {
	for _, routeOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "target override", true: "route-only override"}[routeOnly], func(t *testing.T) {
			handler := &auditOutboundHandler{dispatched: make(chan context.Context, 1)}
			dispatcher := &DefaultDispatcher{ohm: &auditOutboundManager{handler: handler}}
			original := net.TCPDestination(net.ParseAddress("203.0.113.20"), 80)
			routedSniffed := net.TCPDestination(net.DomainAddress("example.com."), 80)
			outboundSession := &session.Outbound{}
			message := &log.AccessMessage{
				From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				To:     original,
				Status: log.AccessAccepted,
				Email:  "3",
			}
			ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outboundSession})
			ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
				Enabled:                        true,
				OverrideDestinationForProtocol: []string{"http"},
				RouteOnly:                      routeOnly,
				LogSniffedDestination:          true,
			}})
			ctx = log.ContextWithAccessMessage(ctx, message)

			reader, writer := pipe.New()
			defer common.Interrupt(reader)
			defer common.Close(writer)
			if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("GET / HTTP/1.1\r\nHost: EXAMPLE.COM.\r\n\r\n"))); err != nil {
				t.Fatal(err)
			}
			link := &transport.Link{Reader: reader, Writer: buf.Discard}
			if err := dispatcher.DispatchLink(ctx, original, link); err != nil {
				t.Fatal(err)
			}

			select {
			case <-handler.dispatched:
			default:
				t.Fatal("synchronous dispatch did not call outbound handler")
			}

			if got, want := message.String(), "from tcp:198.51.100.10:50000 accepted tcp:example.com:80 [direct] email: 3 original: tcp:203.0.113.20:80 sniffed: http"; got != want {
				t.Fatalf("access message = %q, want %q", got, want)
			}
			if outboundSession.OriginalTarget != original {
				t.Fatalf("original target = %v, want %v", outboundSession.OriginalTarget, original)
			}
			if routeOnly {
				if outboundSession.Target != original || outboundSession.RouteTarget != routedSniffed {
					t.Fatalf("route-only targets: target=%v routeTarget=%v", outboundSession.Target, outboundSession.RouteTarget)
				}
			} else if outboundSession.Target != routedSniffed || outboundSession.RouteTarget.IsValid() {
				t.Fatalf("override targets: target=%v routeTarget=%v", outboundSession.Target, outboundSession.RouteTarget)
			}
		})
	}
}

func TestDispatchDefaultOffPreservesLegacyLogAndRouting(t *testing.T) {
	tlsPayload := captureTLSClientHello(t, "tls.example.com")
	quicPayload, err := hex.DecodeString("cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40feb7c1d9ce5e71b")
	if err != nil {
		t.Fatal(err)
	}

	protocols := []struct {
		name           string
		original       net.Destination
		payload        []byte
		override       string
		expectedDomain string
	}{
		{"http", net.TCPDestination(net.ParseAddress("203.0.113.20"), 80), []byte("GET / HTTP/1.1\r\nHost: http.example.com\r\n\r\n"), "http", "http.example.com"},
		{"tls", net.TCPDestination(net.ParseAddress("203.0.113.20"), 443), tlsPayload, "tls", "tls.example.com"},
		{"quic", net.UDPDestination(net.ParseAddress("203.0.113.20"), 443), quicPayload, "quic", "www.google.com"},
	}

	for _, flagState := range []string{"absent", "false"} {
		for _, protocol := range protocols {
			t.Run(flagState+"/"+protocol.name, func(t *testing.T) {
				handler := &auditOutboundHandler{dispatched: make(chan context.Context, 1)}
				dispatcher := &DefaultDispatcher{ohm: &auditOutboundManager{handler: handler}}
				outboundSession := &session.Outbound{}
				message := &log.AccessMessage{
					From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
					To:     protocol.original,
					Status: log.AccessAccepted,
					Email:  "3",
				}
				request := session.SniffingRequest{
					Enabled:                        true,
					OverrideDestinationForProtocol: []string{protocol.override},
				}
				if flagState == "false" {
					request.LogSniffedDestination = false
				}
				content := &session.Content{SniffingRequest: request}
				ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
				ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outboundSession})
				ctx = session.ContextWithContent(ctx, content)
				ctx = log.ContextWithAccessMessage(ctx, message)

				inbound, err := dispatcher.Dispatch(ctx, protocol.original)
				if err != nil {
					t.Fatal(err)
				}
				defer common.Interrupt(inbound.Reader)
				defer common.Close(inbound.Writer)
				if err := inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, protocol.payload)); err != nil {
					t.Fatal(err)
				}
				select {
				case <-handler.dispatched:
				case <-time.After(3 * time.Second):
					t.Fatal("timed out waiting for asynchronous dispatch")
				}

				if content.Protocol == "" {
					t.Fatal("payload was not successfully sniffed")
				}
				expectedTarget := protocol.original
				expectedTarget.Address = net.DomainAddress(protocol.expectedDomain)
				if outboundSession.OriginalTarget != protocol.original || outboundSession.Target != expectedTarget || outboundSession.RouteTarget.IsValid() {
					t.Fatalf("routing changed: original=%v target=%v routeTarget=%v", outboundSession.OriginalTarget, outboundSession.Target, outboundSession.RouteTarget)
				}
				if message.To != protocol.original || message.OriginalDestination != nil || message.SniffedProtocol != "" {
					t.Fatalf("default-off message mutated: %+v", message)
				}
				if got, want := message.String(), "from tcp:198.51.100.10:50000 accepted "+protocol.original.String()+" [direct] email: 3"; got != want {
					t.Fatalf("access message = %q, want %q", got, want)
				}
			})
		}
	}
}

func TestDispatchTCPOptInLogsHTTPAndTLSForAllOriginalAddressFamilies(t *testing.T) {
	tlsPayload := captureTLSClientHello(t, "tls.example.com")
	tests := []struct {
		name     string
		original net.Destination
		payload  []byte
		override string
		domain   string
		source   string
	}{
		{"http original ipv4", net.TCPDestination(net.ParseAddress("203.0.113.20"), 80), []byte("GET / HTTP/1.1\r\nHost: http.example.com\r\n\r\n"), "http", "http.example.com", "http"},
		{"http original ipv6", net.TCPDestination(net.ParseAddress("2001:db8::20"), 80), []byte("GET / HTTP/1.1\r\nHost: http.example.com\r\n\r\n"), "http", "http.example.com", "http"},
		{"tls original ipv4", net.TCPDestination(net.ParseAddress("203.0.113.20"), 443), tlsPayload, "tls", "tls.example.com", "tls"},
		{"tls original ipv6", net.TCPDestination(net.ParseAddress("2001:db8::20"), 443), tlsPayload, "tls", "tls.example.com", "tls"},
		{"tls original domain", net.TCPDestination(net.DomainAddress("origin.example.net"), 443), tlsPayload, "tls", "tls.example.com", "tls"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &auditOutboundHandler{dispatched: make(chan context.Context, 1)}
			dispatcher := &DefaultDispatcher{ohm: &auditOutboundManager{handler: handler}}
			outboundSession := &session.Outbound{}
			message := &log.AccessMessage{
				From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				To:     test.original,
				Status: log.AccessAccepted,
				Email:  "3",
			}
			ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outboundSession})
			ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
				Enabled:                        true,
				OverrideDestinationForProtocol: []string{test.override},
				LogSniffedDestination:          true,
			}})
			ctx = log.ContextWithAccessMessage(ctx, message)

			inbound, err := dispatcher.Dispatch(ctx, test.original)
			if err != nil {
				t.Fatal(err)
			}
			defer common.Interrupt(inbound.Reader)
			defer common.Close(inbound.Writer)
			if err := inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, test.payload)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-handler.dispatched:
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for asynchronous dispatch")
			}

			expectedTarget := test.original
			expectedTarget.Address = net.DomainAddress(test.domain)
			if outboundSession.OriginalTarget != test.original || outboundSession.Target != expectedTarget || outboundSession.RouteTarget.IsValid() {
				t.Fatalf("unexpected routing state: original=%v target=%v routeTarget=%v", outboundSession.OriginalTarget, outboundSession.Target, outboundSession.RouteTarget)
			}
			expected := "from tcp:198.51.100.10:50000 accepted " + expectedTarget.String() + " [direct] email: 3 original: " + test.original.String() + " sniffed: " + test.source
			if got := message.String(); got != expected {
				t.Fatalf("access message = %q, want %q", got, expected)
			}
		})
	}
}

func TestDispatchTCPOptInKeepsOriginalForNoSNIAndIncompleteClientHello(t *testing.T) {
	clientHello := captureTLSClientHello(t, "tls.example.com")
	tests := []struct {
		name    string
		payload []byte
	}{
		{"no sni", captureTLSClientHello(t, "")},
		{"incomplete client hello", clientHello[:20]},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &auditOutboundHandler{dispatched: make(chan context.Context, 1)}
			dispatcher := &DefaultDispatcher{ohm: &auditOutboundManager{handler: handler}}
			original := net.TCPDestination(net.ParseAddress("203.0.113.20"), 443)
			outboundSession := &session.Outbound{}
			message := &log.AccessMessage{
				From:   net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000),
				To:     original,
				Status: log.AccessAccepted,
				Email:  "3",
			}
			ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outboundSession})
			ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
				Enabled:                        true,
				OverrideDestinationForProtocol: []string{"tls"},
				LogSniffedDestination:          true,
			}})
			ctx = log.ContextWithAccessMessage(ctx, message)

			inbound, err := dispatcher.Dispatch(ctx, original)
			if err != nil {
				t.Fatal(err)
			}
			defer common.Interrupt(inbound.Reader)
			if err := inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, test.payload)); err != nil {
				t.Fatal(err)
			}
			common.Close(inbound.Writer)
			select {
			case <-handler.dispatched:
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for asynchronous dispatch")
			}

			if outboundSession.OriginalTarget != original || outboundSession.Target != original || outboundSession.RouteTarget.IsValid() {
				t.Fatalf("unexpected routing state: original=%v target=%v routeTarget=%v", outboundSession.OriginalTarget, outboundSession.Target, outboundSession.RouteTarget)
			}
			if message.OriginalDestination != nil || message.SniffedProtocol != "" {
				t.Fatalf("negative TLS case added audit fields: %+v", message)
			}
			if got, want := message.String(), "from tcp:198.51.100.10:50000 accepted tcp:203.0.113.20:443 [direct] email: 3"; got != want {
				t.Fatalf("access message = %q, want %q", got, want)
			}
		})
	}
}

func TestDispatchUDPQUICOptInAddressFamiliesAndIsolation(t *testing.T) {
	quicPayload := validQUICInitial(t)
	tests := []struct {
		name     string
		original net.Destination
		email    string
	}{
		{"original ipv4 user a", net.UDPDestination(net.ParseAddress("203.0.113.20"), 443), "1001"},
		{"original ipv6 user b", net.UDPDestination(net.ParseAddress("2001:db8::20"), 443), "1002"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			message, outboundSession := dispatchQUICPayload(t, test.original, test.email, quicPayload)
			expectedTarget := net.UDPDestination(net.DomainAddress("www.google.com"), 443)
			if outboundSession.OriginalTarget != test.original || outboundSession.Target != expectedTarget || outboundSession.RouteTarget.IsValid() {
				t.Fatalf("unexpected routing state: original=%v target=%v routeTarget=%v", outboundSession.OriginalTarget, outboundSession.Target, outboundSession.RouteTarget)
			}
			expected := "from udp:198.51.100.10:50000 accepted udp:www.google.com:443 [direct] email: " + test.email + " original: " + test.original.String() + " sniffed: quic"
			if got := message.String(); got != expected {
				t.Fatalf("access message = %q, want %q", got, expected)
			}
		})
	}
}

func TestDispatchUDPQUICInvalidAndNonInitialStayOriginal(t *testing.T) {
	nonInitial, err := hex.DecodeString("53f4144825dab3ba251b83d0089e910210bec1a6507cca92ad9ff539cc21f6c75e3551ca44003d9a")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		payload []byte
	}{
		{"non-initial packet", nonInitial},
		{"unsupported version", []byte{0xc0, 0xff, 0xff, 0xff, 0xff, 0x00}},
		{"malformed packet", []byte{0xc0, 0x00, 0x00}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := net.UDPDestination(net.ParseAddress("203.0.113.20"), 443)
			message, outboundSession := dispatchQUICPayload(t, original, "1001", test.payload)
			if outboundSession.OriginalTarget != original || outboundSession.Target != original || outboundSession.RouteTarget.IsValid() {
				t.Fatalf("invalid QUIC changed routing: original=%v target=%v routeTarget=%v", outboundSession.OriginalTarget, outboundSession.Target, outboundSession.RouteTarget)
			}
			if message.OriginalDestination != nil || message.SniffedProtocol != "" {
				t.Fatalf("invalid QUIC added audit fields: %+v", message)
			}
			if got, want := message.String(), "from udp:198.51.100.10:50000 accepted udp:203.0.113.20:443 [direct] email: 1001"; got != want {
				t.Fatalf("access message = %q, want %q", got, want)
			}
		})
	}
}

func dispatchQUICPayload(t *testing.T, original net.Destination, email string, payload []byte) (*log.AccessMessage, *session.Outbound) {
	t.Helper()
	handler := &auditOutboundHandler{dispatched: make(chan context.Context, 1)}
	dispatcher := &DefaultDispatcher{ohm: &auditOutboundManager{handler: handler}}
	outboundSession := &session.Outbound{}
	message := &log.AccessMessage{
		From:   net.UDPDestination(net.ParseAddress("198.51.100.10"), 50000),
		To:     original,
		Status: log.AccessAccepted,
		Email:  email,
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outboundSession})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
		Enabled:                        true,
		OverrideDestinationForProtocol: []string{"quic"},
		LogSniffedDestination:          true,
	}})
	ctx = log.ContextWithAccessMessage(ctx, message)

	inbound, err := dispatcher.Dispatch(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(inbound.Reader)
	if err := inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
		t.Fatal(err)
	}
	common.Close(inbound.Writer)
	select {
	case <-handler.dispatched:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for QUIC dispatch")
	}
	return message, outboundSession
}

func validQUICInitial(t *testing.T) []byte {
	t.Helper()
	payload, err := hex.DecodeString("cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40feb7c1d9ce5e71b")
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func captureTLSClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	clientConn, serverConn := stdnet.Pipe()
	client := tls.Client(clientConn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec -- test-only capture
	done := make(chan struct{})
	go func() {
		_ = client.Handshake()
		close(done)
	}()
	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4096)
	n, err := serverConn.Read(payload)
	_ = serverConn.Close()
	_ = clientConn.Close()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	return payload[:n]
}
