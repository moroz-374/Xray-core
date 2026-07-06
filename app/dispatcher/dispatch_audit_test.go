package dispatcher

import (
	"context"
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
