package dispatcher

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestInboundHandlerAuditCompatibilityMatrix(t *testing.T) {
	tests := []struct {
		name         string
		dispatchLink bool
		network      net.Network
		email        string
	}{
		{"vless normal", true, net.Network_TCP, "vless-user"},
		{"trojan tcp", false, net.Network_TCP, "trojan-user"},
		{"vmess normal", false, net.Network_TCP, "vmess-user"},
		{"shadowsocks legacy tcp", false, net.Network_TCP, "shadowsocks-user"},
		{"shadowsocks 2022 single", false, net.Network_TCP, "shadowsocks-2022-user"},
		{"shadowsocks 2022 multi", false, net.Network_TCP, "shadowsocks-2022-multi-user"},
		{"shadowsocks 2022 relay", false, net.Network_TCP, "shadowsocks-2022-relay-user"},
		{"hysteria tcp", true, net.Network_TCP, "hysteria-user"},
		{"hysteria udp", true, net.Network_UDP, "hysteria-user"},
		{"socks tcp identity gap", true, net.Network_TCP, ""},
		{"http connect identity gap", true, net.Network_TCP, ""},
		{"http plain", false, net.Network_TCP, ""},
		{"dokodemo-door", true, net.Network_TCP, ""},
		{"tun flow", true, net.Network_TCP, ""},
		{"wireguard inner flow", true, net.Network_TCP, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, outboundSession := runInboundCompatibilityCase(t, test.dispatchLink, test.network, test.email)
			if message.Email != test.email {
				t.Fatalf("email = %q, want %q", message.Email, test.email)
			}
			if message.OriginalDestination == nil {
				t.Fatal("original destination is missing")
			}
			if test.network == net.Network_UDP {
				if message.SniffedProtocol != log.SniffedProtocolQUIC || outboundSession.Target.Address.Domain() != "www.google.com" {
					t.Fatalf("UDP audit mismatch: source=%q target=%v", message.SniffedProtocol, outboundSession.Target)
				}
			} else if message.SniffedProtocol != log.SniffedProtocolHTTP || outboundSession.Target.Address.Domain() != "handler.example.com" {
				t.Fatalf("TCP audit mismatch: source=%q target=%v", message.SniffedProtocol, outboundSession.Target)
			}
		})
	}
}

func TestAuditConcurrentTCPUDPUserBurst(t *testing.T) {
	for index := range 64 {
		index := index
		t.Run(fmt.Sprintf("flow-%02d", index), func(t *testing.T) {
			t.Parallel()
			network := net.Network_TCP
			if index%2 == 1 {
				network = net.Network_UDP
			}
			email := fmt.Sprintf("user-%02d", index)
			message, outbound := runInboundCompatibilityCase(t, false, network, email)
			if message.Email != email {
				t.Fatalf("identity leaked: got %q, want %q", message.Email, email)
			}
			if message.OriginalDestination == nil || outbound.OriginalTarget.String() != message.OriginalDestination.String() {
				t.Fatalf("original destination crossed flow: outbound=%v message=%v", outbound.OriginalTarget, message.OriginalDestination)
			}
		})
	}
}

func runInboundCompatibilityCase(t *testing.T, useDispatchLink bool, network net.Network, email string) (*log.AccessMessage, *session.Outbound) {
	t.Helper()
	handler := &auditOutboundHandler{dispatched: make(chan context.Context, 1)}
	dispatcher := &DefaultDispatcher{ohm: &auditOutboundManager{handler: handler}}
	original := net.TCPDestination(net.ParseAddress("203.0.113.20"), 80)
	payload := []byte("GET / HTTP/1.1\r\nHost: handler.example.com\r\n\r\n")
	override := "http"
	from := net.TCPDestination(net.ParseAddress("198.51.100.10"), 50000)
	if network == net.Network_UDP {
		original = net.UDPDestination(net.ParseAddress("203.0.113.20"), 443)
		payload = validQUICInitial(t)
		override = "quic"
		from = net.UDPDestination(net.ParseAddress("198.51.100.10"), 50000)
	}
	outboundSession := &session.Outbound{}
	message := &log.AccessMessage{From: from, To: original, Status: log.AccessAccepted, Email: email}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outboundSession})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
		Enabled:                        true,
		OverrideDestinationForProtocol: []string{override},
		LogSniffedDestination:          true,
	}})
	ctx = log.ContextWithAccessMessage(ctx, message)

	if useDispatchLink {
		reader, writer := pipe.New()
		defer common.Interrupt(reader)
		defer common.Close(writer)
		if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
			t.Fatal(err)
		}
		if err := dispatcher.DispatchLink(ctx, original, &transport.Link{Reader: reader, Writer: buf.Discard}); err != nil {
			t.Fatal(err)
		}
	} else {
		inbound, err := dispatcher.Dispatch(ctx, original)
		if err != nil {
			t.Fatal(err)
		}
		defer common.Interrupt(inbound.Reader)
		defer common.Close(inbound.Writer)
		if err := inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-handler.dispatched:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for asynchronous compatibility dispatch")
		}
	}

	if outboundSession.OriginalTarget != original {
		t.Fatalf("original target = %v, want %v", outboundSession.OriginalTarget, original)
	}
	return message, outboundSession
}
