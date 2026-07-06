package hysteria

import (
	"context"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestContextWithHysteriaUDPAccessMessage(t *testing.T) {
	destination := xnet.UDPDestination(xnet.ParseAddress("203.0.113.20"), 443)
	ctx := contextWithHysteriaUDPAccessMessage(
		context.Background(),
		&stdnet.UDPAddr{IP: stdnet.ParseIP("198.51.100.10"), Port: 50000},
		destination,
		"hysteria-user",
	)

	message := log.AccessMessageFromContext(ctx)
	if message == nil {
		t.Fatal("access message is missing")
	}
	if got, want := message.String(), "from 198.51.100.10:50000 accepted udp:203.0.113.20:443 email: hysteria-user"; got != want {
		t.Fatalf("access message = %q, want %q", got, want)
	}
}
