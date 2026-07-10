package scenarios

import (
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

func TestTunIPv4TCPMatrix(t *testing.T) {
	tcpServer := tcp.Server{Listen: net.AnyIP, MsgProcessor: xor}
	target, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()
	target.Address = nonLoopbackIPv4(t)

	const tunName = "x40tun0"
	testDestination := stdnet.ParseIP("198.18.0.1")
	tunConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{}),
			ProxySettings:    serial.ToTypedMessage(&tun.Config{Name: tunName, MTU: 1500}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{DestinationOverride: &freedom.DestinationOverride{
				Server: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(target.Address), Port: uint32(target.Port)},
			}}),
		}},
	}

	servers, err := InitializeServerConfigs(tunConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	link := waitForTunLink(t, tunName)
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &stdnet.IPNet{IP: testDestination, Mask: stdnet.CIDRMask(32, 32)},
	}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = netlink.RouteDel(route) }()

	connection, err := stdnet.DialTimeout("tcp4", stdnet.JoinHostPort(testDestination.String(), target.Port.String()), time.Second*10)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	payload := []byte("x40-tun-ipv4-tcp")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	for i := range payload {
		if response[i] != payload[i]^'c' {
			t.Fatalf("unexpected echoed byte at %d: got %x want %x", i, response[i], payload[i]^'c')
		}
	}
}

func TestTunIPv4UDPMatrix(t *testing.T) {
	udpServer := udp.Server{Listen: net.AnyIP, MsgProcessor: xor}
	target, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()
	target.Address = nonLoopbackIPv4(t)

	const tunName = "x40tun1"
	testDestination := stdnet.ParseIP("198.18.0.2")
	tunConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{}),
			ProxySettings:    serial.ToTypedMessage(&tun.Config{Name: tunName, MTU: 1500}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{DestinationOverride: &freedom.DestinationOverride{
				Server: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(target.Address), Port: uint32(target.Port)},
			}}),
		}},
	}

	servers, err := InitializeServerConfigs(tunConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	link := waitForTunLink(t, tunName)
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &stdnet.IPNet{IP: testDestination, Mask: stdnet.CIDRMask(32, 32)},
	}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = netlink.RouteDel(route) }()

	connection, err := stdnet.DialTimeout("udp4", stdnet.JoinHostPort(testDestination.String(), target.Port.String()), time.Second*10)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	payload := []byte("x40-tun-ipv4-udp")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	for i := range payload {
		if response[i] != payload[i]^'c' {
			t.Fatalf("unexpected echoed byte at %d: got %x want %x", i, response[i], payload[i]^'c')
		}
	}
}

func waitForTunLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	deadline := time.Now().Add(time.Second * 10)
	for time.Now().Before(deadline) {
		link, err := netlink.LinkByName(name)
		if err == nil {
			return link
		}
		time.Sleep(time.Millisecond * 50)
	}
	t.Fatalf("TUN interface %q was not created", name)
	return nil
}
