package scenarios

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"golang.org/x/sync/errgroup"
)

func TestWireguard(t *testing.T) {
	tcpServer := tcp.Server{
		Listen:       net.AnyIP,
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()
	dest.Address = nonLoopbackIPv4(t)

	serverPrivate, _ := conf.ParseWireGuardKey("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=")
	serverPublic, _ := conf.ParseWireGuardKey("osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=")
	clientPrivate, _ := conf.ParseWireGuardKey("CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=")
	clientPublic, _ := conf.ParseWireGuardKey("MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw=")

	serverPort := udp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:    false,
					NoKernelTun: true,
					Endpoint:    []string{"10.0.0.1"},
					Mtu:         1420,
					SecretKey:   serverPrivate,
					Peers: []*wireguard.PeerConfig{{
						PublicKey:  serverPublic,
						AllowedIps: []string{"0.0.0.0/0", "::0/0"},
					}},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	}

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:    true,
					NoKernelTun: true,
					Endpoint:    []string{"10.0.0.2"},
					Mtu:         1420,
					SecretKey:   clientPrivate,
					Peers: []*wireguard.PeerConfig{{
						Endpoint:   "127.0.0.1:" + serverPort.String(),
						PublicKey:  clientPublic,
						AllowedIps: []string{"0.0.0.0/0", "::0/0"},
					}},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	var errg errgroup.Group
	for i := 0; i < 1; i++ {
		errg.Go(testTCPConn(clientPort, 1024, time.Second*10))
	}
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
}

func TestWireguardUDP(t *testing.T) {
	udpServer := udp.Server{Listen: net.AnyIP, MsgProcessor: xor}
	dest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()
	dest.Address = nonLoopbackIPv4(t)

	serverPrivate, _ := conf.ParseWireGuardKey("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=")
	serverPublic, _ := conf.ParseWireGuardKey("osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=")
	clientPrivate, _ := conf.ParseWireGuardKey("CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=")
	clientPublic, _ := conf.ParseWireGuardKey("MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw=")

	serverPort := udp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
				IsClient: false, NoKernelTun: true, Endpoint: []string{"10.0.0.1"}, Mtu: 1420, SecretKey: serverPrivate,
				Peers: []*wireguard.PeerConfig{{PublicKey: serverPublic, AllowedIps: []string{"0.0.0.0/0", "::0/0"}}},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{})}},
	}

	clientPort := udp.PickPort()
	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				Address: net.NewIPOrDomain(dest.Address), Port: uint32(dest.Port), Networks: []net.Network{net.Network_UDP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
				IsClient: true, NoKernelTun: true, Endpoint: []string{"10.0.0.2"}, Mtu: 1420, SecretKey: clientPrivate,
				Peers: []*wireguard.PeerConfig{{
					Endpoint: "127.0.0.1:" + serverPort.String(), PublicKey: clientPublic, AllowedIps: []string{"0.0.0.0/0", "::0/0"},
				}},
			}),
		}},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testUDPConn(clientPort, 1024, time.Second*10)(); err != nil {
		t.Fatal(err)
	}
}

func nonLoopbackIPv4(t *testing.T) net.Address {
	t.Helper()

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ip := ipNet.IP.To4(); ip != nil && !ip.IsLoopback() {
			return net.IPAddress(ip)
		}
	}
	t.Fatal("no non-loopback IPv4 address found")
	return nil
}
