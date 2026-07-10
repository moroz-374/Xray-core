package scenarios

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

func TestTrojanTLS(t *testing.T) {
	testTrojanTLS(t, "", nil)
}

func TestTrojanWebSocketTLS(t *testing.T) {
	testTrojanTLS(t, "websocket", []*internet.TransportConfig{{
		ProtocolName: "websocket",
		Settings:     serial.ToTypedMessage(&websocket.Config{Path: "/x40-trojan"}),
	}})
}

func TestTrojanGRPCTLS(t *testing.T) {
	testTrojanTLS(t, "grpc", []*internet.TransportConfig{{
		ProtocolName: "grpc",
		Settings:     serial.ToTypedMessage(&grpc.Config{ServiceName: "x40trojan"}),
	}})
}

func TestTrojanHTTPUpgradeTLS(t *testing.T) {
	testTrojanTLS(t, "httpupgrade", []*internet.TransportConfig{{
		ProtocolName: "httpupgrade",
		Settings:     serial.ToTypedMessage(&httpupgrade.Config{Path: "/x40-trojan"}),
	}})
}

func TestTrojanXHTTP(t *testing.T) {
	testTrojanTLS(t, "splithttp", []*internet.TransportConfig{{
		ProtocolName: "splithttp",
		Settings:     serial.ToTypedMessage(&splithttp.Config{Host: "localhost", Path: "/x40-trojan", Mode: "auto"}),
	}})
}

func testTrojanTLS(t *testing.T, transportProtocol string, transportSettings []*internet.TransportConfig) {
	t.Helper()
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	const password = "x40-trojan-password"
	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
				StreamSettings: &internet.StreamConfig{
					ProtocolName:      transportProtocol,
					TransportSettings: transportSettings,
					SecurityType:      serial.GetMessageType(&tls.Config{}),
					SecuritySettings: []*serial.TypedMessage{
						serial.ToTypedMessage(&tls.Config{Certificate: []*tls.Certificate{tls.ParseCertificate(certificate)}}),
					},
				},
			}),
			ProxySettings: serial.ToTypedMessage(&trojan.ServerConfig{Users: []*protocol.User{{
				Account: serial.ToTypedMessage(&trojan.Account{Password: password}),
			}}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{})}},
	}

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				Address:  net.NewIPOrDomain(dest.Address),
				Port:     uint32(dest.Port),
				Networks: []net.Network{net.Network_TCP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&trojan.ClientConfig{Server: &protocol.ServerEndpoint{
				Address: net.NewIPOrDomain(net.LocalHostIP),
				Port:    uint32(serverPort),
				User:    &protocol.User{Account: serial.ToTypedMessage(&trojan.Account{Password: password})},
			}}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
				ProtocolName:      transportProtocol,
				TransportSettings: transportSettings,
				SecurityType:      serial.GetMessageType(&tls.Config{}),
				SecuritySettings: []*serial.TypedMessage{
					serial.ToTypedMessage(&tls.Config{PinnedPeerCertSha256: [][]byte{certificateHash[:]}}),
				},
			}}),
		}},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, time.Second*20)(); err != nil {
		t.Fatal(err)
	}
}
