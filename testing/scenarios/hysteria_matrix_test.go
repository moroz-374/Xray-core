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
	hyproxy "github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	hytransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestHysteria2UDPMatrix(t *testing.T) {
	testHysteriaUDP(t, 2)
}

func TestHysteria1UDPMatrix(t *testing.T) {
	testHysteriaUDP(t, 1)
}

func testHysteriaUDP(t *testing.T, version int32) {
	t.Helper()
	udpServer := udp.Server{MsgProcessor: xor}
	destination, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	const auth = "x40-hysteria-auth"
	serverPort := udp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
				StreamSettings: &internet.StreamConfig{
					ProtocolName: "hysteria",
					TransportSettings: []*internet.TransportConfig{{
						ProtocolName: "hysteria",
						Settings:     serial.ToTypedMessage(&hytransport.Config{Version: version, Auth: auth, UdpIdleTimeout: 60}),
					}},
					SecurityType: serial.GetMessageType(&tls.Config{}),
					SecuritySettings: []*serial.TypedMessage{
						serial.ToTypedMessage(&tls.Config{Certificate: []*tls.Certificate{tls.ParseCertificate(certificate)}, NextProtocol: []string{"h3"}}),
					},
				},
			}),
			ProxySettings: serial.ToTypedMessage(&hyproxy.ServerConfig{Users: []*protocol.User{{
				Account: serial.ToTypedMessage(&account.Account{Auth: auth}),
			}}}),
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
				Address: net.NewIPOrDomain(destination.Address), Port: uint32(destination.Port), Networks: []net.Network{net.Network_UDP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&hyproxy.ClientConfig{Version: version, Server: &protocol.ServerEndpoint{
				Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(serverPort),
				User: &protocol.User{Account: serial.ToTypedMessage(&account.Account{Auth: auth})},
			}}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
				ProtocolName: "hysteria",
				TransportSettings: []*internet.TransportConfig{{
					ProtocolName: "hysteria",
					Settings:     serial.ToTypedMessage(&hytransport.Config{Version: version, Auth: auth, UdpIdleTimeout: 60}),
				}},
				SecurityType: serial.GetMessageType(&tls.Config{}),
				SecuritySettings: []*serial.TypedMessage{
					serial.ToTypedMessage(&tls.Config{ServerName: "localhost", PinnedPeerCertSha256: [][]byte{certificateHash[:]}, NextProtocol: []string{"h3"}}),
				},
			}}),
		}},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testUDPConn(clientPort, 1024, time.Second*20)(); err != nil {
		t.Fatal(err)
	}
}
