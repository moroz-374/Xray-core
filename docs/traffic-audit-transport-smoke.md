# Traffic audit transport smoke

Status: X-21 in progress. Baseline executed on Windows with Go 1.26.4 on 2026-07-07.

X-21 is complete only when a real client/server session carries a controlled inner HTTP/TLS or UDP/QUIC destination and the captured access record proves that the inner destination—not the outer transport handshake name—was logged. Upstream byte-relay tests are useful transport evidence but are not sufficient audit evidence.

| Profile | Baseline evidence | Audit-aware outer/inner separation | Status |
|---|---|---|---|
| VLESS TLS | `TestVlessTls` passed | controlled inner SNI and captured extended log still required | Partial |
| VLESS Vision+TLS | `TestVlessXtlsVision` passed | controlled inner SNI and captured extended log still required | Partial |
| VLESS Vision+REALITY | `TestVlessXtlsVisionReality` passed | distinct REALITY server name vs inner SNI still required | Partial |
| VLESS REALITY without Vision | no dedicated selected baseline | required if supported by pinned config | Pending |
| WebSocket+TLS | `TestTLSOverWebSocket` passed | distinct outer TLS name vs inner destination still required | Partial |
| gRPC+TLS | `TestGRPC` passed | distinct outer TLS name vs inner destination still required | Partial |
| HTTPUpgrade+TLS | transport `Test_listenHTTPUpgradeAndDial_TLS` passed | protocol-level VLESS inner payload/log required | Partial |
| XHTTP/SplitHTTP TLS | transport `Test_ListenXHAndDial_TLS` passed | protocol-level inner payload/log required | Partial |
| XHTTP/SplitHTTP REALITY | not covered by selected baseline | protocol-level inner payload/log required | Pending |
| Trojan TLS | no upstream scenario in `testing/scenarios` | full client/server audit-aware scenario required | Pending |
| Hysteria/Hysteria2 naming | no selected standard scenario; pinned key is `hysteria` | proxied TCP/UDP target and outer QUIC/TLS name separation required | Pending |
| Shadowsocks legacy TCP | `TestShadowsocksChaCha20Poly1305TCP` passed | audit-aware controlled inner destination required | Partial |
| Shadowsocks legacy UDP | `TestShadowsocksAES128GCMUDP` passed | audit-aware QUIC destination required | Partial |
| Shadowsocks 2022 TCP | `TestShadowsocks2022Tcp` passed | audit-aware controlled inner destination required | Partial |
| Shadowsocks 2022 UDP | `TestShadowsocks2022UdpAES128` passed | audit-aware QUIC destination required | Partial |

The baseline command also passed as a combined `testing/scenarios` run, which detects port/config interactions across the selected profiles. No profile in this table is marked complete solely from config validation or a transport dial/listen test.
