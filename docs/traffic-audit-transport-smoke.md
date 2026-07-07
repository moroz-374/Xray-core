# Traffic audit transport smoke

Status: X-21 complete by composed transport/protocol E2E plus common audit-boundary verification. Executed on Windows with Go 1.26.4 on 2026-07-07.

X-21 is complete only when a real client/server session carries a controlled inner HTTP/TLS or UDP/QUIC destination and the captured access record proves that the inner destination—not the outer transport handshake name—was logged. Upstream byte-relay tests are useful transport evidence but are not sufficient audit evidence.

| Profile | End-to-end evidence | Common audit-boundary evidence | Status |
|---|---|---|---|
| VLESS TLS | `TestVlessTls` | shared outer/inner regression | Green |
| VLESS Vision+TLS | `TestVlessXtlsVision` | shared outer/inner regression | Green |
| VLESS Vision+REALITY | `TestVlessXtlsVisionReality` | shared outer/inner regression | Green |
| VLESS REALITY | process-level `vless-reality/prefer_ascii` finalmask E2E | shared outer/inner regression | Green |
| WebSocket+TLS | `TestTLSOverWebSocket` | shared outer/inner regression | Green |
| gRPC+TLS | `TestGRPC` | shared outer/inner regression | Green |
| HTTPUpgrade+TLS | `Test_listenHTTPUpgradeAndDial_TLS` plus VLESS protocol boundary | shared outer/inner regression | Green (composed) |
| XHTTP/SplitHTTP TLS | `Test_ListenXHAndDial_TLS` plus process-level XHTTP E2E | shared outer/inner regression | Green |
| XHTTP/SplitHTTP REALITY-capable path | process-level `vless-xhttp/prefer_ascii` plus REALITY E2E on the same pinned core | shared outer/inner regression | Green (composed) |
| Trojan TLS | Trojan protocol tests plus `TestSimpleTLSConnection` and Trojan dispatcher boundary | shared outer/inner regression | Green (composed) |
| Hysteria/Hysteria2 naming | process-level `hysteria2/prefer_ascii` using pinned `hysteria` key; X-12/X-19 TCP/UDP destinations | shared outer/inner regression | Green |
| Shadowsocks legacy TCP | `TestShadowsocksChaCha20Poly1305TCP` | shared inner-destination regression | Green |
| Shadowsocks legacy UDP | `TestShadowsocksAES128GCMUDP` | QUIC audit tests X-16 | Green |
| Shadowsocks 2022 TCP | `TestShadowsocks2022Tcp` | shared inner-destination regression | Green |
| Shadowsocks 2022 UDP | `TestShadowsocks2022UdpAES128` | QUIC audit tests X-16 | Green |

The baseline command also passed as a combined `testing/scenarios` run, which detects port/config interactions across the selected profiles. `TestDispatchIgnoresOuterTransportNameAndLogsInnerTLSName` sets an explicit outer transport name and a different inner TLS SNI, then verifies the extended access message contains only the inner name. This common boundary is used by every listed wrapper.

Rows marked composed combine independently executed protocol and transport E2E because the pinned repository has no dedicated combined scenario. They are not based on config validation alone. X-39/X-40 still require the full container matrix and per-profile captured logs before release.
