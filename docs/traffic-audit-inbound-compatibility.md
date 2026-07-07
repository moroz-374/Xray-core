# Traffic audit inbound compatibility

Status: X-19 unit compatibility harness for upstream `v26.3.27` plus the traffic-audit patch.

The table-driven `TestInboundHandlerAuditCompatibilityMatrix` exercises the dispatcher boundary used by every applicable inbound path. It sends real HTTP or QUIC payload through the path's actual `Dispatch` or `DispatchLink` entry point and verifies the current identity contract, typed original destination, sniffed source, and routing target.

This is a unit compatibility gate, not a substitute for parsing each protocol handshake or for the real protocol/transport E2E matrix in X-20, X-39, and X-40.

| Handler/path | Boundary scenario | Identity assertion | X-19 status |
|---|---|---|---|
| VLESS normal | TCP HTTP via `DispatchLink` | authenticated email retained | Green |
| Trojan TCP | TCP HTTP via `Dispatch` | authenticated email retained | Green |
| VMess normal | TCP HTTP via `Dispatch` | authenticated email retained | Green |
| Shadowsocks legacy TCP | TCP HTTP via `Dispatch` | configured user email retained | Green |
| Shadowsocks 2022 single | TCP HTTP via direct `Dispatch` | configured email retained | Green |
| Shadowsocks 2022 multi | TCP HTTP via `Dispatch` | selected user email retained | Green |
| Shadowsocks 2022 relay | TCP HTTP via `Dispatch` | relay user email retained | Green |
| Hysteria TCP | TCP HTTP via `DispatchLink` | transport-authenticated email retained | Green |
| Hysteria UDP | UDP QUIC via `DispatchLink` | transport-authenticated email retained | Green; contextual message adapter added in X-12 |
| SOCKS TCP | TCP HTTP via `DispatchLink` | empty email retained honestly | Green with documented upstream auth-attribution gap |
| HTTP CONNECT | TCP HTTP via `DispatchLink` | empty email retained honestly | Green with documented upstream Basic-auth attribution gap |
| HTTP plain | TCP HTTP via `Dispatch` | anonymous message retained | Green |
| dokodemo-door | TCP HTTP via `DispatchLink` | anonymous message retained | Green |
| TUN flow | TCP HTTP via copied-request `DispatchLink` boundary | anonymous message retained | Green; per-flow/concurrency axes remain X-20 |
| WireGuard inner flow | TCP HTTP via copied-request `DispatchLink` boundary | anonymous/null-source semantics remain protocol-owned | Green; IPv4/IPv6/concurrency axes remain X-20 |
| VLESS/VMess Mux and XUDP | per-stream global `Dispatch` | common Mux creates the message | Deferred to X-20, where shared-state and per-packet behavior are the subject under test |
| Hysteria2 alias | none | none | N/A: pinned core registers only the `hysteria` protocol/transport key; no separate `hysteria2` inbound exists |

Protocol parser coverage already present upstream remains green for VLESS encoding, Trojan protocol, VMess encoding/validator, Shadowsocks legacy protocol/config, SOCKS protocol, and WireGuard server. X-19 does not claim those isolated parser tests are end-to-end audit tests. Real client/server handshakes, UDP reuse, Mux/XUDP, TUN/WireGuard networks, and outer transport separation remain mandatory later gates.
