# Traffic audit special-path verification

Status: X-20 unit verification for pinned Xray `v26.3.27` plus the traffic-audit patch.

X-20 verifies the state boundaries that are specific to Mux/XUDP, TUN, WireGuard, and Hysteria. It does not replace the real protocol and transport profiles required by X-21, X-39, and X-40.

| Path | Context/destination evidence | Isolation evidence | Remaining E2E axis |
|---|---|---|---|
| Mux | `handleStatusNew` creates a sub-context and a new message for `meta.Target` before global `Dispatch` | concurrent unit matrix uses distinct content, outbound, message, email and TCP IPv4 destination | real VLESS/VMess Mux streams |
| XUDP | each `SessionStatusNew` creates the message from that frame's `meta.Target` before new/hit handling; rebind does not reuse the prior message pointer | concurrent unit matrix uses an independent UDP IPv6 destination and identity | GlobalID detach/reattach with real packets |
| TUN | `HandleConnection` copies the cached read-only `SniffingRequest`, creates a sub-context, then a message for the per-flow destination | concurrent unit matrix covers system DNS and IPv4 FakeDNS-shaped destinations without shared fields | real stack IPv4/IPv6/FakeDNS flows |
| WireGuard | `forwardConnection` copies parent inbound/content into a new sub-context and creates a new message for each inner destination | concurrent unit matrix covers inner IPv4 TCP and IPv6 UDP without shared fields | real peers and netstack flows |
| Hysteria TCP | server creates an authenticated message for the parsed proxied TCP target before `DispatchLink` | X-19 boundary test verifies TCP target/email; message is connection-local | real outer transport with different inner SNI |
| Hysteria UDP | X-12 adapter creates an authenticated message for the parsed first proxied UDP target before `DispatchLink` | X-12 exact-message test and X-19 real QUIC boundary test verify UDP target/email | multi-packet InterUdpConn transport profile |
| Hysteria2 alias | no separate inbound exists in the pinned source; only `hysteria` is registered | N/A with source evidence | external/client naming must map to the supported pinned profile |

The concurrent unit test is intentionally run under the Go race detector again in X-22. Mutable audit fields live only on each newly attached `AccessMessage`; `SniffingRequest` is read-only and copied by value. Destination-per-packet and GlobalID behavior are also mandatory production-like E2E assertions, because a synthetic unit context cannot prove transport framing.
