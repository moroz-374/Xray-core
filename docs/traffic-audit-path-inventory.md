# Traffic audit logging and sniffing path inventory

Status: X-02 inventory for upstream `v26.3.27` (`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`).

This document records the inbound access-log, dispatcher, and sniffing paths that the opt-in traffic-audit patch must preserve. It is an implementation inventory, not the final log grammar or configuration contract.

## Static search baseline

The inventory was produced with repository-wide searches over non-test Go sources:

```text
AccessMessage constructors: 32 (28 proxy/mux, 3 internal DNS, plus the type definition excluded from the count)
SniffingRequest composite literals: 2
SniffingRequest references: 27
Dispatch/DispatchLink-style call sites: 51
```

The authoritative searches are:

```sh
rg -n --glob '*.go' --glob '!**/*_test.go' 'AccessMessage\s*\{' .
rg -n --glob '*.go' --glob '!**/*_test.go' 'SniffingRequest' .
rg -n --glob '*.go' --glob '!**/*_test.go' '\.(Dispatch|DispatchLink)\(' .
```

Internal DNS messages in `app/dns/dnscommon.go`, `app/dns/nameserver_doh.go`, and `app/dns/nameserver_quic.go` are not inbound user connections. They remain in the compatibility search baseline so a future patch cannot accidentally treat them as user-attributed audit events.

## Common logging and sniffing contract

- `common/log/access.go` defines `AccessMessage`. `routedDispatch` records a contextual message only after outbound selection and adds its detour string.
- `app/dispatcher/default.go` is the only production implementation of the global `routing.Dispatcher`. Both `Dispatch` and `DispatchLink` set `Outbound.OriginalTarget` and `Outbound.Target` before sniffing.
- Both dispatcher entry points use the same `sniffer` and `shouldOverride` functions. Successful override changes the local destination and either `Outbound.Target` or `Outbound.RouteTarget`, according to `RouteOnly`, FakeDNS, and fake-IP semantics.
- Sniffers are HTTP Host, TLS SNI, BitTorrent, QUIC SNI, uTP, FakeDNS, and `fakedns+others`. A result with no domain cannot pass `shouldOverride`.
- `SniffingRequest` is copied from proxyman inbound configuration by the three worker paths in `app/proxyman/inbound/worker.go`; `app/proxyman/inbound/always.go` contains the other explicit construction.
- TUN caches the request from its initialization context and copies it into each flow. WireGuard copies it from the parent inbound content into each peer flow. VLESS reverse outbound creates a new request with sniffing disabled.

The future logging helper therefore belongs after successful `shouldOverride` in both `DefaultDispatcher.Dispatch` and `DefaultDispatcher.DispatchLink`. It must mutate only the contextual `AccessMessage`; routing fields retain their existing behavior.

## Inbound handler matrix

`Identity` describes what is available to the access message today. `Per-packet` means a fresh access-message context is constructed for each UDP destination before entering the UDP dispatcher.

| Handler/path | Network and destination source | Access message and identity | Dispatcher path | Required tests / implementation note |
|---|---|---|---|---|
| VLESS normal | TCP/UNIX carrier; requested TCP/UDP/domain/IP from VLESS header | Accepted message for non-Mux requests; authenticated `request.User.Email` | `DispatchLink` | TCP and UDP commands, domain/IPv4/IPv6, user isolation, default-off and opt-in sniffing |
| VLESS Mux/XUDP | Mux command; target comes from each mux frame | VLESS skips the outer message; `common/mux/server.go` creates one per logical stream and inherits inbound user email | Mux wrapper delegates each stream to global `Dispatch`; XUDP may reconnect by `GlobalID` | Multiple concurrent streams/users and UDP destinations; no shared mutable message on XUDP hit/rebind |
| VMess normal | TCP/UNIX carrier; requested TCP/UDP/domain/IP from VMess header | Accepted message for non-Mux requests; authenticated `request.User.Email` | `Dispatch` | TCP/UDP commands, all address families, user isolation, both dispatcher timing and log output |
| VMess Mux/XUDP | Mux command and per-frame target | Outer message skipped; common Mux message carries inherited user email | Mux wrapper to global `Dispatch` | Same Mux/XUDP concurrency and destination-isolation suite as VLESS |
| Trojan TCP | TCP/UNIX carrier; destination from Trojan header | Accepted message with authenticated user email; rejected handshake messages are recorded directly | `Dispatch` | Accepted/rejected distinction, TCP domain/IP, TLS/QUIC payload sniffing, fallback must not create accepted audit data |
| Trojan UDP | UDP packets encapsulated in Trojan TCP; destination per packet | Fresh accepted message with user email per packet | `transport/internet/udp.Dispatcher`, which opens/reuses global `Dispatch` rays | Multiple packet destinations, cone/reuse behavior, no cross-packet domain assignment |
| Shadowsocks legacy TCP | TCP destination from request header | Accepted message with `request.User.Email`; rejected handshake recorded directly | `Dispatch` | Legacy AEAD TCP, domain/IPv4/IPv6, user identity and default-off compatibility |
| Shadowsocks legacy UDP | Native UDP; destination and user from each decrypted packet | Fresh accepted message with user email per packet; invalid packets recorded rejected | UDP dispatcher to global `Dispatch` | UDP multi-destination and multi-user isolation, QUIC/FakeDNS paths |
| Shadowsocks 2022 single | TCP and UDP connection metadata from sing-box adapter | Accepted message has configured single-user email | singbridge calls upstream `DispatchLink` for TCP and UDP | Both networks, domain/IP variants, metadata conversion and payload sniffing |
| Shadowsocks 2022 multi-user | TCP and UDP metadata; user index from context | Accepted message has selected `MemoryUser.Email` | Direct global `Dispatch` for TCP/UDP | Multi-user isolation, packet connection behavior, all destination forms |
| Shadowsocks 2022 relay | TCP and UDP relay destination metadata; relay user index | Accepted message has relay user email | Direct global `Dispatch` | Relay destination and identity preservation; TCP/UDP sniffing |
| SOCKS TCP CONNECT | TCP/UNIX carrier; destination from SOCKS4/4a/5 request | Accepted message exists, but currently omits `Email` even when SOCKS auth populated `inbound.User.Email` | `DispatchLink` | Authenticated and anonymous cases; preserve the known identity gap explicitly until addressed |
| SOCKS UDP | Native UDP association; destination per datagram | Fresh message per packet, but currently omits authenticated email | UDP dispatcher to global `Dispatch` | Multi-destination, cone/reuse, auth attribution gap, DNS/QUIC |
| SOCKS HTTP fallback | Non-SOCKS first byte is delegated to HTTP handler | Same behavior as HTTP proxy | HTTP path | Ensure fallback does not lose inbound identity or first payload bytes |
| HTTP proxy CONNECT | TCP/UNIX; destination parsed from Host | Accepted message uses request URL but currently omits `Email`; Basic auth is only in `inbound.User.Email` | `DispatchLink` | CONNECT domain/IP, Basic auth attribution gap, TLS SNI inside tunnel |
| HTTP proxy plain request | TCP/UNIX; destination parsed from absolute URL/Host | One accepted message per request context, currently without `Email` | `Dispatch`; handler supplies `Content.Protocol=http/1.1` and attributes | Keep-alive requests, domain/IP, routing attributes, no double attribution |
| Dokodemo-door | Configured TCP/UDP target or redirected original destination | Accepted message, anonymous by configuration | `DispatchLink` | TCP/UDP, followRedirect/original target, domain/IPv4/IPv6 where supported |
| TUN | Per-flow TCP/UDP destination from stack, IPv4/IPv6 | Accepted message per flow; no user identity | Cached `SniffingRequest`, then `DispatchLink` | IPv4/IPv6, system DNS, FakeDNS, concurrent flows and copied request integrity |
| WireGuard inbound | UDP carrier; inner TCP/UDP destination per netstack connection | Accepted message per inner flow; no user email; source is intentionally a null destination | Copied parent `SniffingRequest`, then `DispatchLink` | IPv4/IPv6 peers, inner TCP/UDP, FakeDNS, concurrent flow isolation |
| Hysteria TCP | Hysteria transport exposes proxied TCP target in request | Accepted message with transport-authenticated user email; rejected header recorded directly | `DispatchLink` | Real proxied TCP payload, authenticated identity, outer transport SNI must not replace destination SNI |
| Hysteria UDP | Inter-UDP connection; first proxied UDP target initializes reader/writer | **No `AccessMessage` is created today** | Direct `DispatchLink` for the first destination | Mandatory gap test: UDP/QUIC must not be claimed covered until a contextual message and destination semantics are defined |

No other type under `proxy/` implements the inbound `Network`/`Process` contract at this pinned revision. Outbound-only handlers, loopback, reverse, DNS, observatory, and tagged dialing can invoke the global dispatcher but are not new authenticated inbound protocol families.

## Dispatcher wrappers and alternate paths

| Component | Behavior | Audit implication |
|---|---|---|
| `common/mux.Server` | Implements `routing.Dispatcher` as a wrapper and delegates to the global dispatcher. The server worker creates a contextual message per Mux `SessionStatusNew`. | This is the authoritative access-message creation point for VLESS/VMess Mux and XUDP streams. |
| `transport/internet/udp.Dispatcher` | Converts packet dispatch into reusable global `Dispatch` rays keyed by destination or cone policy. | The packet-specific context/message must remain associated with the ray that performs sniffing; reuse needs isolation tests. |
| `common/singbridge.Dispatcher` | Adapts sing TCP/UDP connections to upstream `DispatchLink`. | Shadowsocks 2022 single-user uses this path; metadata and context must survive the adapter. |
| `app/reverse.BridgeWorker` | Implements a routing-dispatcher wrapper and forwards to the global dispatcher, with optional forced outbound tag. | Reverse traffic is not a new inbound handler, but logging changes must not break its forwarding/context semantics. |
| tagged/loopback/core dial helpers | Call the global dispatcher for internally initiated or redirected traffic. | They normally have no inbound `AccessMessage`; the helper must be a no-op when none exists. |
| internal DNS and observatory callers | Dispatch system-generated DNS/health traffic. | They must never acquire a user identity or synthetic accepted audit message. Existing explicit DNS access messages retain upstream output. |

## Known coverage gaps that later tasks must resolve

1. Hysteria UDP has no contextual access message and therefore cannot emit a normal accepted access record.
2. HTTP Basic-auth and SOCKS authenticated paths keep identity in `session.Inbound.User` but omit `AccessMessage.Email`; the traffic-audit patch must not silently invent attribution. A separate explicit decision/test is required.
3. TUN and WireGuard correctly copy `SniffingRequest`, but their per-flow messages are anonymous. Tests must prove that concurrent inner flows do not share mutable audit fields.
4. Mux creates a message per logical stream, while XUDP can detach and reattach a ray by global ID. Tests must cover rebind and simultaneous destinations.
5. Legacy SOCKS/Shadowsocks/Trojan UDP use a reusable UDP dispatcher. The original per-packet destination and contextual message must not be overwritten by a later packet.
6. HTTP plain keep-alive can process multiple requests on one client connection and creates a new request context each loop. Audit semantics remain connection/request-path specific to the existing access log and must be tested before changing output.
7. Direct `log.Record` rejected messages and internal DNS messages bypass contextual dispatcher mutation. Extended suffixes must never be added to those records accidentally.

## Completion mapping

Every pinned inbound handler is classified above with its networks, identity source, destination source, dispatcher entry point, and required test family. X-03 must use this inventory when defining grammar; X-05 must turn each required-test cell and each known gap into a traceable matrix row. X-08 and X-12 must repeat the static searches to detect newly introduced constructors or missed `SniffingRequest` copies.
