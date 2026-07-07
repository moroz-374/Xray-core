# Traffic audit test specification

Status: X-05 pre-implementation specification for upstream `v26.3.27` (`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`).

This document converts the compatibility model and X-02 through X-04 contracts into traceable tests. Tests marked `required` are expected to be red or absent before implementation; this is a specification, not an execution report.

## Test levels and evidence

| Level | Code | Purpose | Required evidence |
|---|---|---|---|
| Unit | U | Pure formatter, normalization, config, and helper behavior | Exact values and byte-for-byte golden strings |
| Dispatcher integration | D | Real `DefaultDispatcher.Dispatch`/`DispatchLink` with controlled sniffer input, context, router, and outbound spy | Access record plus independent `Outbound`/router/dial assertions |
| Protocol integration | P | Real inbound protocol handler and client/server pair using local fixtures | Exact config, user, inner target, captured access line, successful payload |
| Container E2E | E | Built Xray binaries and production-like transports/clients | Version/SHA, configs, client command, target evidence, actual log, route evidence |

Every test stores the original destination (`O`), sniffed destination (`S`), selected outbound, and actual access line separately. A successful proxy request alone is not sufficient evidence.

## Canonical fixtures and expected states

| Symbol | Value |
|---|---|
| `O4T` | `tcp:203.0.113.20:443` |
| `O6T` | `tcp:[2001:db8::20]:443` |
| `O4U` | `udp:203.0.113.20:443` |
| `O6U` | `udp:[2001:db8::20]:443` |
| `ODT` | `tcp:origin.example:443` |
| `S_TLS_T` | `tcp:example.com:443`, source `tls` |
| `S_HTTP_T` | `tcp:example.com:80`, source `http` |
| `S_QUIC_U` | `udp:example.com:443`, source `quic` |
| `S_FAKE_T` | `tcp:example.com:443`, source `fakedns` |
| user A/B | email/client identifier `1001` / `1002` |

Expected routing states:

| State | Condition | `OriginalTarget` | `Target` | `RouteTarget` | Access destination |
|---|---|---|---|---|---|
| `R0` | no accepted override | `O` | `O` | empty | legacy `O` |
| `R1` | accepted override, `routeOnly=false` | `O` | `S` | empty | legacy `O`, or opt-in `S + original O` |
| `R2` | accepted non-FakeDNS override, `routeOnly=true` | `O` | `O` | `S` | legacy `O`, or opt-in `S + original O` |
| `RF` | FakeDNS/fake-pool override, either routeOnly value | `O` | `S` | unchanged | legacy `O`, or opt-in `S + original O` |

“Legacy” always means exact upstream bytes, not merely equivalent parsed fields.

## Formatter, normalization, and config unit matrix

| ID | Fixture/action | Expected access/config result | Expected routing result |
|---|---|---|---|
| U-LOG-01 | Existing accepted message, no new fields | Exact upstream golden bytes | N/A |
| U-LOG-02 | Existing rejected message with reason | Exact upstream golden bytes | N/A |
| U-LOG-03 | Existing email and detour variants | Exact upstream golden bytes | N/A |
| U-LOG-04 | Extended `O4T → S_TLS_T`, email present | X-03 exact extended line; order email, original, sniffed | N/A |
| U-LOG-05 | Extended TCP/UDP original domain/IPv4/IPv6 | Correct network, IPv6 brackets, port, atomic suffix | N/A |
| U-LOG-06 | Only original or only source populated | Emit neither suffix field | N/A |
| U-LOG-07 | Empty contextual fields | Byte-identical upstream output | N/A |
| U-LOG-08 | Detour absent/present and anonymous message | Grammar remains valid; suffix follows legacy prefix | N/A |
| U-NORM-01 | `Example.COM.` | `example.com` | N/A |
| U-NORM-02 | valid `xn--` labels | Preserved lowercase punycode | N/A |
| U-NORM-03 | empty, whitespace/control, empty/oversized label, oversized name, leading/trailing hyphen | rejected; helper is no-op | N/A |
| U-NORM-04 | apparent IPv4/IPv6 instead of domain | rejected as sniffed domain | N/A |
| U-CFG-01 | field absent, `null`, false, true | runtime false, false, false, true | N/A |
| U-CFG-02 | string/number/object/array field type | config parsing fails | N/A |
| U-CFG-03 | existing config without field serialized/built | existing protobuf values unchanged, new bool false | N/A |
| U-CFG-04 | protobuf round-trip field 6 | true survives; field numbers 1–5 unchanged | N/A |
| U-CFG-05 | aliases `https`/`ssl`, QUIC, FakeDNS values | existing `destOverride` normalization unchanged | N/A |
| U-COPY-01 | TCP/UDP/Unix worker and `always.go` | bool copied exactly into `SniffingRequest` | N/A |
| U-COPY-02 | TUN and WireGuard per-flow copy | bool copied; independent flow contexts | N/A |
| U-COPY-03 | VLESS reverse outbound request | remains explicitly disabled/not inherited | N/A |

Target files: `common/log/access_test.go`, new helper tests near its implementation, `infra/conf/xray_test.go`, `app/proxyman` worker tests, and focused TUN/WireGuard context tests.

## Dispatcher decision matrix

All D tests run against both `Dispatch` and `DispatchLink` unless a row explicitly names one. Each row asserts access output and routing state independently.

| ID | Original / sniff result / config | Expected access line | Expected routing |
|---|---|---|---|
| D-OFF-01 | HTTP/TLS/QUIC success; option absent | exact legacy `O` | existing `R1` |
| D-OFF-02 | HTTP/TLS/QUIC success; option false | byte-identical to D-OFF-01 | existing `R1` |
| D-OFF-03 | sniffing disabled; option true | exact legacy `O`; no payload wait added | `R0` |
| D-OFF-04 | empty `destOverride`; option true | exact legacy `O` | `R0` |
| D-ON-01 | `O4T → TLS`, option true | `S_TLS_T`, original `O4T`, source `tls` | `R1` |
| D-ON-02 | `O6T → TLS`, option true | same with bracketed `O6T` | `R1` |
| D-ON-03 | IPv4/IPv6 TCP → HTTP Host | normalized `S_HTTP_T`, typed original, source `http` | `R1` |
| D-ON-04 | `O4U/O6U → QUIC` | normalized `S_QUIC_U`, typed original, source `quic` | `R1` |
| D-ON-05 | original domain `ODT`, same observed domain | truthful original domain; no IP inference | `R1` with same effective domain |
| D-ON-06 | no contextual `AccessMessage` | no record/panic/synthetic identity | normal existing routing |
| D-FAIL-01 | no-SNI TLS/QUIC, incomplete payload, unknown payload | exact legacy `O`, no suffix | `R0` |
| D-FAIL-02 | ECH with no observable inner name | exact legacy `O`, no inferred domain | `R0` or existing outer-name behavior only when upstream actually returns it |
| D-FAIL-03 | BitTorrent/uTP detection without domain | exact legacy `O` | existing protocol metadata only |
| D-FAIL-04 | invalid normalized domain | exact legacy `O` | existing upstream routing decision must not be broadened by logger |
| D-EXCL-01 | `domainsExcluded` exact match | exact legacy `O` | `R0` |
| D-EXCL-02 | anchored/unanchored `regexp:` match | exact legacy `O` | `R0` |
| D-EXCL-03 | exact/regexp no-match | extended line | `R1`/`R2` as configured |
| D-ROUTE-01 | non-FakeDNS, `routeOnly=false` | extended `S + original O` | `R1`; same selected outbound/dial behavior as upstream |
| D-ROUTE-02 | non-FakeDNS, `routeOnly=true` | same observation as D-ROUTE-01 | `R2`; target remains `O` |
| D-ROUTE-03 | router DIRECT/BLOCK/tagged/balancer | correct detour and suffix | selected route identical to option-false control |
| D-ROUTE-04 | domain strategies AsIs/IPIfNonMatch/IPOnDemand | correct suffix | DNS queries, resolved addresses, and route selection identical to control |
| D-META-01 | `metadataOnly=true`, FakeDNS hit | extended source `fakedns` | `RF` |
| D-META-02 | metadata-only, HTTP/TLS/QUIC payload available | legacy `O`; payload not read for sniffing | existing metadata-only state |
| D-FAKE-01 | FakeDNS IPv4 hit | `S_FAKE_T`, original fake IPv4, source `fakedns` | `RF` |
| D-FAKE-02 | FakeDNS IPv6 hit | sniffed domain, original bracketed fake IPv6 | `RF` |
| D-FAKE-03 | fake-pool lookup miss + TLS/QUIC fallback | domain + original fake IP, source `fakedns+others` | existing fake-pool override behavior |
| D-FAKE-04 | FakeDNS miss/no content result or LRU miss | exact legacy `O` | `R0` |
| D-FAKE-05 | destination outside fake pool | no FakeDNS-derived domain | existing content-sniffer decision |
| D-PRIV-01 | two simultaneous users and destinations | each line has its own email/original/source | no context/data crossing |
| D-PRIV-02 | concurrent TCP and UDP bursts | no mutable message race or cross-assignment | normal per-flow routing |

`ipsExcluded` has no D row because pinned `v26.3.27` has no such config/runtime feature. Its X-18 matrix entry is `N/A` with the X-04 source evidence, not an untested pass.

## Inbound protocol integration matrix

Each P row uses a real protocol encoder/client and local TCP/UDP target. `A/F/T` means run `logSniffedDestination` absent, false, and true. For A/F the expected line is exact legacy `O`; for T it is `S + original O + source` when a domain-bearing sniff succeeds. Route assertions use `R1` unless the row explicitly enables `routeOnly`.

| ID | Handler/path | Required inner traffic and address axes | Identity expectation | Dispatcher/evidence |
|---|---|---|---|---|
| P-VLESS-01 | VLESS normal | TCP HTTP/TLS and UDP DNS/QUIC; domain/IPv4/IPv6; A/F/T | authenticated email | real `DispatchLink`, exact lines and payload |
| P-VLESS-02 | VLESS Mux | concurrent TCP streams, two users | per logical stream email | common Mux message, no outer duplicate |
| P-VLESS-03 | VLESS XUDP | multiple UDP destinations and reconnect by global ID | per stream/user | no destination/context leakage |
| P-VMESS-01 | VMess normal | TCP HTTP/TLS and UDP DNS/QUIC; domain/IPv4/IPv6; A/F/T | authenticated email | real `Dispatch`, exact lines and payload |
| P-VMESS-02 | VMess Mux/XUDP | same concurrency axes as VLESS | per logical stream/user | common Mux isolation |
| P-TROJAN-01 | Trojan TCP | domain/IP TCP HTTP/TLS; A/F/T | authenticated email | accepted line; rejected/fallback is never accepted audit |
| P-TROJAN-02 | Trojan UDP | multiple UDP DNS/QUIC destinations | email per packet | reusable UDP dispatcher isolation |
| P-SS-01 | Shadowsocks legacy TCP | supported AEAD; HTTP/TLS; domain/IP; A/F/T | configured user email | exact line and payload |
| P-SS-02 | Shadowsocks legacy UDP | DNS/QUIC, multiple destinations/users | packet user email | reusable UDP dispatcher isolation |
| P-SS22-01 | Shadowsocks 2022 single | TCP and UDP HTTP/TLS/DNS/QUIC | configured email | singbridge preserves context |
| P-SS22-02 | Shadowsocks 2022 multi-user | TCP/UDP, two users concurrently | selected user email | no user/context crossing |
| P-SS22-03 | Shadowsocks 2022 relay | relay TCP/UDP destinations | relay user email | relay target and source preserved |
| P-SOCKS-01 | SOCKS4/4a/5 CONNECT | domain/IPv4/IPv6, HTTP/TLS; A/F/T | anonymous or configured auth | current email omission is a required failing attribution case to resolve explicitly |
| P-SOCKS-02 | SOCKS5 UDP associate | domain/IP DNS/QUIC, multi-destination | authenticated/anonymous | current email omission plus packet isolation |
| P-SOCKS-03 | SOCKS HTTP fallback | HTTP request and CONNECT | HTTP auth/session behavior | first byte and audit context preserved |
| P-HTTP-01 | HTTP CONNECT | domain/IP then tunneled TLS | Basic-auth identity available in session | current AccessMessage email omission is a required failing attribution case |
| P-HTTP-02 | plain HTTP proxy | absolute URL and keep-alive requests | Basic-auth/anonymous | one correct contextual line per existing request path, no stale message |
| P-DOKO-01 | dokodemo-door | TCP TLS and UDP QUIC, followRedirect on/off | anonymous | redirected original destination preserved |
| P-TUN-01 | TUN | IPv4/IPv6 TCP/UDP, system DNS, FakeDNS | anonymous | per-flow copied request, no shared fields |
| P-WG-01 | WireGuard inbound | IPv4/IPv6 peers carrying TCP TLS and UDP QUIC | anonymous | inner flow destination; null source remains upstream-compatible |
| P-HY-01 | Hysteria TCP | proxied TCP HTTP/TLS | transport-authenticated email | outer handshake name differs from inner SNI |
| P-HY-02 | Hysteria UDP | proxied UDP DNS/QUIC | transport-authenticated user if available | required failing baseline: add/define contextual `AccessMessage`; first destination and later packets verified |
| P-REJECT-01 | all authenticated families | invalid credential/header/blocked request | never attributed as accepted | rejected/direct records have no extended suffix |

No handler is complete with only a config parse or handshake test. A P test must move controlled payload through the inner destination and capture the resulting access record.

## Transport and production-like E2E matrix

E tests use an outer handshake domain different from `example.com`, the inner sniffed destination. Each applicable row carries TCP TLS/SNI and UDP QUIC when the protocol supports UDP. Unsupported combinations may be `N/A` only with schema/source citation and failed config validation from the exact tested SHA.

| ID | Protocol/security/transport profile | Required modes |
|---|---|---|
| E-VLESS-01 | VLESS RAW/TCP, no transport security | TCP + UDP, A/F/T |
| E-VLESS-02 | VLESS RAW/TCP + TLS | TCP + UDP, inner/outer SNI separation |
| E-VLESS-03 | VLESS RAW/TCP + REALITY | TCP + UDP, inner/outer serverName separation |
| E-VLESS-04 | VLESS XTLS Vision + REALITY | TCP + supported UDP/XUDP path |
| E-VLESS-05 | VLESS WebSocket + TLS | TCP + UDP where supported |
| E-VLESS-06 | VLESS gRPC + TLS | TCP + UDP where supported |
| E-VLESS-07 | VLESS HTTPUpgrade + TLS | TCP + UDP where supported |
| E-VLESS-08 | supported VLESS XHTTP + TLS/REALITY modes | every schema-valid pinned mode |
| E-TROJAN-01 | Trojan RAW/TCP + TLS | TCP + UDP, A/F/T |
| E-TROJAN-02 | Trojan WebSocket/gRPC/HTTPUpgrade + TLS | each valid wrapper |
| E-TROJAN-03 | supported Trojan XHTTP | validated pinned variants |
| E-VMESS-01 | VMess RAW/TCP | TCP + UDP, A/F/T |
| E-VMESS-02 | VMess WebSocket/gRPC/HTTPUpgrade + TLS | each valid wrapper |
| E-VMESS-03 | supported VMess XHTTP | validated pinned variants |
| E-SS-01 | Shadowsocks legacy AEAD | native TCP and UDP |
| E-SS22-01 | Shadowsocks 2022 single/multi/relay | native TCP and UDP |
| E-HY-01 | native pinned Hysteria/Hysteria2 profile | proxied TCP and UDP, not handshake-only |
| E-SOCKS-01 | SOCKS CONNECT/UDP associate | domain/IP TCP and UDP |
| E-HTTP-01 | HTTP proxy request/CONNECT | plain HTTP and tunneled TLS |
| E-DOKO-01 | dokodemo-door | TCP, UDP, followRedirect where supported |
| E-TUN-01 | TUN | IPv4/IPv6, system DNS, FakeDNS, TCP/UDP |
| E-WG-01 | WireGuard inbound | IPv4/IPv6 peers, TCP/UDP |
| E-MUX-01 | Mux/XUDP | two users, concurrent streams, several UDP destinations |
| E-TRANSPORT-01 | mKCP representative valid profile | inner destination assertion |
| E-TRANSPORT-02 | Hysteria transport representative profile | inner destination assertion |

For every E row, save:

1. exact server and client config;
2. Xray version and source revision;
3. client command/profile and target fixture;
4. expected legacy or extended line;
5. actual complete line;
6. expected and actual selected outbound/dial destination;
7. pass/fail/N/A with evidence.

## Negative, race, fuzz, and compatibility suites

| ID | Level | Scenario | Pass criterion |
|---|---|---|---|
| N-01 | D/E | ECH, no-SNI, encrypted DNS, shared CDN IP | original IP only; no invented domain |
| N-02 | D | malformed/fragmented QUIC, non-initial packets | no panic, false domain, or cross-flow assignment |
| N-03 | D/P | incomplete ClientHello/HTTP payload and sniffer timeout | upstream timing/error behavior and legacy line |
| N-04 | P/E | outer transport SNI differs from inner destination SNI | log contains only inner destination when proven |
| N-05 | P | disabled user/anonymous/internal traffic | no false user attribution |
| C-01 | U | fuzz `AccessMessage.String()` and domain normalizer | no panic/control-line injection/unbounded allocation |
| C-02 | D | `go test -race` dispatcher/log packages under parallel users | no race or mutable context leak |
| C-03 | P | UDP burst, XUDP rebind, Mux concurrent close/reopen | destinations and users remain isolated |
| C-04 | U/D | static constructor/copy audit | every new AccessMessage/SniffingRequest path classified |
| B-01 | U/D/P | old config and option absent across representative handlers | exact legacy snapshots remain unchanged |
| B-02 | P/E | old and custom nodes/log consumers together | old lines and extended lines both accepted by downstream rollout |
| B-03 | full | `go test -timeout 1h ./...` and platform CI | no upstream regression |

## Traceability to project requirements

| Requirement | Test IDs |
|---|---|
| Default-off byte compatibility | U-LOG-01..03, D-OFF-01..04, B-01 |
| Original destination and source retained | U-LOG-04..06, D-ON-01..05, all applicable P/E rows |
| No routing/data-path change | D-ROUTE-01..04, D-OFF, P/E route evidence |
| HTTP/TLS/QUIC/FakeDNS | D-ON-01..04, D-FAKE, P/E inner traffic |
| TCP/UDP, domain/IPv4/IPv6 | U-LOG-05, D-ON, every protocol row's address axes |
| routeOnly/metadataOnly/exclusions/strategies | D-EXCL, D-ROUTE, D-META, D-FAKE |
| User isolation and anonymous honesty | D-PRIV, P multi-user rows, N-05 |
| Mux/XUDP/TUN/WireGuard/Hysteria | P-VLESS/VMESS Mux, P-TUN, P-WG, P-HY, E-MUX |
| All pinned inbound handlers | complete P matrix from X-02 |
| Transport families and outer-name separation | complete E matrix, N-04 |
| ECH/no-SNI/unknown/malformed | D-FAIL, N-01..03 |
| Race/fuzz/static compatibility | C-01..04, B-03 |

## Exit criterion for X-05

The specification is complete when every X-02 handler and wrapper, every section 4 network/sniffer/routing axis, every mandatory protocol profile, and every X-03/X-04 invariant maps to at least one ID above. Later implementation tasks may split an ID into table-driven cases, but may not delete an axis or mark it `N/A` without exact pinned source/schema/config-validation evidence.
