# Traffic-audit fork patch inventory

## Provenance

- Upstream project: [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- Upstream tag: [`v26.3.27`](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27)
- Upstream commit: [`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`](https://github.com/XTLS/Xray-core/commit/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0)
- Fork repository: [moroz-374/Xray-core](https://github.com/moroz-374/Xray-core)
- Development branch: [`feature/traffic-audit-log`](https://github.com/moroz-374/Xray-core/tree/feature/traffic-audit-log)
- License: Mozilla Public License 2.0; the upstream `LICENSE` is retained.

Release tags have the form `v26.3.27-rw.<n>`. A release tag, the embedded
`<version>@<source SHA>` build marker, and the source link in the GitHub release
notes must all identify the same commit. The manual release workflow rejects a
publish request if the tag, requested ref, and resolved source SHA differ.

## Functional changes

The fork adds the optional per-inbound JSON/protobuf field
`sniffing.logSniffedDestination`. Its default is false. With the field absent or
false, access-log formatting remains byte-compatible with upstream.

When enabled and a domain-bearing sniffer succeeds, the accepted access record
can contain:

```text
original: <network>:<original-address>:<port> sniffed: <source>
```

The primary destination becomes the normalized sniffed domain. The original
typed destination is retained separately. Supported source values currently
include `http`, `tls`, `quic`, `fakedns`, and `fakedns+others`. The extension
does not infer a domain from DNS history or an IP address, does not decrypt ECH,
and does not change routing, outbound selection, or proxy chaining.

## Patch surface

Runtime and configuration changes are intentionally limited to:

- `app/dispatcher`: validates and attaches confirmed sniff results to the
  contextual access message without mutating outbound routing state.
- `app/proxyman`: carries the per-inbound opt-in from generated protobuf config
  into the dispatcher sniffing request.
- `common/log` and `common/session`: hold and format the optional audit fields.
- `infra/conf`: parses and validates the JSON option.
- `proxy/hysteria` and `proxy/vless/outbound`: preserve authenticated identity
  and the opt-in context on their special dispatch paths.

Two small upstream-hardening changes were required by the race suite:

- `proxy/dns` copies normalized IP bytes instead of mutating a shared lookup
  slice while an asynchronous logger may still format it.
- `proxy/blackhole` test synchronization uses a channel instead of reading a
  result concurrently with the worker writing it.

Tests and design evidence live in the corresponding `*_audit_test.go`,
dispatcher compatibility tests, and `docs/traffic-audit-*` files. CI and manual
release behavior are defined in `.github/workflows/test.yml` and
`.github/workflows/fork-release.yml`.

## Compatibility and limitations

- HTTP Host and TLS SNI are observable only when the payload is available to
  the existing Xray sniffer.
- QUIC SNI is available only for supported, parseable Initial packets.
- ECH, no-SNI traffic, malformed/encrypted payloads, and unknown protocols stay
  IP-only unless FakeDNS provides a confirmed mapping.
- The access record represents an accepted Xray TCP/UDP connection or flow, not
  every HTTP request carried inside it.
- Old nodes and old-format access records remain valid during rolling upgrades.

The exact grammar and configuration semantics are specified in
[`docs/traffic-audit-access-log-grammar.md`](docs/traffic-audit-access-log-grammar.md)
and [`docs/traffic-audit-config-contract.md`](docs/traffic-audit-config-contract.md).

## Verifying a binary

1. Download the ZIP, adjacent `.zip.sha256`, and SPDX JSON file from the same
   GitHub prerelease.
2. Verify the checksum with `sha256sum --check <asset>.zip.sha256`.
3. Verify the GitHub attestation for the ZIP with GitHub CLI.
4. Run `xray version` and record the embedded `<version>@<source SHA>` marker.
5. Open `https://github.com/moroz-374/Xray-core/tree/<source SHA>` and confirm
   that the release tag resolves to the same commit.
6. Compare the fork with the fixed upstream base using
   `git diff v26.3.27..<release tag>`.

No binary from this fork should be treated as reproducible or attributable if
its checksum, attestation, tag, embedded marker, and public source SHA do not
agree.
