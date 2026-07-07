# Traffic audit opt-in configuration contract

Status: X-04 contract for upstream `v26.3.27` (`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`).

This document fixes the public JSON, protobuf, and runtime behavior of the traffic-audit log opt-in. It does not implement or generate code.

## Public JSON field

The field name is `logSniffedDestination`. It belongs to each inbound's existing `sniffing` object:

```json
{
  "sniffing": {
    "enabled": true,
    "destOverride": ["http", "tls", "quic"],
    "metadataOnly": false,
    "routeOnly": false,
    "logSniffedDestination": true
  }
}
```

It is a JSON boolean. A string, number, object, or array is invalid under the same decoding behavior as the existing bool fields. Go JSON decoding treats `null` for a non-pointer bool as no value, so `null` has the same effective value as absent/false; callers should use an explicit boolean.

The field is per inbound. It is not a global log option, does not alter the access-log destination/path, and does not enable traffic audit for another inbound that shares the same protocol, port, user, or outbound.

## Protobuf and Go fields

`app/proxyman/config.proto` gains the next unused field in `SniffingConfig`:

```proto
// Include a validated sniffed destination, original destination, and
// domain-bearing sniffer source in accepted access messages.
bool log_sniffed_destination = 6;
```

Existing fields use numbers 1 through 5 and none are reserved in `SniffingConfig`. Number 6 must not be reused for another purpose. The generated protobuf JSON name is `logSniffedDestination`.

`infra/conf.SniffingConfig` gains:

```go
LogSniffedDestination bool `json:"logSniffedDestination"`
```

The value is copied through `proxyman.SniffingConfig` into a read-only `session.SniffingRequest.LogSniffedDestination` field. Every existing construction/copy path identified by X-02 must carry it: TCP, UDP, Unix-domain socket, `always.go`, TUN per-flow copy, and WireGuard per-flow copy. VLESS reverse outbound continues to construct its own disabled sniffing request and must not inherit an unrelated inbound opt-in.

## Defaults and compatibility

Proto3 bool zero-value semantics are intentional:

| JSON state | Runtime value | Extended access suffix |
|---|---:|---|
| `sniffing` absent | `false` | never |
| field absent | `false` | never |
| field `null` | `false` | never |
| `"logSniffedDestination": false` | `false` | never |
| `"logSniffedDestination": true` | `true` | only after all gates below pass |

Absent and explicit `false` are observably identical. They produce the same protobuf zero value, the same routing/session behavior, and byte-for-byte upstream access-log output. Existing JSON and serialized protobuf configurations remain valid.

The new field is not a nullable/presence-sensitive `optional bool`: runtime does not need to distinguish absent from false.

## Emission gates

Setting `logSniffedDestination` does not enable or broaden sniffing. The extended `original`/`sniffed` pair from X-03 is emitted only when all conditions are true:

1. A contextual accepted `AccessMessage` exists.
2. `sniffing.enabled` is true.
3. `logSniffedDestination` is true.
4. Existing sniffing returns a successful result with a non-empty domain.
5. Existing `shouldOverride` accepts that result for `destOverride` and exclusions.
6. The domain passes the X-03 normalization/validation contract.

Failure of any gate leaves the entire `AccessMessage` byte-for-byte in upstream form. The flag does not create an access message for a path that currently lacks one, does not add identity, and does not transform rejected or internal DNS messages.

## Interaction with existing fields

### `enabled`

`enabled: false` is authoritative. `logSniffedDestination: true` with sniffing disabled is valid but inert: no payload is read for this option and no extended suffix is emitted.

### `destOverride`

The new option observes the existing successful override decision; it does not add protocols to `destOverride`. An empty or absent list cannot pass `shouldOverride`, so the new option remains inert.

The pinned JSON builder accepts `http`, `tls` (including aliases `https` and `ssl`), `quic`, `fakedns`, and `fakedns+others`; aliases are normalized by existing code. The logged `sniffed` value is the actual domain-bearing runtime result, not the spelling used in JSON.

### `domainsExcluded`

Existing semantics are preserved exactly. The builder lowercases entries. Runtime exclusion is either:

- exact comparison with the sniffed domain after lowercase handling; or
- `regexp:` followed by the existing Go regular expression, matched with `MatchString` and therefore not implicitly anchored.

An excluded domain does not pass `shouldOverride`; consequently neither the primary access-log destination nor the extended suffix changes. The logging option must not run a second, divergent exclusion implementation.

### `ipsExcluded`

Pinned Xray `v26.3.27` has no `ipsExcluded` JSON property, protobuf field, runtime field, or dispatcher behavior. Repository-wide static search confirms its absence. X-04 does not introduce unrelated IP-exclusion semantics.

For X-05/X-18, `ipsExcluded` rows are `N/A` for the pinned base with this source evidence unless a separate requirement explicitly adds and defines that feature. Unknown JSON handling remains upstream behavior; users must not rely on `ipsExcluded` affecting this option.

### `metadataOnly`

`metadataOnly: true` preserves current behavior: payload sniffers are not read. A FakeDNS metadata hit can still produce a domain and, if every emission gate passes, an extended line. HTTP Host, TLS SNI, QUIC SNI, and `fakedns+others` payload fallback cannot independently produce an extended line in metadata-only mode.

The logging option never overrides `metadataOnly` and never waits for payload that upstream would not read.

### `routeOnly`

`routeOnly` affects routing state, not what was observed. After an accepted non-FakeDNS sniff result:

- `routeOnly: false` keeps current behavior: `Outbound.Target` becomes the sniffed destination.
- `routeOnly: true` keeps current behavior: `Outbound.Target` remains original and `Outbound.RouteTarget` receives the sniffed destination.
- FakeDNS/fake-IP exceptions retain their current target behavior.

With logging enabled, both cases may show the sniffed domain as the primary access-log destination and the pre-sniff typed destination in `original`. The helper updates only the contextual `AccessMessage`; it must not write `Outbound.Target`, `Outbound.RouteTarget`, DNS state, or the destination passed to routing. Thus enabling logging cannot change the selected outbound or dial target.

### FakeDNS and `fakedns+others`

- A FakeDNS mapping hit logs source `fakedns` and preserves the fake IP as `original`.
- When the fake IP is in pool, the FakeDNS lookup misses, and a payload sniffer supplies the domain through the combined path, source is `fakedns+others`.
- A mapping miss without a successful domain-bearing fallback remains in legacy form.
- A destination outside the fake pool retains existing behavior.

The option never performs its own FakeDNS lookup and never substitutes a domain from DNS cache or ordinary resolution.

## Truth table

| enabled | log option | successful domain result | accepted by `shouldOverride` | extended output |
|---:|---:|---:|---:|---:|
| false | false/true | N/A | N/A | no |
| true | false | false/true | false/true | no |
| true | true | false | false | no |
| true | true | true | false | no |
| true | true | true | true | yes |

`routeOnly` does not alter the last column. `metadataOnly` and FakeDNS influence whether a successful result can exist, but do not bypass any gate.

## Invalid and edge configurations

- `logSniffedDestination: true` with `enabled: false` is accepted and inert rather than rejected, preserving composability and zero-value behavior.
- `logSniffedDestination: true` with no `destOverride` is accepted and inert.
- Invalid non-null JSON types fail configuration parsing; no truthy string/number coercion is permitted. JSON `null` retains the zero value, consistent with existing bool fields.
- A config sent through protobuf with unknown future fields retains protobuf compatibility rules. Old binaries ignore field 6 and retain upstream behavior; new binaries read it as false when absent.
- Dynamic configuration replacement follows the existing inbound lifecycle. This option does not add a separate runtime control plane or mutate already-created connection contexts.

## Required implementation tests for X-07/X-08

1. JSON absent, false, and true reach the expected protobuf/runtime bool; invalid types fail.
2. Existing configs serialize/build unchanged when the field is absent.
3. TCP, UDP, Unix-domain socket, `always.go`, TUN, and WireGuard copies preserve the value without shared mutable state.
4. Disabled sniffing and empty `destOverride` remain inert even when the new bool is true.
5. `routeOnly` true/false produce identical audit observation but unchanged, distinct upstream routing state.
6. `domainsExcluded` exact/regexp matches suppress both override and extended output; no-match permits both.
7. FakeDNS hit, combined fallback, miss, metadata-only, and non-pool cases follow the rules above.
8. Static compatibility checks fail if a new `SniffingRequest` constructor/copy appears without explicit classification.
