# Traffic audit access-log grammar

Status: X-03 contract for upstream `v26.3.27` (`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`).

This document fixes the textual contract for the opt-in extended access log. It does not add the configuration field or implement the formatter.

## Compatibility rule

When traffic-audit logging is absent, disabled, or has no successful domain-bearing sniff result, `AccessMessage.String()` must return the exact upstream byte sequence. The logger-owned timestamp and final platform newline are also unchanged.

When enabled and a domain-bearing sniff result is accepted, the existing destination token becomes the sniffed destination and exactly two labeled suffix fields are appended:

```text
 original: <original-destination> sniffed: <sniffer-source>
```

The suffix is appended after the existing optional `email: <email>` field. Existing fields are never reordered. There is no quoting, backslash escaping, percent encoding, or JSON encoding in an access-log line.

## EBNF

ISO/IEC 14977-style notation is used. `? ... ?` denotes a lexical production described in prose.

```ebnf
file-line             = timestamp, " ", access-message, newline ;

timestamp             = date, " ", time ;
date                  = digit, digit, digit, digit, "/",
                        digit, digit, "/", digit, digit ;
time                  = digit, digit, ":", digit, digit, ":", digit, digit,
                        [ ".", digit, { digit } ] ;
newline               = "\n" | "\r\n" ;

access-message        = "from ", from-value, " ", status, " ", to-value,
                        [ " [", detour, "]" ],
                        [ " ", reason ],
                        [ " email: ", email ],
                        [ extended-suffix ] ;

status                = "accepted" | "rejected" ;
extended-suffix       = " original: ", destination,
                        " sniffed: ", sniffer-source ;

destination           = network, ":", host-port ;
network               = "tcp" | "udp" ;
host-port             = domain, ":", port
                      | ipv4, ":", port
                      | "[", ipv6, "]:", port ;

sniffer-source        = source-char, { source-char } ;
source-char           = lowercase | digit | "+" | "-" | "_" | "." ;

from-value            = ? upstream serial.ToString(AccessMessage.From) ? ;
to-value              = ? upstream serial.ToString(AccessMessage.To) ? ;
detour                = ? existing text excluding "]" ? ;
reason                = ? existing upstream reason text ? ;
email                 = non-space, { non-space } ;
domain                = label, { ".", label } ;
label                 = alphanumeric,
                        { alphanumeric | "-" },
                        [ alphanumeric ] ;
ipv4                  = ? canonical dotted-decimal IPv4 ? ;
ipv6                  = ? canonical compressed IPv6 without brackets ? ;
port                  = ? decimal integer 1 through 65535 ? ;
non-space             = ? any byte other than ASCII whitespace ? ;
alphanumeric          = lowercase | digit ;
lowercase             = "a" | "b" | "c" | "d" | "e" | "f" | "g" |
                        "h" | "i" | "j" | "k" | "l" | "m" | "n" |
                        "o" | "p" | "q" | "r" | "s" | "t" | "u" |
                        "v" | "w" | "x" | "y" | "z" ;
digit                 = "0" | "1" | "2" | "3" | "4" |
                        "5" | "6" | "7" | "8" | "9" ;
```

`reason` is intentionally not made structurally parseable: it is an existing free-form upstream field. Extended fields are emitted only for accepted contextual messages after successful sniffing, where the implementation currently uses an empty reason. Consumers interested in traffic audit must parse the accepted-line subset below rather than attempt to split arbitrary rejected reasons.

## Accepted-line regular expressions

The logger prefix uses Go's `log.Ldate | log.Ltime | log.Lmicroseconds`. The canonical emitted timestamp therefore has six fractional digits, although readers may accept no fraction or another positive precision for compatibility with historical fixtures.

Legacy accepted line:

```regex
^(?<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) from (?<source>\S+) accepted (?<destination>(?:tcp|udp):\S+)(?: \[(?<detour>[^\]]+)])?(?: email: (?<email>\S+))?$
```

Extended accepted line:

```regex
^(?<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) from (?<source>\S+) accepted (?<destination>(?:tcp|udp):\S+)(?: \[(?<detour>[^\]]+)])?(?: email: (?<email>\S+))? original: (?<original>(?:tcp|udp):\S+) sniffed: (?<sniffed>[a-z0-9][a-z0-9+._-]*)$
```

Implementations must anchor to the end of the line after trimming the platform newline.

The initial source values are `http`, `tls`, `quic`, `fakedns`, and `fakedns+others`. The lexical form is intentionally extensible so a future domain-bearing sniffer can be added without changing the line grammar. `bittorrent`, `utp`, unknown content, incomplete payload, ECH without an observable destination name, and TLS/QUIC without SNI do not produce the extended suffix.

## Domain and address normalization

Only the sniffed domain is normalized by the new helper:

1. Convert ASCII letters to lowercase.
2. Remove exactly one terminal DNS root dot.
3. Reject an empty result, ASCII whitespace, control bytes, a label longer than 63 bytes, a full name longer than 253 bytes, an empty label, or a label starting/ending with `-`.
4. Preserve an already encoded `xn--` label. No implicit Unicode/IDNA conversion is performed.
5. Do not DNS-resolve the value and do not infer a domain from an IP address.

The original destination is the exact typed `net.Destination` captured before sniffing and is serialized with existing Xray methods. IPv4 is `tcp:192.0.2.10:443`; IPv6 is `tcp:[2001:db8::10]:443`; domain is `tcp:example.com:443`. The network and port must match the accepted connection. The original value is not reconstructed from routing state after override.

The main destination in an extended line uses the normalized sniffed domain but retains the original network and port. This yields an unambiguous pair:

```text
accepted udp:example.com:443 ... original: udp:203.0.113.20:443 sniffed: quic
```

## Canonical examples

Default-off TCP/IPv4; exact upstream form:

```text
2026/07/06 12:00:00.000001 from 198.51.100.10:50000 accepted tcp:203.0.113.20:443 [vless-in >> direct] email: 3
```

Opt-in TLS SNI from TCP/IPv4:

```text
2026/07/06 12:00:00.000001 from 198.51.100.10:50000 accepted tcp:example.com:443 [vless-in >> direct] email: 3 original: tcp:203.0.113.20:443 sniffed: tls
```

Opt-in HTTP Host from TCP/IPv6:

```text
2026/07/06 12:00:01.000002 from [2001:db8::100]:50001 accepted tcp:example.com:80 [socks-in >> direct] email: user@example.com original: tcp:[2001:db8::20]:80 sniffed: http
```

Opt-in QUIC SNI from UDP/IPv6:

```text
2026/07/06 12:00:02.000003 from [2001:db8::100]:50002 accepted udp:example.com:443 [shadowsocks-in >> direct] email: 3 original: udp:[2001:db8::20]:443 sniffed: quic
```

Original domain already known, with successful sniffing to the same normalized domain:

```text
2026/07/06 12:00:03.000004 from 198.51.100.10:50003 accepted tcp:example.com:443 [http-in >> direct] email: alice original: tcp:example.com:443 sniffed: tls
```

FakeDNS:

```text
2026/07/06 12:00:04.000005 from 198.51.100.10:50004 accepted tcp:example.com:443 [tun-in >> direct] original: tcp:198.18.0.42:443 sniffed: fakedns
```

No SNI, ECH without an observable destination name, unknown payload, sniffer failure, excluded domain, or opt-in disabled uses the exact legacy form and contains neither `original:` nor `sniffed:`.

## Consumer compatibility

The current Remnawave node parser starts at the timestamp, accepts the historical optional `from` token, captures the main `tcp|udp` destination and optional email, and is not end-anchored. It therefore continues to parse an extended line as before: the normalized sniffed domain becomes its current `destination`, while the new original/source fields are ignored until X-33 extends the event contract. Lines without email continue to be discarded by the current node.

Line-oriented `tail`, `grep`, and prefix parsers remain compatible because:

- the timestamp, `from`, status, primary destination, detour, and email prefix are unchanged;
- new data is append-only and contains no whitespace inside values;
- every connection remains one physical line;
- no delimiter used by the legacy prefix is reinterpreted.

Consumers that anchor immediately after `email` must update to allow the optional suffix. Consumers must not split the entire line on spaces and infer fixed positions: detour and legacy reason are already variable-width upstream fields.

## Formatter invariants for X-06

- New fields are typed; the formatter does not accept preformatted arbitrary suffix text.
- `original` and `sniffed` are an atomic pair: emit both or neither.
- The pair is emitted only when opt-in is true and a validated domain-bearing sniff result was accepted.
- The `email` field retains its upstream behavior and escaping limitations.
- Rejected/direct `log.Record` messages and internal DNS messages never gain the pair.
- Empty new fields leave `AccessMessage.String()` byte-for-byte identical to upstream.
