# SwiftDNS

A complete DNS library for Swift — a port of the Go [`miekg/dns`](https://github.com/miekg/dns)
library. It supports client- and server-side programming: building and parsing
messages, ~80 resource-record types, EDNS0, SVCB/HTTPS, zone-file parsing,
DNSSEC signing/validation, TSIG, dynamic updates, and zone transfers.

Built on [SwiftNIO](https://github.com/apple/swift-nio) for async networking and
[swift-crypto](https://github.com/apple/swift-crypto) for DNSSEC. Cross-platform
(macOS and Linux).

## Packages

| Target | Purpose |
| --- | --- |
| `DNSCore` | Wire primitives: buffers, name compression, addresses (no dependencies) |
| `DNSTypes` | The `RR` protocol, ~80 record types, `Msg`, EDNS0, SVCB/HTTPS, zone parsing |
| `DNSClient` | Async resolver over UDP/TCP, zone transfers, `resolv.conf` |
| `DNSServer` | `DNSServer`, `ServeMux`, handlers (UDP + TCP) |
| `DNSSEC` | Key tags, DS, RRSIG sign/verify, NSEC3 hashing, TSIG |

Record wire codecs and presentation (zone-text) forms are generated at compile
time by the `@DNSRecord` macro (in the `DNSMacros` target) from each record's
fields — the Swift equivalent of the Go library's `go generate` step.

## Quick start

```swift
import DNSClient
import DNSTypes

let client = DNSClient()
let reply = try await client.query("example.com.", .a, server: "8.8.8.8")
print(reply)                       // dig-style output
for case let a as A in reply.answers { print(a.a) }
try await client.shutdown()
```

Parse a record from zone text, or a whole zone file:

```swift
let rr = try NewRR("example.com. 3600 IN MX 10 mail.example.com.")
let records = try parseZone(zoneFileText, origin: "example.com.")
```

## Differential testing

The port is verified byte-for-byte against the reference `miekg/dns`
implementation. `oracle/` is a small Go program that packs records, messages,
zone lines, DNSSEC signatures, TSIG, and updates with the real library and
writes golden vectors under `Tests/`; the Swift test suite asserts identical
output (and, for DNSSEC/TSIG, verifies the reference's signatures).

The Go sources of the original library have been removed (this is now a pure
Swift package); the pre-port state is preserved at the `go-oracle-source` git
tag. To regenerate the vectors:

```sh
cd oracle && go run .
```

The oracle fetches upstream `miekg/dns` via its own `go.mod`, so no Go sources
live in the package itself.

## License

BSD-3-Clause, inherited from `miekg/dns`. See `LICENSE` and `COPYRIGHT`.
