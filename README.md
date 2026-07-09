# DNSKit

[![CI](https://github.com/willpowersdev/DNSKit/actions/workflows/ci.yml/badge.svg)](https://github.com/willpowersdev/DNSKit/actions/workflows/ci.yml)

A complete, cross-platform DNS library for Swift — a port of the Go
[`miekg/dns`](https://github.com/miekg/dns) library. It supports client- and
server-side programming: building and parsing messages, ~80 resource-record
types, EDNS0, SVCB/HTTPS, zone-file parsing, DNSSEC signing/validation, TSIG,
dynamic updates, zone transfers, and DNS-over-TLS (DoT).

Built on [SwiftNIO](https://github.com/apple/swift-nio) for async networking,
[swift-nio-ssl](https://github.com/apple/swift-nio-ssl) for TLS, and
[swift-crypto](https://github.com/apple/swift-crypto) for DNSSEC — all of which
run on **macOS, iOS, and Linux**. There are no Apple-only framework dependencies
(no `Security.framework`); the parsing, encoding, and data-model code is pure,
platform-neutral Swift over `[UInt8]`/`Data`, and the one OS-specific facility
(loading the system resolver config) is isolated behind conditional compilation
and throws `DNSError.unsupportedPlatform` where unavailable.

## Requirements

Swift 6.0+ · macOS 13+ / iOS 16+ / Linux.

## Installation

Add DNSKit to your `Package.swift` (track `master`, or pin a tagged release once
one is published):

```swift
dependencies: [
    .package(url: "https://github.com/willpowersdev/DNSKit.git", branch: "master"),
],
```

then add the `DNSKit` product to your target:

```swift
.target(name: "YourTarget", dependencies: [
    .product(name: "DNSKit", package: "DNSKit"),
]),
```

## Usage

Consumers import a single umbrella module:

```swift
import DNSKit
```

Internally the package is split into focused modules — `DNSCore` (wire
primitives), `DNSTypes` (the `RR` model, `Msg`, EDNS0, SVCB, zone parsing),
`DNSClient`, `DNSServer`, and `DNSSEC` — but these are implementation detail
re-exported through `DNSKit`. Record wire codecs and presentation (zone-text)
forms are generated at compile time by the `@DNSRecord` macro from each record's
fields — the Swift equivalent of the Go library's `go generate` step.

## Quick start

```swift
import DNSKit

let client = DNSClient()
let reply = try await client.query("example.com.", .a, server: "8.8.8.8")
print(reply)                       // dig-style output
for case let a as A in reply.answers { print(a.a) }
try await client.shutdown()
```

Or over DNS-over-TLS (RFC 7858), with the certificate verified against a name:

```swift
let reply = try await client.query(
    "example.com.", .a,
    server: "1.1.1.1", transport: .tls, serverName: "cloudflare-dns.com")
```

`query` and `exchange` are one-shot — they open a connection, send one message,
and close it. To reuse a connection across many queries (and, for TLS, pay the
handshake only once), open a persistent `DNSConnection` with `connect`:

```swift
let conn = try await client.connect(
    to: "1.1.1.1", transport: .tls, serverName: "cloudflare-dns.com")

for name in ["example.com.", "example.org."] {
    var query = Msg(header: MsgHeader(id: .random(in: .min ... .max), recursionDesired: true),
                    questions: [Question(Name(name), .a)])
    let reply = try await conn.exchange(query)
    print(reply.answers)
}
await conn.close()
```

Parse a record from zone text, or a whole zone file:

```swift
let rr = try newRR("example.com. 3600 IN MX 10 mail.example.com.")
let records = try parseZone(zoneFileText, origin: "example.com.")
```

## Differential testing

The port is verified byte-for-byte against the reference `miekg/dns`
implementation. Golden vectors — packed records, messages, zone lines, DNSSEC
signatures, TSIG, and updates — are committed under `Tests/` as JSON; the Swift
test suite asserts identical output (and, for DNSSEC/TSIG/SIG(0), verifies the
reference's signatures). Running the tests requires no Go:

```sh
swift test   # 96 tests
```

The generator that produces those vectors (a small Go program using upstream
`miekg/dns`) lives on the `feature/differential-test-engine` branch, keeping
this package 100% Swift. The pre-port Go source is preserved at the
`go-oracle-source` git tag.

## Platform support

`swift build` and `swift test` run on macOS and Linux, and
[CI](https://github.com/willpowersdev/DNSKit/actions/workflows/ci.yml) exercises
both on every push (Linux in the official `swift:6.0` image; macOS with the
latest Xcode). The package declares minimum Apple OS versions (macOS 13, iOS 16);
Linux has no such floor. All dependencies (SwiftNIO, swift-crypto, swift-syntax
for the macro) are cross-platform, so no `#if canImport(...)` guards are needed
around imports — only the handful of genuinely OS-specific operations use
`#if os(...)` with a `DNSError.unsupportedPlatform` fallback.

## License

BSD-3-Clause, inherited from `miekg/dns`. See `LICENSE` and `COPYRIGHT`.
