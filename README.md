# DNSKit

A complete, cross-platform DNS library for Swift — a port of the Go
[`miekg/dns`](https://github.com/miekg/dns) library. It supports client- and
server-side programming: building and parsing messages, ~80 resource-record
types, EDNS0, SVCB/HTTPS, zone-file parsing, DNSSEC signing/validation, TSIG,
dynamic updates, and zone transfers.

Built on [SwiftNIO](https://github.com/apple/swift-nio) for async networking and
[swift-crypto](https://github.com/apple/swift-crypto) for DNSSEC — both of which
run on **macOS, iOS, and Linux**. There are no Apple-only framework dependencies
(no `Security.framework`); the parsing, encoding, and data-model code is pure,
platform-neutral Swift over `[UInt8]`/`Data`, and the one OS-specific facility
(loading the system resolver config) is isolated behind conditional compilation
and throws `DNSError.unsupportedPlatform` where unavailable.

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

Parse a record from zone text, or a whole zone file:

```swift
let rr = try NewRR("example.com. 3600 IN MX 10 mail.example.com.")
let records = try parseZone(zoneFileText, origin: "example.com.")
```

## Differential testing

The port is verified byte-for-byte against the reference `miekg/dns`
implementation. Golden vectors — packed records, messages, zone lines, DNSSEC
signatures, TSIG, and updates — are committed under `Tests/` as JSON; the Swift
test suite asserts identical output (and, for DNSSEC/TSIG/SIG(0), verifies the
reference's signatures). Running the tests requires no Go:

```sh
swift test   # 93 tests
```

The generator that produces those vectors (a small Go program using upstream
`miekg/dns`) lives on the `feature/differential-test-engine` branch, keeping
this package 100% Swift. The pre-port Go source is preserved at the
`go-oracle-source` git tag.

## Platform support

`swift build` and `swift test` work on macOS and Linux. The package declares
minimum Apple OS versions (macOS 13, iOS 16); Linux has no such floor. All
dependencies (SwiftNIO, swift-crypto, swift-syntax for the macro) are
cross-platform, so no `#if canImport(...)` guards are needed around imports —
only the handful of genuinely OS-specific operations use `#if os(...)` with a
`DNSError.unsupportedPlatform` fallback.

## License

BSD-3-Clause, inherited from `miekg/dns`. See `LICENSE` and `COPYRIGHT`.
