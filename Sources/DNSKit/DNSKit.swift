// DNSKit is the umbrella module for the package: a single `import DNSKit`
// re-exports the whole library — the data model and wire codec (DNSCore,
// DNSTypes), zone parsing, the async client and server, and DNSSEC/TSIG.
//
// The internal modules are organized so that parsing, encoding, and the data
// model stay platform-neutral (pure Swift, `[UInt8]`/`Data`), and the few
// OS-specific facilities (e.g. loading the system resolver configuration) are
// isolated behind conditional compilation and throw `DNSError.unsupportedPlatform`
// where unavailable. From a consumer's perspective this is a normal, cross-
// platform Swift package:
//
//     import DNSKit
//
//     let client = DNSClient()
//     let reply = try await client.query("example.com.", .a, server: "1.1.1.1")

@_exported import DNSCore
@_exported import DNSTypes
@_exported import DNSClient
@_exported import DNSServer
@_exported import DNSSEC
