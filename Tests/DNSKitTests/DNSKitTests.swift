import XCTest
import DNSKit  // the single umbrella import re-exports every internal module

final class DNSKitTests: XCTestCase {
    /// Symbols from DNSCore, DNSTypes, DNSClient, and DNSSEC must all be
    /// reachable through the one `import DNSKit`.
    func testUmbrellaImportExposesEntireLibrary() throws {
        let name = Name("example.com.")                             // DNSCore
        let a = A(header: RRHeader(name: name, type: .a, ttl: 300), // DNSTypes
                  a: IPv4Address("192.0.2.1"))
        let wire = try Msg(header: MsgHeader(id: 1), answers: [a]).pack()
        let parsed = try Msg(unpacking: wire)                       // DNSTypes
        XCTAssertEqual((parsed.answers.first as? A)?.a.description, "192.0.2.1")

        _ = DNSClient()                                             // DNSClient

        let key = DNSKEY(header: RRHeader(name: name, type: .dnskey, ttl: 0),
                         flags: 256, proto: 3, algorithm: 13, publicKey: Array(0..<64))
        XCTAssertNoThrow(try DNSSEC.keyTag(key))                    // DNSSEC
    }

    /// Data-model / parser code is platform-neutral and works everywhere.
    func testPlatformNeutralParsing() throws {
        let rr = try newRR("example.com. 3600 IN MX 10 mail.example.com.")
        XCTAssertEqual((rr as? MX)?.preference, 10)

        let config = ClientConfig(parsing: "nameserver 1.1.1.1\noptions ndots:2\n")
        XCTAssertEqual(config.nameservers, ["1.1.1.1"])
        XCTAssertEqual(config.ndots, 2)
    }

    /// The platform-gated error type is exposed and usable.
    func testUnsupportedPlatformErrorIsReachable() {
        let error: any Error = DNSError.unsupportedPlatform
        XCTAssertEqual(error as? DNSError, .unsupportedPlatform)
    }
}
