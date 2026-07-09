import XCTest
import Foundation
import DNSCore
@testable import DNSTypes

final class ZoneTests: XCTestCase {
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    // MARK: Lexer

    func testLexerBasics() {
        XCTAssertEqual(lexPresentationLine("example.com. 3600 IN A 192.0.2.1"),
                       ["example.com.", "3600", "IN", "A", "192.0.2.1"])
    }
    func testLexerQuotesAndComments() {
        XCTAssertEqual(lexPresentationLine(#"x IN TXT "hello world" "a;b" ; trailing"#),
                       ["x", "IN", "TXT", "hello world", "a;b"])
    }
    func testLexerParensContinuation() {
        XCTAssertEqual(lexPresentationLine("x IN SOA ( ns hm 1 2 3 4 5 )"),
                       ["x", "IN", "SOA", "ns", "hm", "1", "2", "3", "4", "5"])
    }

    // MARK: Differential parse vs miekg

    func testnewRRMatchesGoOracle() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("oracle_zone.json")
        let data = try Data(contentsOf: url)
        let vectors = try JSONSerialization.jsonObject(with: data) as! [[String: String]]
        XCTAssertFalse(vectors.isEmpty)

        for vec in vectors {
            let line = vec["line"]!, expected = vec["hex"]!
            let rr = try newRR(line)
            let got = hex(try rr.packedBytes(compress: false))
            XCTAssertEqual(got, expected, "parse mismatch vs miekg for line: \(line)")
        }
    }

    // MARK: Header parsing flexibility

    func testTTLAndClassOptionalAndReordered() throws {
        // TTL/class omitted -> defaults; class-before-TTL also accepted.
        let a = try newRR("host.example.com. A 10.0.0.1", defaultTTL: 300)
        XCTAssertEqual(a.header.ttl, 300)
        XCTAssertEqual(a.header.class, .in)
        let b = try newRR("host.example.com. IN 60 A 10.0.0.2")
        XCTAssertEqual(b.header.ttl, 60)
        XCTAssertEqual((b as? A)?.a.description, "10.0.0.2")
    }

    func testRelativeNameQualifiedByOrigin() throws {
        let rr = try newRR("www 3600 IN A 192.0.2.7", origin: "example.com.")
        XCTAssertEqual(rr.header.name.value, "www.example.com.")
    }

    // MARK: Render -> parse round-trips

    func testPresentRoundTrips() throws {
        let records: [any RR] = [
            MX(header: RRHeader(name: Name("example.com."), type: .mx, ttl: 3600),
               preference: 10, mx: Name("mail.example.com.")),
            DS(header: RRHeader(name: Name("example.com."), type: .ds, ttl: 3600),
               keyTag: 9999, algorithm: 13, digestType: 2, digest: Array(0..<16)),
            DNSKEY(header: RRHeader(name: Name("example.com."), type: .dnskey, ttl: 3600),
                   flags: 257, proto: 3, algorithm: 8, publicKey: Array(0..<24)),
            TXT(header: RRHeader(name: Name("example.com."), type: .txt, ttl: 3600),
                txt: ["one", "two three"]),
        ]
        for rr in records {
            let text = try rr.present()
            let reparsed = try newRR(text)
            XCTAssertEqual(hex(try reparsed.packedBytes(compress: false)),
                           hex(try rr.packedBytes(compress: false)),
                           "present->newRR round-trip failed for \(text)")
        }
    }

    func testUnsupportedPresentationThrows() {
        // NSEC3 has size-prefixed fields (presentation deferred) -> render throws.
        let nsec3 = NSEC3(header: RRHeader(name: Name("x."), type: .nsec3, ttl: 60),
                          hash: 1, flags: 0, iterations: 12, saltLength: 0, salt: [],
                          hashLength: 0, nextDomain: [], typeBitMap: [1, 2])
        XCTAssertThrowsError(try nsec3.present())
    }
}
