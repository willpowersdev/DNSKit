import XCTest
import Foundation
import DNSCore
@testable import DNSTypes

/// Differential test of the full message codec against miekg/dns.
/// `oracle_messages.json` holds each message packed both uncompressed and
/// compressed. We require byte-identical *uncompressed* output, and we require
/// that Swift can *decompress* miekg's compressed form back to the same message
/// (compression itself is implementation-defined, so byte-identity of the
/// compressed form is intentionally not required).
final class MessageDifferentialTests: XCTestCase {
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    private func bytes(fromHex s: String) -> [UInt8] {
        var out: [UInt8] = []; var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return out
    }

    private func hdr(_ name: String, _ type: RRType, ttl: UInt32) -> RRHeader {
        RRHeader(name: Name(name), type: type, class: .in, ttl: ttl)
    }

    private func query() -> Msg {
        var h = MsgHeader(id: 0x1234); h.recursionDesired = true
        return Msg(header: h, questions: [Question(Name("www.example.com."), .a)])
    }

    private func response() -> Msg {
        var h = MsgHeader(id: 0x1234)
        h.response = true; h.authoritative = true
        h.recursionDesired = true; h.recursionAvailable = true
        return Msg(
            header: h,
            questions: [Question(Name("www.example.com."), .a)],
            answers: [
                A(header: hdr("www.example.com.", .a, ttl: 300), a: IPv4Address("192.0.2.1")),
                A(header: hdr("www.example.com.", .a, ttl: 300), a: IPv4Address("192.0.2.2")),
            ],
            authorities: [
                NS(header: hdr("example.com.", .ns, ttl: 3600), ns: Name("ns1.example.com.")),
                NS(header: hdr("example.com.", .ns, ttl: 3600), ns: Name("ns2.example.com.")),
            ],
            additionals: [
                A(header: hdr("ns1.example.com.", .a, ttl: 3600), a: IPv4Address("192.0.2.53")),
            ]
        )
    }

    private func loadVectors() throws -> [String: [String: String]] {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("oracle_messages.json")
        let data = try Data(contentsOf: url)
        return try JSONSerialization.jsonObject(with: data) as! [String: [String: String]]
    }

    func testMessagesMatchGoOracle() throws {
        let vectors = try loadVectors()
        for (name, msg) in [("query", query()), ("response", response())] {
            guard let vec = vectors[name],
                  let uncompressedHex = vec["uncompressed"],
                  let compressedHex = vec["compressed"] else {
                XCTFail("missing oracle vectors for \(name)"); continue
            }

            // 1. Swift uncompressed pack must byte-match miekg exactly.
            XCTAssertEqual(hex(try msg.pack(compress: false)), uncompressedHex,
                           "\(name): uncompressed pack mismatch vs miekg")

            // 2. Swift must decompress miekg's compressed message: unpack it,
            //    re-pack uncompressed, and land on the same bytes.
            let fromCompressed = try Msg(unpacking: bytes(fromHex: compressedHex))
            XCTAssertEqual(hex(try fromCompressed.pack(compress: false)), uncompressedHex,
                           "\(name): failed to decompress miekg's compressed form")

            // 3. Swift must unpack miekg's uncompressed message equivalently.
            let fromUncompressed = try Msg(unpacking: bytes(fromHex: uncompressedHex))
            XCTAssertEqual(hex(try fromUncompressed.pack(compress: false)), uncompressedHex,
                           "\(name): unpack of uncompressed form not stable")

            // 4. Swift's own compression must round-trip.
            let selfRoundTrip = try Msg(unpacking: msg.pack(compress: true))
            XCTAssertEqual(hex(try selfRoundTrip.pack(compress: false)), uncompressedHex,
                           "\(name): Swift compress -> unpack -> uncompress not stable")
        }
    }
}
