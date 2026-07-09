import XCTest
import DNSCore
@testable import DNSTypes

final class MessageTests: XCTestCase {
    func testHeaderBitsRoundTrip() {
        var h = MsgHeader(id: 42)
        h.response = true
        h.opcode = 5
        h.authoritative = true
        h.recursionDesired = true
        h.checkingDisabled = true
        h.rcode = 9
        var decoded = MsgHeader(id: 42)
        decoded.bits = h.bits
        XCTAssertEqual(decoded, h)
    }

    func testKnownFlagBitLayout() {
        var h = MsgHeader()
        h.response = true            // 0x8000
        h.recursionDesired = true    // 0x0100
        h.recursionAvailable = true  // 0x0080
        XCTAssertEqual(h.bits, 0x8180)
    }

    func testUnknownTypeFallsBackToRFC3597() throws {
        // Build a record of an unregistered type by packing an RFC3597 blob,
        // then unpack via the polymorphic path.
        let unknown = RFC3597(header: RRHeader(name: Name("x."), type: RRType(rawValue: 9999),
                                               class: .in, ttl: 60),
                              rdata: [0xCA, 0xFE, 0xBA, 0xBE])
        var p = MessagePacker()
        try unknown.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let rr = try unpackRR(from: &u)
        let back = try XCTUnwrap(rr as? RFC3597)
        XCTAssertEqual(back.header.type.rawValue, 9999)
        XCTAssertEqual(back.rdata, [0xCA, 0xFE, 0xBA, 0xBE])
    }

    func testMixedMessageRoundTrip() throws {
        let msg = Msg(
            header: MsgHeader(id: 7, response: true),
            questions: [Question(Name("example.com."), .any)],
            answers: [
                MX(header: RRHeader(name: Name("example.com."), type: .mx, ttl: 300),
                   preference: 10, mx: Name("mail.example.com.")),
                TXT(header: RRHeader(name: Name("example.com."), type: .txt, ttl: 300),
                    txt: ["v=spf1 -all"]),
            ]
        )
        let wire = try msg.pack()
        let back = try Msg(unpacking: wire)
        XCTAssertEqual(back.header.id, 7)
        XCTAssertTrue(back.header.response)
        XCTAssertEqual(back.questions.first?.name.value, "example.com.")
        XCTAssertEqual(back.answers.count, 2)
        XCTAssertEqual((back.answers[0] as? MX)?.mx.value, "mail.example.com.")
        XCTAssertEqual((back.answers[1] as? TXT)?.txt, ["v=spf1 -all"])
    }
}
