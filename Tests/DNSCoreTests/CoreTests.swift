import XCTest
@testable import DNSCore

final class CoreTests: XCTestCase {
    func testNameLabels() throws {
        let labels = try Name("example.com.").labels()
        XCTAssertEqual(labels.map { String(decoding: $0, as: UTF8.self) }, ["example", "com"])
        XCTAssertEqual(try Name(".").labels().count, 0)
    }

    func testNameEscapes() throws {
        // "a\.b.com." is two labels: "a.b" and "com".
        let labels = try Name("a\\.b.com.").labels()
        XCTAssertEqual(labels.map { String(decoding: $0, as: UTF8.self) }, ["a.b", "com"])
    }

    func testNameRoundTripFromLabels() {
        let n = Name.from(labels: [Array("example".utf8), Array("com".utf8)])
        XCTAssertEqual(n.value, "example.com.")
    }

    func testIntegerRoundTrip() throws {
        var p = MessagePacker()
        p.appendUInt8(0xAB); p.appendUInt16(0x1234); p.appendUInt32(0xDEADBEEF)
        XCTAssertEqual(p.bytes, [0xAB, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF])
        var u = MessageUnpacker(p.bytes)
        XCTAssertEqual(try u.readUInt8(), 0xAB)
        XCTAssertEqual(try u.readUInt16(), 0x1234)
        XCTAssertEqual(try u.readUInt32(), 0xDEADBEEF)
    }

    func testNameWireRoundTrip() throws {
        var p = MessagePacker()
        try p.appendName(Name("example.com."), compress: false)
        // 7 e x a m p l e 3 c o m 0
        XCTAssertEqual(p.bytes.first, 7)
        XCTAssertEqual(p.bytes.last, 0)
        var u = MessageUnpacker(p.bytes)
        XCTAssertEqual(try u.readName().value, "example.com.")
    }

    func testNameCompression() throws {
        var p = MessagePacker()
        try p.appendName(Name("a.example.com."), compress: true)
        let afterFirst = p.count
        try p.appendName(Name("b.example.com."), compress: true)
        // Second name shares the "example.com." suffix, so it must be shorter
        // than a full independent encoding (1+"b" label + 2-byte pointer).
        XCTAssertEqual(p.count - afterFirst, 1 + 1 + 2)

        var u = MessageUnpacker(p.bytes)
        XCTAssertEqual(try u.readName().value, "a.example.com.")
        XCTAssertEqual(try u.readName().value, "b.example.com.")
    }

    func testBadForwardPointerRejected() {
        // A pointer at offset 0 pointing to offset 0 is not strictly backward.
        var u = MessageUnpacker([0xC0, 0x00])
        XCTAssertThrowsError(try u.readName())
    }

    func testIPv4RoundTrip() {
        let ip = IPv4Address("192.0.2.1")
        XCTAssertEqual(ip.bytes, [192, 0, 2, 1])
        XCTAssertEqual(ip.description, "192.0.2.1")
    }
}
