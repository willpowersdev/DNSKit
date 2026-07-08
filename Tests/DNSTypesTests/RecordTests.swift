import XCTest
import DNSCore
@testable import DNSTypes

final class RecordTests: XCTestCase {
    private func hdr(_ name: String, _ type: RRType) -> RRHeader {
        RRHeader(name: Name(name), type: type, class: .in, ttl: 3600)
    }

    func testARdataGolden() throws {
        let a = A(header: hdr("example.com.", .a), a: IPv4Address("192.0.2.1"))
        var p = MessagePacker()
        try a.packRdata(into: &p)
        XCTAssertEqual(p.bytes, [192, 0, 2, 1])
    }

    func testMXRdataGolden() throws {
        let mx = MX(header: hdr("example.com.", .mx), preference: 10, mx: Name("mail.example.com."))
        var p = MessagePacker()
        try mx.packRdata(into: &p)
        // preference(10) + 4 m a i l 7 e x a m p l e 3 c o m 0
        let expected: [UInt8] = [0, 10,
            4, 109, 97, 105, 108,
            7, 101, 120, 97, 109, 112, 108, 101,
            3, 99, 111, 109, 0]
        XCTAssertEqual(p.bytes, expected)
    }

    func testAFullRoundTrip() throws {
        let a = A(header: hdr("example.com.", .a), a: IPv4Address("192.0.2.1"))
        var p = MessagePacker()
        try a.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let back = try A.unpack(from: &u)
        XCTAssertEqual(back.header.name.value, "example.com.")
        XCTAssertEqual(back.header.type, .a)
        XCTAssertEqual(back.header.ttl, 3600)
        XCTAssertEqual(back.a.bytes, [192, 0, 2, 1])
    }

    func testAAAARoundTrip() throws {
        let ip = IPv6Address("2001:db8::1")
        let aaaa = AAAA(header: hdr("example.com.", .aaaa), aaaa: ip)
        var p = MessagePacker()
        try aaaa.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let back = try AAAA.unpack(from: &u)
        XCTAssertEqual(back.aaaa.bytes, ip.bytes)
    }

    func testMXFullRoundTrip() throws {
        let mx = MX(header: hdr("example.com.", .mx), preference: 20, mx: Name("mail.example.com."))
        var p = MessagePacker()
        try mx.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let back = try MX.unpack(from: &u)
        XCTAssertEqual(back.preference, 20)
        XCTAssertEqual(back.mx.value, "mail.example.com.")
    }

    func testTXTRoundTrip() throws {
        let txt = TXT(header: hdr("example.com.", .txt), txt: ["hello", "world", ""])
        var p = MessagePacker()
        try txt.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let back = try TXT.unpack(from: &u)
        XCTAssertEqual(back.txt, ["hello", "world", ""])
    }

    func testSOARoundTrip() throws {
        let soa = SOA(header: hdr("example.com.", .soa),
                      ns: Name("ns1.example.com."), mbox: Name("hostmaster.example.com."),
                      serial: 2024010101, refresh: 7200, retry: 3600, expire: 1209600, minttl: 3600)
        var p = MessagePacker()
        try soa.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let back = try SOA.unpack(from: &u)
        XCTAssertEqual(back.ns.value, "ns1.example.com.")
        XCTAssertEqual(back.mbox.value, "hostmaster.example.com.")
        XCTAssertEqual(back.serial, 2024010101)
        XCTAssertEqual(back.expire, 1209600)
    }

    // Compression across records: two MX records sharing "example.com." must
    // round-trip correctly when packed into one message.
    func testMultiRecordCompression() throws {
        let mx1 = MX(header: hdr("example.com.", .mx), preference: 10, mx: Name("mail.example.com."))
        let mx2 = MX(header: hdr("example.com.", .mx), preference: 20, mx: Name("mail2.example.com."))
        var p = MessagePacker()
        try mx1.pack(into: &p)
        try mx2.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let b1 = try MX.unpack(from: &u)
        let b2 = try MX.unpack(from: &u)
        XCTAssertEqual(b1.mx.value, "mail.example.com.")
        XCTAssertEqual(b2.mx.value, "mail2.example.com.")
        XCTAssertEqual(b2.preference, 20)
    }
}
