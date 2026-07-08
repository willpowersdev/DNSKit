import XCTest
import DNSCore
@testable import DNSTypes

final class EDNS0Tests: XCTestCase {
    func testHeaderFieldEncoding() {
        var opt = OPT(udpSize: 4096, dnssecOK: true, version: 0)
        XCTAssertEqual(opt.udpSize, 4096)
        XCTAssertTrue(opt.dnssecOK)
        XCTAssertEqual(opt.header.type, .opt)
        XCTAssertEqual(opt.header.ttl & 0x8000, 0x8000) // DO bit
        opt.dnssecOK = false
        XCTAssertEqual(opt.header.ttl & 0x8000, 0)
        opt.z = 0x1FFF
        XCTAssertEqual(opt.z, 0x1FFF)
    }

    func testOptionRoundTripThroughMessage() throws {
        let opt = OPT(udpSize: 1232, dnssecOK: true, options: [
            EDNS0_NSID(nsid: [0xDE, 0xAD]),
            EDNS0_COOKIE(cookie: Array(0..<8)),
            EDNS0_EDE(infoCode: 18, extraText: "prohibited"),
            EDNS0_SUBNET(family: 1, sourceNetmask: 24, sourceScope: 0, address: [203, 0, 113]),
            EDNS0_TCP_KEEPALIVE(timeout: 200),
            EDNS0_EXPIRE(expire: 3600),
            EDNS0_PADDING(padding: Array(repeating: 0, count: 6)),
        ])
        // Carry the OPT in a real message's additional section and round-trip.
        let msg = Msg(header: MsgHeader(id: 99, response: true),
                      questions: [Question(Name("example.com."), .a)],
                      additionals: [opt])
        let back = try Msg(unpacking: msg.pack())
        let decoded = try XCTUnwrap(back.additionals.first as? OPT)
        XCTAssertEqual(decoded.udpSize, 1232)
        XCTAssertTrue(decoded.dnssecOK)
        XCTAssertEqual(decoded.options.count, 7)

        XCTAssertEqual((decoded.options[0] as? EDNS0_NSID)?.nsid, [0xDE, 0xAD])
        XCTAssertEqual((decoded.options[1] as? EDNS0_COOKIE)?.cookie, Array(0..<8))
        let ede = try XCTUnwrap(decoded.options[2] as? EDNS0_EDE)
        XCTAssertEqual(ede.infoCode, 18)
        XCTAssertEqual(ede.extraText, "prohibited")
        let subnet = try XCTUnwrap(decoded.options[3] as? EDNS0_SUBNET)
        XCTAssertEqual(subnet.sourceNetmask, 24)
        XCTAssertEqual(subnet.address, [203, 0, 113])
        XCTAssertEqual((decoded.options[4] as? EDNS0_TCP_KEEPALIVE)?.timeout, 200)
        XCTAssertEqual((decoded.options[5] as? EDNS0_EXPIRE)?.expire, 3600)
        XCTAssertEqual((decoded.options[6] as? EDNS0_PADDING)?.padding.count, 6)
    }

    func testUnknownOptionFallsBackToLocal() throws {
        let opt = OPT(options: [EDNS0_LOCAL(code: 0x1234, data: [1, 2, 3])])
        var p = MessagePacker()
        try opt.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let back = try XCTUnwrap(try unpackRR(from: &u) as? OPT)
        let local = try XCTUnwrap(back.options.first as? EDNS0_LOCAL)
        XCTAssertEqual(local.code, 0x1234)
        XCTAssertEqual(local.data, [1, 2, 3])
    }

    func testEmptyTimeoutAndExpireOmitData() throws {
        let opt = OPT(options: [EDNS0_TCP_KEEPALIVE(timeout: nil), EDNS0_EXPIRE(expire: nil)])
        var p = MessagePacker()
        try opt.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let back = try XCTUnwrap(try unpackRR(from: &u) as? OPT)
        XCTAssertNil((back.options[0] as? EDNS0_TCP_KEEPALIVE)?.timeout)
        XCTAssertNil((back.options[1] as? EDNS0_EXPIRE)?.expire)
    }
}
