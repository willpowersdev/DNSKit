import XCTest
import DNSCore
@testable import DNSTypes

final class SVCBTests: XCTestCase {
    func testParamsRoundTripThroughMessage() throws {
        let svcb = SVCB(header: RRHeader(name: Name("example.com."), type: .svcb, ttl: 300),
                        priority: 16, target: Name("svc.example.net."), values: [
            SVCBAlpn(alpn: ["h2", "h3"]),
            SVCBPort(port: 8443),
            SVCBIPv4Hint(hints: [IPv4Address("203.0.113.1")]),
            SVCBIPv6Hint(hints: [IPv6Address("2001:db8::1")]),
            SVCBMandatory(codes: [SVCBKey.alpn]),
            SVCBECHConfig(ech: [1, 2, 3, 4]),
        ])
        let msg = Msg(header: MsgHeader(id: 1, response: true), answers: [svcb])
        let back = try Msg(unpacking: msg.pack())
        let decoded = try XCTUnwrap(back.answers.first as? SVCB)
        XCTAssertEqual(decoded.priority, 16)
        XCTAssertEqual(decoded.target.value, "svc.example.net.")
        // Params come back sorted by key: mandatory(0), alpn(1), port(3), ipv4(4), ech(5), ipv6(6).
        XCTAssertEqual(decoded.values.map(\.key), [0, 1, 3, 4, 5, 6])
        XCTAssertEqual((decoded.values.first { $0.key == SVCBKey.alpn } as? SVCBAlpn)?.alpn, ["h2", "h3"])
        XCTAssertEqual((decoded.values.first { $0.key == SVCBKey.port } as? SVCBPort)?.port, 8443)
        XCTAssertEqual((decoded.values.first { $0.key == SVCBKey.ipv4hint } as? SVCBIPv4Hint)?.hints.first?.description, "203.0.113.1")
        XCTAssertEqual((decoded.values.first { $0.key == SVCBKey.mandatory } as? SVCBMandatory)?.codes, [SVCBKey.alpn])
    }

    func testAliasFormRoundTrip() throws {
        // Alias mode: priority 0, target set, no params.
        let https = HTTPS(header: RRHeader(name: Name("example.com."), type: .https, ttl: 300),
                          priority: 0, target: Name("svc.example.com."))
        var p = MessagePacker()
        try https.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let back = try XCTUnwrap(try unpackRR(from: &u) as? HTTPS)
        XCTAssertEqual(back.priority, 0)
        XCTAssertEqual(back.target.value, "svc.example.com.")
        XCTAssertTrue(back.values.isEmpty)
    }

    func testUnknownKeyFallsBackToLocal() throws {
        let svcb = SVCB(header: RRHeader(name: Name("x."), type: .svcb, ttl: 60),
                        priority: 1, target: Name("."), values: [SVCBLocal(key: 65400, data: [9, 8, 7])])
        var p = MessagePacker()
        try svcb.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        let back = try XCTUnwrap(try unpackRR(from: &u) as? SVCB)
        let local = try XCTUnwrap(back.values.first as? SVCBLocal)
        XCTAssertEqual(local.key, 65400)
        XCTAssertEqual(local.data, [9, 8, 7])
    }

    func testPresentationRenderParseRoundTrip() throws {
        let https = HTTPS(header: RRHeader(name: Name("example.com."), type: .https, ttl: 3600),
                          priority: 1, target: Name("."), values: [
            SVCBAlpn(alpn: ["h2", "h3"]),
            SVCBPort(port: 443),
            SVCBIPv4Hint(hints: [IPv4Address("192.0.2.1")]),
            SVCBNoDefaultAlpn(),
        ])
        let text = try https.present()
        XCTAssertTrue(text.contains("alpn=\"h2,h3\""))
        XCTAssertTrue(text.contains("port=443"))
        XCTAssertTrue(text.contains("no-default-alpn"))

        let reparsed = try newRR(text)
        XCTAssertEqual(try reparsed.packedBytes(compress: false),
                       try https.packedBytes(compress: false))
    }

    func testRejectsDuplicateKeys() {
        let svcb = SVCB(header: RRHeader(name: Name("x."), type: .svcb, ttl: 60),
                        priority: 1, target: Name("."),
                        values: [SVCBPort(port: 1), SVCBPort(port: 2)])
        var p = MessagePacker()
        XCTAssertThrowsError(try svcb.pack(into: &p))
    }
}
