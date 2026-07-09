import XCTest
import DNSCore
@testable import DNSTypes

final class GatewayRecordTests: XCTestCase {
    private func roundTrip(_ rr: any RR) throws -> any RR {
        var p = MessagePacker()
        try rr.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        return try unpackRR(from: &u)
    }

    func testIPSECKEYGatewayVariants() throws {
        let hdr = RRHeader(name: Name("example.com."), type: .ipseckey, ttl: 3600)
        for gw: Gateway in [.none, .ipv4(IPv4Address("192.0.2.1")),
                            .ipv6(IPv6Address("2001:db8::1")), .host(Name("gw.example.com."))] {
            let rec = IPSECKEY(header: hdr, precedence: 10, algorithm: 2, gateway: gw, publicKey: [1, 2, 3, 4])
            let back = try XCTUnwrap(try roundTrip(rec) as? IPSECKEY)
            XCTAssertEqual(back.gateway, gw)
            XCTAssertEqual(back.publicKey, [1, 2, 3, 4])
            XCTAssertEqual(back.precedence, 10)
        }
    }

    func testAMTRELAYDiscoveryBit() throws {
        let hdr = RRHeader(name: Name("example.com."), type: .amtrelay, ttl: 3600)
        let rec = AMTRELAY(header: hdr, precedence: 5, discovery: true, gateway: .ipv6(IPv6Address("2001:db8::2")))
        let back = try XCTUnwrap(try roundTrip(rec) as? AMTRELAY)
        XCTAssertTrue(back.discovery)
        XCTAssertEqual(back.gateway, .ipv6(IPv6Address("2001:db8::2")))
    }

    func testAPLPrefixes() throws {
        let hdr = RRHeader(name: Name("example.com."), type: .apl, ttl: 3600)
        let rec = APL(header: hdr, prefixes: [
            APLPrefix(family: 1, prefix: 24, negation: false, afdPart: [192, 0, 2]),
            APLPrefix(family: 2, prefix: 48, negation: true, afdPart: [0x20, 0x01, 0x0d, 0xb8, 0, 1]),
        ])
        let back = try XCTUnwrap(try roundTrip(rec) as? APL)
        XCTAssertEqual(back.prefixes.count, 2)
        XCTAssertEqual(back.prefixes[0].afdPart, [192, 0, 2])
        XCTAssertTrue(back.prefixes[1].negation)
        XCTAssertEqual(back.prefixes[1].prefix, 48)
    }
}
