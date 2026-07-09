import XCTest
import Foundation
import DNSCore
@testable import DNSTypes

final class UpdateTests: XCTestCase {
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    func testUpdateMatchesGoOracle() throws {
        var u = DNSUpdate(zone: Name("example.com."), id: 0x1234)
        u.requireNameInUse(Name("must.example.com."))
        u.insert([A(header: RRHeader(name: Name("host.example.com."), type: .a, ttl: 3600),
                    a: IPv4Address("192.0.2.10"))])
        u.removeRRset(Name("old.example.com."), .txt)
        u.removeName(Name("gone.example.com."))

        XCTAssertEqual(u.message.header.opcode, Opcode.update)

        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("oracle_update.json")
        let data = try Data(contentsOf: url)
        let vec = try JSONSerialization.jsonObject(with: data) as! [String: String]
        XCTAssertEqual(hex(try u.message.pack(compress: false)), vec["wire"]!,
                       "UPDATE wire mismatch vs miekg")
    }

    func testUpdateSectionsRoundTrip() throws {
        var u = DNSUpdate(zone: Name("example.org."), id: 7)
        u.insert([A(header: RRHeader(name: Name("a.example.org."), type: .a, ttl: 60),
                    a: IPv4Address("10.0.0.1"))])
        u.remove([A(header: RRHeader(name: Name("b.example.org."), type: .a, ttl: 0),
                    a: IPv4Address("10.0.0.2"))])
        let back = try Msg(unpacking: u.message.pack())
        XCTAssertEqual(back.header.opcode, Opcode.update)
        XCTAssertEqual(back.questions.first?.qtype, .soa)
        XCTAssertEqual(back.authorities.count, 2)
        // The delete uses class NONE.
        XCTAssertEqual(back.authorities[1].header.class, .none)
    }
}
