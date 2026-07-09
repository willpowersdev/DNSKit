import XCTest
import Foundation
import DNSCore
import DNSTypes
@testable import DNSSEC

final class NSEC3Tests: XCTestCase {
    func testHashMatchesGoOracle() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("oracle_nsec3.json")
        let data = try Data(contentsOf: url)
        let vec = try JSONSerialization.jsonObject(with: data) as! [String: String]

        let salt: [UInt8] = [0xaa, 0xbb, 0xcc, 0xdd]
        let hash = try DNSSEC.nsec3Hash(name: Name(vec["name"]!), salt: salt, iterations: 12)
        XCTAssertEqual(DNSSEC.base32HexEncode(hash), vec["hash"])
    }

    func testBase32HexKnownVector() {
        // RFC 4648 base32hex: "foobar" -> "CPNMUOJ1E8======" (we omit padding).
        XCTAssertEqual(DNSSEC.base32HexEncode(Array("foobar".utf8)), "CPNMUOJ1E8")
    }
}
