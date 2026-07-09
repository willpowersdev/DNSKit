import XCTest
import Foundation
import DNSCore
import DNSTypes
@testable import DNSSEC

final class TSIGTests: XCTestCase {
    private func bytes(fromHex s: String) -> [UInt8] {
        var out: [UInt8] = []; var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return out
    }

    /// Interop: verify a TSIG-signed message produced by miekg's TsigGenerate.
    func testVerifiesGoTSIG() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("oracle_tsig.json")
        let data = try Data(contentsOf: url)
        let vec = try JSONSerialization.jsonObject(with: data) as! [String: String]
        let secret = bytes(fromHex: vec["secretHex"]!)
        let wire = bytes(fromHex: vec["wire"]!)

        let tsig = try TSIG_.verify(rawMessage: wire, secret: secret)
        XCTAssertEqual(tsig.header.name.value, "test.key.")
        XCTAssertEqual(tsig.algorithm.value, "hmac-sha256.")

        // A wrong secret must fail.
        XCTAssertThrowsError(try TSIG_.verify(rawMessage: wire, secret: Array(repeating: 0xFF, count: 16)))
    }

    func testSignVerifyRoundTrip() throws {
        let secret = Array<UInt8>(0..<16)
        let msg = Msg(header: MsgHeader(id: 0x2222),
                      questions: [Question(Name("example.com."), .a)])
        let signed = try TSIG_.sign(msg, keyName: Name("test.key."), algorithm: .hmacSHA256,
                                    secret: secret, timeSigned: 1_600_000_000)
        XCTAssertEqual(signed.additionals.count, 1)

        let wire = try signed.pack()
        let tsig = try TSIG_.verify(rawMessage: wire, secret: secret)
        XCTAssertEqual(tsig.origID, 0x2222)

        // Tampering with the message body invalidates the MAC.
        var tampered = wire
        tampered[0] ^= 0xFF  // flip a header bit
        XCTAssertThrowsError(try TSIG_.verify(rawMessage: tampered, secret: secret))
    }

    func testSHA512RoundTrip() throws {
        let secret = Array<UInt8>(repeating: 7, count: 32)
        let msg = Msg(header: MsgHeader(id: 1), questions: [Question(Name("a.test."), .txt)])
        let signed = try TSIG_.sign(msg, keyName: Name("k."), algorithm: .hmacSHA512,
                                    secret: secret, timeSigned: 1_600_000_000)
        let tsig = try TSIG_.verify(rawMessage: signed.pack(), secret: secret)
        XCTAssertEqual(tsig.algorithm.value, "hmac-sha512.")
    }

    func testSHA384RoundTrip() throws {
        let secret = Array<UInt8>(repeating: 3, count: 24)
        let msg = Msg(header: MsgHeader(id: 9), questions: [Question(Name("b.test."), .a)])
        let signed = try TSIG_.sign(msg, keyName: Name("k2."), algorithm: .hmacSHA384,
                                    secret: secret, timeSigned: 1_600_000_000)
        let tsig = try TSIG_.verify(rawMessage: signed.pack(), secret: secret)
        XCTAssertEqual(tsig.algorithm.value, "hmac-sha384.")
    }
}
