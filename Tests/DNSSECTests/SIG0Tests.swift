import XCTest
import Foundation
import Crypto
import DNSCore
import DNSTypes
@testable import DNSSEC

final class SIG0Tests: XCTestCase {
    private func bytes(fromHex s: String) -> [UInt8] {
        var out: [UInt8] = []; var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return out
    }
    private func unpackDNSKEY(_ hex: String) throws -> DNSKEY {
        var u = MessageUnpacker(bytes(fromHex: hex))
        return try XCTUnwrap(try unpackRR(from: &u) as? DNSKEY)
    }

    /// Interop: verify a SIG(0)-signed message produced by miekg.
    func testVerifiesGoSIG0() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("oracle_sig0.json")
        let data = try Data(contentsOf: url)
        let vec = try JSONSerialization.jsonObject(with: data) as! [String: String]

        let key = try unpackDNSKEY(vec["dnskey"]!)
        let wire = bytes(fromHex: vec["wire"]!)
        XCTAssertTrue(try SIG0.verify(rawMessage: wire, key: key))

        // Tampering with the message invalidates the signature.
        var tampered = wire
        tampered[4] ^= 0x01  // flip a bit in QDCOUNT-adjacent header
        XCTAssertFalse((try? SIG0.verify(rawMessage: tampered, key: key)) ?? false)
    }

    func testSignVerifyRoundTrip() throws {
        let signer = P256Signer(P256.Signing.PrivateKey())
        let key = DNSKEY(header: RRHeader(name: Name("example.com."), type: .dnskey, ttl: 0),
                         flags: 256, proto: 3, algorithm: signer.algorithm, publicKey: signer.publicKey)
        let msg = Msg(header: MsgHeader(id: 0x4444), questions: [Question(Name("example.com."), .a)])
        let signed = try SIG0.sign(msg, signer: signer, keyTag: try DNSSEC.keyTag(key),
                                   signerName: Name("example.com."),
                                   inception: 1_600_000_000, expiration: 1_700_000_000)
        XCTAssertEqual(signed.additionals.count, 1)
        XCTAssertTrue(try SIG0.verify(rawMessage: signed.pack(), key: key))
    }
}
