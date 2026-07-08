import XCTest
import Foundation
import Crypto
import _CryptoExtras
import DNSCore
import DNSTypes
@testable import DNSSEC

final class DNSSECTests: XCTestCase {
    private func bytes(fromHex s: String) -> [UInt8] {
        var out: [UInt8] = []; var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return out
    }
    private func unpack(_ hex: String) throws -> any RR {
        var u = MessageUnpacker(bytes(fromHex: hex))
        return try unpackRR(from: &u)
    }

    /// Interop: verify signatures produced by the real miekg/dns library, and
    /// check key-tag and DS computation against it.
    func testVerifiesGoSignaturesAndDS() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("oracle_dnssec.json")
        let data = try Data(contentsOf: url)
        let vectors = try JSONSerialization.jsonObject(with: data) as! [[String: Any]]
        XCTAssertFalse(vectors.isEmpty)

        for vec in vectors {
            let alg = (vec["alg"] as! NSNumber).uint8Value
            let key = try XCTUnwrap(try unpack(vec["dnskey"] as! String) as? DNSKEY)
            let rrsig = try XCTUnwrap(try unpack(vec["rrsig"] as! String) as? RRSIG)
            let rrset = try (vec["rrset"] as! [String]).map { try unpack($0) }
            let ds = try XCTUnwrap(try unpack(vec["ds"] as! String) as? DS)
            let expectedKeyTag = (vec["keytag"] as! NSNumber).uint16Value

            XCTAssertTrue(try DNSSEC.verify(rrsig: rrsig, rrset: rrset, key: key),
                          "failed to verify miekg signature for algorithm \(alg)")
            XCTAssertEqual(try DNSSEC.keyTag(key), expectedKeyTag, "key tag mismatch for algorithm \(alg)")
            XCTAssertEqual(try DNSSEC.makeDS(key, digestType: DSDigestType.sha256).digest, ds.digest,
                           "DS digest mismatch for algorithm \(alg)")

            // A tampered RRset must NOT verify.
            if var tampered = rrset.first as? A {
                tampered.a = IPv4Address("10.9.8.7")
                XCTAssertFalse(try DNSSEC.verify(rrsig: rrsig, rrset: [tampered], key: key))
            }
        }
    }

    private func rrset() -> [any RR] {
        [
            A(header: RRHeader(name: Name("example.com."), type: .a, ttl: 3600), a: IPv4Address("192.0.2.1")),
            A(header: RRHeader(name: Name("example.com."), type: .a, ttl: 3600), a: IPv4Address("192.0.2.2")),
        ]
    }
    private func template(keyTag: UInt16) -> RRSIG {
        RRSIG(header: RRHeader(name: Name("example.com."), type: .rrsig, ttl: 3600),
              typeCovered: RRType.a.rawValue, algorithm: 0, labels: 2, origTtl: 3600,
              expiration: 1_700_000_000, inception: 1_600_000_000, keyTag: keyTag,
              signerName: Name("example.com."), signature: [])
    }

    func testEd25519SignVerifyRoundTrip() throws {
        let signer = Ed25519Signer(Curve25519.Signing.PrivateKey())
        let key = DNSKEY(header: RRHeader(name: Name("example.com."), type: .dnskey, ttl: 3600),
                         flags: 257, proto: 3, algorithm: signer.algorithm, publicKey: signer.publicKey)
        let rrsig = try DNSSEC.sign(rrset: rrset(), template: template(keyTag: try DNSSEC.keyTag(key)), signer: signer)
        XCTAssertTrue(try DNSSEC.verify(rrsig: rrsig, rrset: rrset(), key: key))
    }

    func testP256SignVerifyRoundTrip() throws {
        let signer = P256Signer(P256.Signing.PrivateKey())
        let key = DNSKEY(header: RRHeader(name: Name("example.com."), type: .dnskey, ttl: 3600),
                         flags: 257, proto: 3, algorithm: signer.algorithm, publicKey: signer.publicKey)
        let rrsig = try DNSSEC.sign(rrset: rrset(), template: template(keyTag: try DNSSEC.keyTag(key)), signer: signer)
        XCTAssertTrue(try DNSSEC.verify(rrsig: rrsig, rrset: rrset(), key: key))
    }

    func testP384SignVerifyRoundTrip() throws {
        let signer = P384Signer(P384.Signing.PrivateKey())
        let key = DNSKEY(header: RRHeader(name: Name("example.com."), type: .dnskey, ttl: 3600),
                         flags: 257, proto: 3, algorithm: signer.algorithm, publicKey: signer.publicKey)
        let rrsig = try DNSSEC.sign(rrset: rrset(), template: template(keyTag: try DNSSEC.keyTag(key)), signer: signer)
        XCTAssertTrue(try DNSSEC.verify(rrsig: rrsig, rrset: rrset(), key: key))
    }

    func testRSASignVerifyRoundTrip() throws {
        let signer = RSASigner(try _RSA.Signing.PrivateKey(keySize: .bits2048))
        XCTAssertFalse(signer.publicKey.isEmpty)
        let key = DNSKEY(header: RRHeader(name: Name("example.com."), type: .dnskey, ttl: 3600),
                         flags: 257, proto: 3, algorithm: signer.algorithm, publicKey: signer.publicKey)
        let rrsig = try DNSSEC.sign(rrset: rrset(), template: template(keyTag: try DNSSEC.keyTag(key)), signer: signer)
        XCTAssertTrue(try DNSSEC.verify(rrsig: rrsig, rrset: rrset(), key: key))
    }

    /// Name-bearing canonical form: an MX RRset with mixed-case targets signed
    /// by miekg must verify (both sides lowercase the exchange names).
    func testNameBearingCanonicalFormViaOracle() throws {
        // Covered by testVerifiesGoSignaturesAndDS (the MX vector), but assert
        // the lowercasing explicitly here too.
        let mx = MX(header: RRHeader(name: Name("example.com."), type: .mx, ttl: 3600),
                    preference: 10, mx: Name("Mail.EXAMPLE.com."))
        XCTAssertEqual(mx.withLowercasedNames().mx.value, "mail.example.com.")
    }
}
