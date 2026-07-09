import XCTest
import DNSCore
@testable import DNSTypes

/// Exercises the wire kinds added in Part 2 beyond the Milestone-0 prototype:
/// opaque rest-of-rdata, hex/base64 blobs, NSEC bitmaps, size-prefixed fields,
/// uint48/uint64, octet strings, and domain-name lists.
final class FullTypeTests: XCTestCase {
    private func hdr(_ type: RRType) -> RRHeader {
        RRHeader(name: Name("example.com."), type: type, class: .in, ttl: 300)
    }

    private func roundTrip<T: RR>(_ rr: T) throws -> T {
        var p = MessagePacker()
        try rr.pack(into: &p)
        var u = MessageUnpacker(p.bytes)
        return try T.unpack(from: &u)
    }

    func testEmptyRdata() throws {
        let any = ANY(header: hdr(.any))
        var p = MessagePacker()
        try any.pack(into: &p)
        // header name + type + class + ttl + rdlength(0), no rdata bytes.
        XCTAssertEqual(p.bytes.suffix(2), [0, 0]) // rdlength == 0
        _ = try roundTrip(any)
    }

    func testNULLOpaque() throws {
        let n = NULL(header: hdr(.null), data: [0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(try roundTrip(n).data, [0xDE, 0xAD, 0xBE, 0xEF])
    }

    func testDSHexGolden() throws {
        let ds = DS(header: hdr(.ds), keyTag: 12345, algorithm: 8, digestType: 2,
                    digest: [0xAB, 0xCD, 0xEF])
        var p = MessagePacker()
        try ds.packRdata(into: &p)
        XCTAssertEqual(p.bytes, [0x30, 0x39, 8, 2, 0xAB, 0xCD, 0xEF])
        let back = try roundTrip(ds)
        XCTAssertEqual(back.keyTag, 12345)
        XCTAssertEqual(back.digest, [0xAB, 0xCD, 0xEF])
    }

    func testDNSKEYBase64Rest() throws {
        let k = DNSKEY(header: hdr(.dnskey), flags: 256, proto: 3, algorithm: 8,
                       publicKey: Array(0..<40))
        let back = try roundTrip(k)
        XCTAssertEqual(back.flags, 256)
        XCTAssertEqual(back.proto, 3)
        XCTAssertEqual(back.publicKey, Array(0..<40))
    }

    func testRRSIGFull() throws {
        let sig = RRSIG(header: hdr(.rrsig), typeCovered: RRType.a.rawValue, algorithm: 8,
                        labels: 2, origTtl: 3600, expiration: 1700000000, inception: 1699000000,
                        keyTag: 54321, signerName: Name("example.com."), signature: Array(0..<64))
        let back = try roundTrip(sig)
        XCTAssertEqual(back.typeCovered, RRType.a.rawValue)
        XCTAssertEqual(back.keyTag, 54321)
        XCTAssertEqual(back.signerName.value, "example.com.")
        XCTAssertEqual(back.signature, Array(0..<64))
    }

    func testNSECBitmap() throws {
        let types = [RRType.a.rawValue, RRType.mx.rawValue, RRType.rrsig.rawValue, RRType.nsec.rawValue]
        let nsec = NSEC(header: hdr(.nsec), nextDomain: Name("next.example.com."), typeBitMap: types)
        let back = try roundTrip(nsec)
        XCTAssertEqual(back.nextDomain.value, "next.example.com.")
        XCTAssertEqual(back.typeBitMap, types.sorted())
    }

    func testNSECBitmapAcrossWindows() throws {
        // Types in different windows (high byte differs): 1 (win 0) and 32769/DLV (win 128).
        let types: [UInt16] = [1, 258, RRType.dlv.rawValue]
        let nsec = NSEC(header: hdr(.nsec), nextDomain: Name("a."), typeBitMap: types)
        XCTAssertEqual(try roundTrip(nsec).typeBitMap, types.sorted())
    }

    func testNSEC3SizePrefixedAndBitmap() throws {
        let salt: [UInt8] = [0x01, 0x02, 0x03]
        let hash: [UInt8] = Array(repeating: 0xAA, count: 20)
        let n = NSEC3(header: hdr(.nsec3), hash: 1, flags: 0, iterations: 12,
                      saltLength: UInt8(salt.count), salt: salt,
                      hashLength: UInt8(hash.count), nextDomain: hash,
                      typeBitMap: [RRType.a.rawValue, RRType.rrsig.rawValue])
        let back = try roundTrip(n)
        XCTAssertEqual(back.salt, salt)
        XCTAssertEqual(back.nextDomain, hash)
        XCTAssertEqual(back.typeBitMap, [RRType.a.rawValue, RRType.rrsig.rawValue])
    }

    func testTKEYDoubleSizePrefixed() throws {
        let key: [UInt8] = Array(0..<16)
        let other: [UInt8] = [0xFF, 0xEE]
        let t = TKEY(header: hdr(.tkey), algorithm: Name("hmac-sha256."), inception: 1, expiration: 2,
                     mode: 3, error: 0, keySize: UInt16(key.count), key: key,
                     otherLen: UInt16(other.count), otherData: other)
        let back = try roundTrip(t)
        XCTAssertEqual(back.algorithm.value, "hmac-sha256.")
        XCTAssertEqual(back.key, key)
        XCTAssertEqual(back.otherData, other)
    }

    func testHIPSizePrefixedPlusNameList() throws {
        let hit: [UInt8] = Array(0..<12)
        let pk: [UInt8] = Array(0..<20)
        let h = HIP(header: hdr(.hip), hitLength: UInt8(hit.count), publicKeyAlgorithm: 2,
                    publicKeyLength: UInt16(pk.count), hit: hit, publicKey: pk,
                    rendezvousServers: [Name("rvs1.example.com."), Name("rvs2.example.com.")])
        let back = try roundTrip(h)
        XCTAssertEqual(back.hit, hit)
        XCTAssertEqual(back.publicKey, pk)
        XCTAssertEqual(back.rendezvousServers.map(\.value), ["rvs1.example.com.", "rvs2.example.com."])
    }

    func testEUI48And64() throws {
        let e48 = EUI48(header: hdr(.eui48), address: 0x0011_2233_4455)
        var p = MessagePacker(); try e48.packRdata(into: &p)
        XCTAssertEqual(p.bytes, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) // 6 octets
        XCTAssertEqual(try roundTrip(e48).address, 0x0011_2233_4455)

        let e64 = EUI64(header: hdr(.eui64), address: 0x0011_2233_4455_6677)
        XCTAssertEqual(try roundTrip(e64).address, 0x0011_2233_4455_6677)
    }

    func testNIDUInt64() throws {
        let nid = NID(header: hdr(.nid), preference: 10, nodeID: 0xABCD_1234_5678_9F00)
        let back = try roundTrip(nid)
        XCTAssertEqual(back.preference, 10)
        XCTAssertEqual(back.nodeID, 0xABCD_1234_5678_9F00)
    }

    func testURIOctet() throws {
        let uri = URI(header: hdr(.uri), priority: 10, weight: 1, target: "https://example.com/path")
        let back = try roundTrip(uri)
        XCTAssertEqual(back.priority, 10)
        XCTAssertEqual(back.target, "https://example.com/path")
    }

    func testCAAOctet() throws {
        let caa = CAA(header: hdr(.caa), flag: 0, tag: "issue", value: "letsencrypt.org")
        let back = try roundTrip(caa)
        XCTAssertEqual(back.tag, "issue")
        XCTAssertEqual(back.value, "letsencrypt.org")
    }

    func testL32IPv4() throws {
        let l = L32(header: hdr(.l32), preference: 5, locator32: IPv4Address("10.0.0.1"))
        let back = try roundTrip(l)
        XCTAssertEqual(back.preference, 5)
        XCTAssertEqual(back.locator32.bytes, [10, 0, 0, 1])
    }

    func testRFC3597Opaque() throws {
        let r = RFC3597(header: hdr(RRType(rawValue: 9999)), rdata: [1, 2, 3, 4, 5])
        XCTAssertEqual(try roundTrip(r).rdata, [1, 2, 3, 4, 5])
    }

    func testHINFOTwoCharacterStrings() throws {
        let h = HINFO(header: hdr(.hinfo), cpu: "Intel", os: "Linux")
        let back = try roundTrip(h)
        XCTAssertEqual(back.cpu, "Intel")
        XCTAssertEqual(back.os, "Linux")
    }
}
