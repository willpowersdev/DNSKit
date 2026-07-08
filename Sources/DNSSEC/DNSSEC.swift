import Foundation
import Crypto
import DNSCore
import DNSTypes

/// DNSSEC algorithm numbers (IANA registry). This milestone implements the
/// modern signing algorithms; RSA (5/7/8/10) is the next increment.
public enum DNSSECAlgorithm {
    public static let rsaSHA256: UInt8 = 8
    public static let rsaSHA512: UInt8 = 10
    public static let ecdsaP256SHA256: UInt8 = 13
    public static let ecdsaP384SHA384: UInt8 = 14
    public static let ed25519: UInt8 = 15
}

/// DS digest type numbers (IANA registry).
public enum DSDigestType {
    public static let sha1: UInt8 = 1
    public static let sha256: UInt8 = 2
    public static let sha384: UInt8 = 4
}

public enum DNSSECError: Error, Sendable, Equatable {
    case unsupportedAlgorithm(UInt8)
    case unsupportedDigestType(UInt8)
    case badPublicKey
    case badSignature
    case emptyRRset
}

public enum DNSSEC {
    /// Lowercases the ASCII letters of a name for canonical form (RFC 4034 §6.2).
    private static func canonical(_ name: Name) -> Name { Name(name.value.lowercased()) }

    /// The DNSKEY key tag (RFC 4034 Appendix B), for algorithms other than 1.
    public static func keyTag(_ key: DNSKEY) throws -> UInt16 {
        var m = MessagePacker(compressionEnabled: false)
        try key.packRdata(into: &m)
        var ac = 0
        for (i, b) in m.bytes.enumerated() {
            ac += (i & 1 == 0) ? Int(b) << 8 : Int(b)
        }
        ac += (ac >> 16) & 0xFFFF
        return UInt16(ac & 0xFFFF)
    }

    /// Computes the DS record for a DNSKEY (RFC 4034 §5.1.4): the digest is over
    /// the canonical owner name followed by the DNSKEY RDATA.
    public static func makeDS(_ key: DNSKEY, digestType: UInt8) throws -> DS {
        var m = MessagePacker(compressionEnabled: false)
        try m.appendName(canonical(key.header.name), compress: false)
        try key.packRdata(into: &m)
        let data = Data(m.bytes)
        let digest: [UInt8]
        switch digestType {
        case DSDigestType.sha256: digest = Array(SHA256.hash(data: data))
        case DSDigestType.sha384: digest = Array(SHA384.hash(data: data))
        case DSDigestType.sha1: digest = Array(Insecure.SHA1.hash(data: data))
        default: throw DNSSECError.unsupportedDigestType(digestType)
        }
        return DS(header: RRHeader(name: key.header.name, type: .ds, class: key.header.class, ttl: key.header.ttl),
                  keyTag: try keyTag(key), algorithm: key.algorithm, digestType: digestType, digest: digest)
    }

    /// Builds the data covered by an RRSIG (RFC 4034 §3.1.8.1): the RRSIG RDATA
    /// (without the signature) followed by the canonical, sorted RRset. Each RR
    /// uses the RRSIG's original TTL and canonical (lowercased) owner name.
    ///
    /// Note: rdata-embedded domain names are not yet lowercased, so signing/
    /// verifying is currently correct for rdata without domain names
    /// (A, AAAA, TXT, DS, ...). Name-bearing rdata is a follow-up.
    public static func signingData(rrsig: RRSIG, rrset: [any RR]) throws -> [UInt8] {
        guard !rrset.isEmpty else { throw DNSSECError.emptyRRset }

        var p = MessagePacker(compressionEnabled: false)
        p.appendUInt16(rrsig.typeCovered)
        p.appendUInt8(rrsig.algorithm)
        p.appendUInt8(rrsig.labels)
        p.appendUInt32(rrsig.origTtl)
        p.appendUInt32(rrsig.expiration)
        p.appendUInt32(rrsig.inception)
        p.appendUInt16(rrsig.keyTag)
        try p.appendName(canonical(rrsig.signerName), compress: false)

        // Canonicalize each RR, then sort (equivalent to RFC 4034 §6.3 RDATA
        // ordering since name/type/class/TTL are identical across the RRset).
        var entries: [[UInt8]] = []
        for rr in rrset {
            var e = MessagePacker(compressionEnabled: false)
            try e.appendName(canonical(rr.header.name), compress: false)
            e.appendUInt16(rr.header.type.rawValue)
            e.appendUInt16(rr.header.class.rawValue)
            e.appendUInt32(rrsig.origTtl)
            var rd = MessagePacker(compressionEnabled: false)
            try rr.packRdata(into: &rd)
            e.appendUInt16(UInt16(rd.count))
            e.appendBytes(rd.bytes)
            entries.append(e.bytes)
        }
        entries.sort { lexicographicallyLess($0, $1) }
        for e in entries { p.appendBytes(e) }
        return p.bytes
    }

    /// Verifies an RRSIG over an RRset using a DNSKEY.
    public static func verify(rrsig: RRSIG, rrset: [any RR], key: DNSKEY) throws -> Bool {
        let data = Data(try signingData(rrsig: rrsig, rrset: rrset))
        switch rrsig.algorithm {
        case DNSSECAlgorithm.ecdsaP256SHA256:
            let pub = try P256.Signing.PublicKey(rawRepresentation: Data(key.publicKey))
            let sig = try P256.Signing.ECDSASignature(rawRepresentation: Data(rrsig.signature))
            return pub.isValidSignature(sig, for: data)
        case DNSSECAlgorithm.ecdsaP384SHA384:
            let pub = try P384.Signing.PublicKey(rawRepresentation: Data(key.publicKey))
            let sig = try P384.Signing.ECDSASignature(rawRepresentation: Data(rrsig.signature))
            return pub.isValidSignature(sig, for: data)
        case DNSSECAlgorithm.ed25519:
            let pub = try Curve25519.Signing.PublicKey(rawRepresentation: Data(key.publicKey))
            return pub.isValidSignature(Data(rrsig.signature), for: data)
        default:
            throw DNSSECError.unsupportedAlgorithm(rrsig.algorithm)
        }
    }

    /// Signs an RRset, returning the RRSIG with its `signature` field populated.
    /// The template supplies typeCovered/labels/TTLs/validity/keyTag/signerName.
    public static func sign(rrset: [any RR], template: RRSIG, signer: any DNSSECSigner) throws -> RRSIG {
        var rrsig = template
        rrsig.algorithm = signer.algorithm
        rrsig.signature = []
        let data = try signingData(rrsig: rrsig, rrset: rrset)
        rrsig.signature = try signer.signature(over: data)
        return rrsig
    }

    private static func lexicographicallyLess(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        for i in 0..<min(a.count, b.count) where a[i] != b[i] { return a[i] < b[i] }
        return a.count < b.count
    }
}

/// Produces a DNSSEC signature over the given data with a specific algorithm.
public protocol DNSSECSigner: Sendable {
    var algorithm: UInt8 { get }
    func signature(over data: [UInt8]) throws -> [UInt8]
}

public struct Ed25519Signer: DNSSECSigner {
    public let privateKey: Curve25519.Signing.PrivateKey
    public init(_ key: Curve25519.Signing.PrivateKey) { self.privateKey = key }
    public var algorithm: UInt8 { DNSSECAlgorithm.ed25519 }
    public var publicKey: [UInt8] { Array(privateKey.publicKey.rawRepresentation) }
    public func signature(over data: [UInt8]) throws -> [UInt8] {
        Array(try privateKey.signature(for: Data(data)))
    }
}

public struct P256Signer: DNSSECSigner {
    public let privateKey: P256.Signing.PrivateKey
    public init(_ key: P256.Signing.PrivateKey) { self.privateKey = key }
    public var algorithm: UInt8 { DNSSECAlgorithm.ecdsaP256SHA256 }
    public var publicKey: [UInt8] { Array(privateKey.publicKey.rawRepresentation) }
    public func signature(over data: [UInt8]) throws -> [UInt8] {
        Array(try privateKey.signature(for: Data(data)).rawRepresentation)
    }
}

public struct P384Signer: DNSSECSigner {
    public let privateKey: P384.Signing.PrivateKey
    public init(_ key: P384.Signing.PrivateKey) { self.privateKey = key }
    public var algorithm: UInt8 { DNSSECAlgorithm.ecdsaP384SHA384 }
    public var publicKey: [UInt8] { Array(privateKey.publicKey.rawRepresentation) }
    public func signature(over data: [UInt8]) throws -> [UInt8] {
        Array(try privateKey.signature(for: Data(data)).rawRepresentation)
    }
}
