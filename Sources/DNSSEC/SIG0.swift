import Foundation
import DNSCore
import DNSTypes

/// SIG(0) transaction signatures (RFC 2931): a public-key signature over an
/// entire DNS message, carried in a SIG record in the additional section. The
/// signed data is the SIG RDATA (without the signature) followed by the message
/// wire bytes.
public enum SIG0 {
    /// Serializes the SIG RDATA prefix (fixed fields, no signature) followed by
    /// the message wire bytes.
    private static func signingData(_ sig: SIG, messageWire: [UInt8]) throws -> [UInt8] {
        var p = MessagePacker(compressionEnabled: false)
        p.appendUInt16(0)              // type covered (0 for SIG(0))
        p.appendUInt8(sig.algorithm)
        p.appendUInt8(0)              // labels
        p.appendUInt32(0)             // original TTL
        p.appendUInt32(sig.expiration)
        p.appendUInt32(sig.inception)
        p.appendUInt16(sig.keyTag)
        try p.appendName(sig.signerName, compress: false)
        return p.bytes + messageWire
    }

    private static func makeSIG(algorithm: UInt8, keyTag: UInt16, signerName: Name,
                               inception: UInt32, expiration: UInt32, signature: [UInt8]) -> SIG {
        SIG(header: RRHeader(name: Name("."), type: .sig, class: .any, ttl: 0),
            typeCovered: 0, algorithm: algorithm, labels: 0, origTtl: 0,
            expiration: expiration, inception: inception, keyTag: keyTag,
            signerName: signerName, signature: signature)
    }

    /// Returns a copy of `message` with a SIG(0) record appended.
    public static func sign(_ message: Msg, signer: any DNSSECSigner, keyTag: UInt16,
                           signerName: Name, inception: UInt32, expiration: UInt32) throws -> Msg {
        let messageWire = try message.pack()   // ARCOUNT excludes the SIG
        let template = makeSIG(algorithm: signer.algorithm, keyTag: keyTag, signerName: signerName,
                               inception: inception, expiration: expiration, signature: [])
        let signature = try signer.signature(over: signingData(template, messageWire: messageWire))
        var signed = message
        signed.additionals.append(makeSIG(algorithm: signer.algorithm, keyTag: keyTag, signerName: signerName,
                                          inception: inception, expiration: expiration, signature: signature))
        return signed
    }

    /// Verifies the SIG(0) on a received message (given its raw wire bytes).
    @discardableResult
    public static func verify(rawMessage raw: [UInt8], key: DNSKEY) throws -> Bool {
        var u = MessageUnpacker(raw)
        _ = try u.readUInt16() // id
        _ = try u.readUInt16() // bits
        let qd = Int(try u.readUInt16())
        let an = Int(try u.readUInt16())
        let ns = Int(try u.readUInt16())
        let ar = Int(try u.readUInt16())
        for _ in 0..<qd { _ = try u.readName(); _ = try u.readUInt16(); _ = try u.readUInt16() }

        let total = an + ns + ar
        guard total >= 1, ar >= 1 else { throw DNSSECError.tsigNotFound }
        for _ in 0..<(total - 1) { _ = try unpackRR(from: &u) }

        let sigStart = u.offset
        guard let sig = try unpackRR(from: &u) as? SIG else { throw DNSSECError.tsigNotFound }

        var prefix = Array(raw[0..<sigStart])
        let newAr = UInt16(ar - 1)
        prefix[10] = UInt8(newAr >> 8)
        prefix[11] = UInt8(newAr & 0xff)

        let data = try signingData(sig, messageWire: prefix)
        return try DNSSEC.verifyRaw(algorithm: sig.algorithm, publicKey: key.publicKey,
                                    signature: sig.signature, data: data)
    }
}
