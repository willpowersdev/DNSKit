import Foundation
import Crypto
import DNSCore
import DNSTypes

/// TSIG HMAC algorithms (RFC 8945).
public enum TSIGAlgorithm: String, Sendable {
    case hmacSHA1 = "hmac-sha1."
    case hmacSHA256 = "hmac-sha256."
    case hmacSHA384 = "hmac-sha384."
    case hmacSHA512 = "hmac-sha512."

    static func from(_ name: Name) -> TSIGAlgorithm? {
        TSIGAlgorithm(rawValue: name.value.lowercased())
    }

    func mac(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: Data(key))
        switch self {
        case .hmacSHA1:
            return Array(HMAC<Insecure.SHA1>.authenticationCode(for: Data(data), using: symmetricKey))
        case .hmacSHA256:
            return Array(HMAC<SHA256>.authenticationCode(for: Data(data), using: symmetricKey))
        case .hmacSHA384:
            return Array(HMAC<SHA384>.authenticationCode(for: Data(data), using: symmetricKey))
        case .hmacSHA512:
            return Array(HMAC<SHA512>.authenticationCode(for: Data(data), using: symmetricKey))
        }
    }
}

/// TSIG transaction signatures (RFC 8945). Signs a request by appending a TSIG
/// record whose MAC covers the message plus the "TSIG variables", and verifies
/// a received message over its exact wire bytes (so name-compression choices by
/// the sender don't affect the result).
public enum TSIG_ {
    /// Serializes the TSIG variables that are hashed alongside the message.
    private static func variables(keyName: Name, algorithm: Name, timeSigned: UInt64,
                                 fudge: UInt16, error: UInt16, otherData: [UInt8]) throws -> [UInt8] {
        var p = MessagePacker(compressionEnabled: false)
        try p.appendName(Name(keyName.value.lowercased()), compress: false)
        p.appendUInt16(255)   // CLASS ANY
        p.appendUInt32(0)     // TTL
        try p.appendName(Name(algorithm.value.lowercased()), compress: false)
        p.appendUInt48(timeSigned)
        p.appendUInt16(fudge)
        p.appendUInt16(error)
        p.appendUInt16(UInt16(otherData.count))
        p.appendBytes(otherData)
        return p.bytes
    }

    /// Returns a copy of `message` with a signed TSIG record appended.
    public static func sign(_ message: Msg, keyName: Name, algorithm: TSIGAlgorithm,
                           secret: [UInt8], timeSigned: UInt64, fudge: UInt16 = 300) throws -> Msg {
        let algName = Name(algorithm.rawValue)
        let messageWire = try message.pack()   // ARCOUNT excludes the TSIG
        let vars = try variables(keyName: keyName, algorithm: algName, timeSigned: timeSigned,
                                 fudge: fudge, error: 0, otherData: [])
        let mac = algorithm.mac(key: secret, data: messageWire + vars)

        let tsig = TSIG(header: RRHeader(name: keyName, type: .tsig, class: .any, ttl: 0),
                        algorithm: algName, timeSigned: timeSigned, fudge: fudge,
                        macSize: UInt16(mac.count), mac: mac, origID: message.header.id,
                        error: 0, otherLen: 0, otherData: [])
        var signed = message
        signed.additionals.append(tsig)
        return signed
    }

    /// Verifies the TSIG on a received message (given its raw wire bytes).
    /// Returns the parsed TSIG on success; throws on MAC mismatch or absence.
    @discardableResult
    public static func verify(rawMessage raw: [UInt8], secret: [UInt8]) throws -> TSIG {
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

        let tsigStart = u.offset
        guard let tsig = try unpackRR(from: &u) as? TSIG else { throw DNSSECError.tsigNotFound }
        guard let algorithm = TSIGAlgorithm.from(tsig.algorithm) else {
            throw DNSSECError.tsigUnknownAlgorithm(tsig.algorithm.value)
        }

        // The signed "DNS Message" is the received bytes up to the TSIG, with
        // ARCOUNT decremented by one.
        var prefix = Array(raw[0..<tsigStart])
        let newAr = UInt16(ar - 1)
        prefix[10] = UInt8(newAr >> 8)
        prefix[11] = UInt8(newAr & 0xff)

        let vars = try variables(keyName: tsig.header.name, algorithm: tsig.algorithm,
                                 timeSigned: tsig.timeSigned, fudge: tsig.fudge,
                                 error: tsig.error, otherData: tsig.otherData)
        let expected = algorithm.mac(key: secret, data: prefix + vars)

        guard constantTimeEqual(expected, tsig.mac) else { throw DNSSECError.badSignature }
        return tsig
    }

    private static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}
