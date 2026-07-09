import Foundation
import Crypto
import DNSCore
import DNSTypes

extension DNSSEC {
    /// Computes the NSEC3 hash of an owner name (RFC 5155 §5): iterated SHA-1
    /// over the canonical (lowercased) wire name and salt.
    ///
    ///     IH(0)   = SHA1(name || salt)
    ///     IH(k)   = SHA1(IH(k-1) || salt)
    ///     hash    = IH(iterations)
    public static func nsec3Hash(name: Name, salt: [UInt8], iterations: UInt16) throws -> [UInt8] {
        var p = MessagePacker(compressionEnabled: false)
        try p.appendName(Name(name.value.lowercased()), compress: false)
        var digest = Array(Insecure.SHA1.hash(data: Data(p.bytes + salt)))
        for _ in 0..<iterations {
            digest = Array(Insecure.SHA1.hash(data: Data(digest + salt)))
        }
        return digest
    }

    /// Base32hex encoding (RFC 4648 extended-hex alphabet, no padding, upper
    /// case) — the presentation form of NSEC3 hashed names.
    public static func base32HexEncode(_ bytes: [UInt8]) -> String {
        let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUV")
        var out = ""
        var buffer = 0
        var bits = 0
        for b in bytes {
            buffer = (buffer << 8) | Int(b)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[(buffer >> bits) & 0x1F])
            }
        }
        if bits > 0 {
            out.append(alphabet[(buffer << (5 - bits)) & 0x1F])
        }
        return out
    }
}
