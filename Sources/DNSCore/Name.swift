/// A DNS domain name in presentation format (e.g. `"example.com."`).
///
/// Names are stored as their textual presentation form, matching the Go
/// library's choice to keep names as `string` rather than pre-split labels.
/// Wire encoding/decoding (including compression) lives on ``MessagePacker`` /
/// ``MessageUnpacker`` because it depends on message-global compression state.
public struct Name: Hashable, Sendable, CustomStringConvertible, ExpressibleByStringLiteral {
    /// Presentation-format text, e.g. `"example.com."`. The root is `"."`.
    public var value: String

    public init(_ value: String) { self.value = value }
    public init(stringLiteral value: String) { self.value = value }

    public var description: String { value }

    /// Whether the name is fully qualified (ends in an unescaped dot).
    public var isFqdn: Bool {
        if value.isEmpty { return false }
        if value == "." { return true }
        // Count trailing backslashes before the final dot to detect escaping.
        guard value.hasSuffix(".") else { return false }
        var backslashes = 0
        var idx = value.index(before: value.endIndex) // the dot
        while idx > value.startIndex {
            idx = value.index(before: idx)
            if value[idx] == "\\" { backslashes += 1 } else { break }
        }
        return backslashes % 2 == 0
    }

    /// Returns the name made fully qualified (appends a trailing dot if absent).
    public var fqdn: Name {
        if isFqdn { return self }
        return Name(value == "" ? "." : value + ".")
    }

    /// Splits the name into wire labels (as raw byte arrays), applying DNS
    /// escape decoding (`\.`, `\DDD`). The root produces zero labels.
    public func labels() throws -> [[UInt8]] {
        let fq = fqdn.value
        if fq == "." { return [] }
        var result: [[UInt8]] = []
        var current: [UInt8] = []
        let bytes = Array(fq.utf8)
        var i = 0
        while i < bytes.count {
            let b = bytes[i]
            if b == UInt8(ascii: "\\") {
                i += 1
                guard i < bytes.count else { throw WireError.malformedText("trailing backslash") }
                let n = bytes[i]
                if n >= UInt8(ascii: "0") && n <= UInt8(ascii: "9") {
                    // \DDD decimal escape
                    guard i + 2 < bytes.count else { throw WireError.malformedText("bad \\DDD escape") }
                    let d0 = Int(bytes[i]) - 48, d1 = Int(bytes[i+1]) - 48, d2 = Int(bytes[i+2]) - 48
                    let v = d0 * 100 + d1 * 10 + d2
                    guard (0...255).contains(v) else { throw WireError.malformedText("bad \\DDD escape") }
                    current.append(UInt8(v))
                    i += 3
                } else {
                    current.append(n)
                    i += 1
                }
            } else if b == UInt8(ascii: ".") {
                guard current.count <= 63 else { throw WireError.labelTooLong(length: current.count) }
                result.append(current)
                current = []
                i += 1
            } else {
                current.append(b)
                i += 1
            }
        }
        if !current.isEmpty {
            guard current.count <= 63 else { throw WireError.labelTooLong(length: current.count) }
            result.append(current)
        }
        return result
    }

    /// Builds a presentation name from wire labels, applying escape encoding.
    public static func from(labels: [[UInt8]]) -> Name {
        if labels.isEmpty { return Name(".") }
        var out = ""
        for label in labels {
            for b in label {
                switch b {
                case UInt8(ascii: "."), UInt8(ascii: "\\"):
                    out.append("\\"); out.append(Character(UnicodeScalar(b)))
                case 0x21...0x7E: // printable ASCII
                    out.append(Character(UnicodeScalar(b)))
                default:
                    out.append("\\")
                    out.append(Character(UnicodeScalar(UInt8(48 + b / 100))))
                    out.append(Character(UnicodeScalar(UInt8(48 + (b / 10) % 10))))
                    out.append(Character(UnicodeScalar(UInt8(48 + b % 10))))
                }
            }
            out.append(".")
        }
        return Name(out)
    }
}
