/// An IPv4 address, stored as its 4 wire octets. Backs the `A` record rdata.
public struct IPv4Address: Hashable, Sendable, CustomStringConvertible, ExpressibleByStringLiteral {
    public var octets: (UInt8, UInt8, UInt8, UInt8)

    public init(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) { octets = (a, b, c, d) }

    public init?(_ text: String) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var vals: [UInt8] = []
        for p in parts {
            guard let v = UInt8(p) else { return nil }
            vals.append(v)
        }
        octets = (vals[0], vals[1], vals[2], vals[3])
    }

    public init(stringLiteral value: String) {
        self = IPv4Address(value) ?? IPv4Address(0, 0, 0, 0)
    }

    public var bytes: [UInt8] { [octets.0, octets.1, octets.2, octets.3] }

    public init(bytes: [UInt8]) { self.init(bytes[0], bytes[1], bytes[2], bytes[3]) }

    public var description: String { "\(octets.0).\(octets.1).\(octets.2).\(octets.3)" }

    public static func == (l: IPv4Address, r: IPv4Address) -> Bool { l.octets == r.octets }
    public func hash(into h: inout Hasher) { h.combine(bytes) }
}

/// An IPv6 address, stored as its 16 wire octets. Backs the `AAAA` record rdata.
public struct IPv6Address: Hashable, Sendable, CustomStringConvertible, ExpressibleByStringLiteral {
    public var bytes: [UInt8] // always 16

    public init(bytes: [UInt8]) {
        precondition(bytes.count == 16)
        self.bytes = bytes
    }

    /// Minimal parser: full or `::`-compressed hextet form. Sufficient for the
    /// Part 0 prototype; the zone scanner will supply a complete parser later.
    public init?(_ text: String) {
        func hextets(_ s: Substring) -> [UInt16]? {
            if s.isEmpty { return [] }
            var out: [UInt16] = []
            for g in s.split(separator: ":") {
                guard let v = UInt16(g, radix: 16) else { return nil }
                out.append(v)
            }
            return out
        }
        // Locate an (optional) "::" compression marker without Foundation.
        let chars = Array(text)
        var dc: Int? = nil
        var i = 0
        while i + 1 < chars.count {
            if chars[i] == ":" && chars[i + 1] == ":" {
                if dc != nil { return nil } // at most one "::"
                dc = i
                i += 2
            } else {
                i += 1
            }
        }
        var groups: [UInt16]
        if let dc {
            let head = Substring(String(chars[0..<dc]))
            let tail = Substring(String(chars[(dc + 2)...]))
            guard let h = hextets(head), let t = hextets(tail) else { return nil }
            let missing = 8 - h.count - t.count
            guard missing >= 0 else { return nil }
            groups = h + Array(repeating: 0, count: missing) + t
        } else {
            guard let g = hextets(Substring(text)), g.count == 8 else { return nil }
            groups = g
        }
        var b: [UInt8] = []
        for g in groups { b.append(UInt8(g >> 8)); b.append(UInt8(g & 0xff)) }
        self.bytes = b
    }

    public init(stringLiteral value: String) {
        self = IPv6Address(value) ?? IPv6Address(bytes: Array(repeating: 0, count: 16))
    }

    public var description: String {
        var groups: [UInt16] = []
        for i in stride(from: 0, to: 16, by: 2) {
            groups.append(UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]))
        }
        return groups.map { String($0, radix: 16) }.joined(separator: ":")
    }
}
