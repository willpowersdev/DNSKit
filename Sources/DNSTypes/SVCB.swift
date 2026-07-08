import DNSCore

// SVCB / HTTPS (RFC 9460). Rdata is priority(uint16) + target(domain-name,
// uncompressed) + a list of {key, length, value} SvcParams that MUST be sorted
// by key ascending on the wire. Bespoke format (Go hand-codes it), so these do
// not use @DNSRecord.

/// SvcParamKey constants (RFC 9460 §14.3.2 / IANA registry).
public enum SVCBKey {
    public static let mandatory: UInt16 = 0
    public static let alpn: UInt16 = 1
    public static let noDefaultAlpn: UInt16 = 2
    public static let port: UInt16 = 3
    public static let ipv4hint: UInt16 = 4
    public static let ech: UInt16 = 5
    public static let ipv6hint: UInt16 = 6
    public static let dohpath: UInt16 = 7
    public static let ohttp: UInt16 = 8
}

/// A single SVCB key/value parameter. Concrete params encode only their value
/// payload; the {key, length} framing and ordering are handled by ``SVCB``.
public protocol SVCBValue: Sendable {
    var key: UInt16 { get }
    func packValue() throws -> [UInt8]
}

private func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }

/// mandatory: the set of keys that must be understood, packed as sorted uint16s.
public struct SVCBMandatory: SVCBValue {
    public var codes: [UInt16]
    public init(codes: [UInt16]) { self.codes = codes }
    public init(data: [UInt8]) throws {
        guard data.count % 2 == 0 else { throw WireError.malformedText("svcb mandatory: odd length") }
        codes = stride(from: 0, to: data.count, by: 2).map { UInt16(data[$0]) << 8 | UInt16(data[$0 + 1]) }
    }
    public var key: UInt16 { SVCBKey.mandatory }
    public func packValue() -> [UInt8] { codes.sorted().flatMap(be16) }
}

/// alpn: a list of ALPN protocol identifiers, each length-prefixed (1 byte).
public struct SVCBAlpn: SVCBValue {
    public var alpn: [String]
    public init(alpn: [String]) { self.alpn = alpn }
    public init(data: [UInt8]) throws {
        var out: [String] = []; var i = 0
        while i < data.count {
            let len = Int(data[i]); i += 1
            guard i + len <= data.count else { throw WireError.malformedText("svcb alpn: overflow") }
            out.append(String(decoding: data[i..<i + len], as: UTF8.self)); i += len
        }
        alpn = out
    }
    public var key: UInt16 { SVCBKey.alpn }
    public func packValue() throws -> [UInt8] {
        var out: [UInt8] = []
        for id in alpn {
            let raw = Array(id.utf8)
            guard raw.count <= 255 else { throw WireError.characterStringTooLong(length: raw.count) }
            out.append(UInt8(raw.count)); out.append(contentsOf: raw)
        }
        return out
    }
}

/// no-default-alpn: presence-only, empty value.
public struct SVCBNoDefaultAlpn: SVCBValue {
    public init() {}
    public init(data: [UInt8]) throws {
        guard data.isEmpty else { throw WireError.malformedText("svcb no-default-alpn: must be empty") }
    }
    public var key: UInt16 { SVCBKey.noDefaultAlpn }
    public func packValue() -> [UInt8] { [] }
}

/// port: a single 16-bit port.
public struct SVCBPort: SVCBValue {
    public var port: UInt16
    public init(port: UInt16) { self.port = port }
    public init(data: [UInt8]) throws {
        guard data.count == 2 else { throw WireError.malformedText("svcb port: length != 2") }
        port = UInt16(data[0]) << 8 | UInt16(data[1])
    }
    public var key: UInt16 { SVCBKey.port }
    public func packValue() -> [UInt8] { be16(port) }
}

/// ipv4hint: a list of IPv4 addresses (4 octets each).
public struct SVCBIPv4Hint: SVCBValue {
    public var hints: [IPv4Address]
    public init(hints: [IPv4Address]) { self.hints = hints }
    public init(data: [UInt8]) throws {
        guard !data.isEmpty, data.count % 4 == 0 else { throw WireError.malformedText("svcb ipv4hint: bad length") }
        hints = stride(from: 0, to: data.count, by: 4).map { IPv4Address(bytes: Array(data[$0..<$0 + 4])) }
    }
    public var key: UInt16 { SVCBKey.ipv4hint }
    public func packValue() -> [UInt8] { hints.flatMap(\.bytes) }
}

/// ipv6hint: a list of IPv6 addresses (16 octets each).
public struct SVCBIPv6Hint: SVCBValue {
    public var hints: [IPv6Address]
    public init(hints: [IPv6Address]) { self.hints = hints }
    public init(data: [UInt8]) throws {
        guard !data.isEmpty, data.count % 16 == 0 else { throw WireError.malformedText("svcb ipv6hint: bad length") }
        hints = stride(from: 0, to: data.count, by: 16).map { IPv6Address(bytes: Array(data[$0..<$0 + 16])) }
    }
    public var key: UInt16 { SVCBKey.ipv6hint }
    public func packValue() -> [UInt8] { hints.flatMap(\.bytes) }
}

/// ech: an opaque ECHConfigList (including its own length prefix).
public struct SVCBECHConfig: SVCBValue {
    public var ech: [UInt8]
    public init(ech: [UInt8]) { self.ech = ech }
    public var key: UInt16 { SVCBKey.ech }
    public func packValue() -> [UInt8] { ech }
}

/// dohpath: a URI template for DNS-over-HTTPS (RFC 9461), UTF-8.
public struct SVCBDoHPath: SVCBValue {
    public var template: String
    public init(template: String) { self.template = template }
    public var key: UInt16 { SVCBKey.dohpath }
    public func packValue() -> [UInt8] { Array(template.utf8) }
}

/// ohttp: presence-only, empty value (RFC 9540).
public struct SVCBOhttp: SVCBValue {
    public init() {}
    public init(data: [UInt8]) throws {
        guard data.isEmpty else { throw WireError.malformedText("svcb ohttp: must be empty") }
    }
    public var key: UInt16 { SVCBKey.ohttp }
    public func packValue() -> [UInt8] { [] }
}

/// Fallback for keys we don't model specifically (e.g. private-use range).
public struct SVCBLocal: SVCBValue {
    public let key: UInt16
    public var data: [UInt8]
    public init(key: UInt16, data: [UInt8]) { self.key = key; self.data = data }
    public func packValue() -> [UInt8] { data }
}

enum SVCBRegistry {
    static func decode(key: UInt16, data: [UInt8]) throws -> any SVCBValue {
        switch key {
        case SVCBKey.mandatory: return try SVCBMandatory(data: data)
        case SVCBKey.alpn: return try SVCBAlpn(data: data)
        case SVCBKey.noDefaultAlpn: return try SVCBNoDefaultAlpn(data: data)
        case SVCBKey.port: return try SVCBPort(data: data)
        case SVCBKey.ipv4hint: return try SVCBIPv4Hint(data: data)
        case SVCBKey.ech: return SVCBECHConfig(ech: data)
        case SVCBKey.ipv6hint: return try SVCBIPv6Hint(data: data)
        case SVCBKey.dohpath: return SVCBDoHPath(template: String(decoding: data, as: UTF8.self))
        case SVCBKey.ohttp: return try SVCBOhttp(data: data)
        default: return SVCBLocal(key: key, data: data)
        }
    }
}

// Shared rdata codec for SVCB and HTTPS (identical wire format).
private func packSVCBRdata(priority: UInt16, target: Name, values: [any SVCBValue],
                          into buf: inout MessagePacker) throws {
    buf.appendUInt16(priority)
    try buf.appendName(target, compress: false)
    let sorted = values.sorted { $0.key < $1.key }
    var previous: UInt16? = nil
    for v in sorted {
        if v.key == previous { throw WireError.malformedText("svcb: repeated key \(v.key)") }
        previous = v.key
        buf.appendUInt16(v.key)
        let data = try v.packValue()
        guard data.count <= Int(UInt16.max) else { throw WireError.valueOutOfRange }
        buf.appendUInt16(UInt16(data.count))
        buf.appendBytes(data)
    }
}

private func unpackSVCBRdata(header: RRHeader, from buf: inout MessageUnpacker)
    throws -> (UInt16, Name, [any SVCBValue]) {
    let start = buf.offset
    let priority = try buf.readUInt16()
    let target = try buf.readName()
    var values: [any SVCBValue] = []
    while buf.offset - start < Int(header.rdlength) {
        let key = try buf.readUInt16()
        let len = Int(try buf.readUInt16())
        let data = try buf.readBytes(len)
        values.append(try SVCBRegistry.decode(key: key, data: data))
    }
    return (priority, target, values)
}

/// SVCB service binding record (RFC 9460).
public struct SVCB: RR {
    public var header: RRHeader
    public var priority: UInt16
    public var target: Name
    public var values: [any SVCBValue]

    public init(header: RRHeader, priority: UInt16, target: Name, values: [any SVCBValue] = []) {
        self.header = header; self.priority = priority; self.target = target; self.values = values
    }
    public func packRdata(into buf: inout MessagePacker) throws {
        try packSVCBRdata(priority: priority, target: target, values: values, into: &buf)
    }
    public init(header: RRHeader, rdata buf: inout MessageUnpacker) throws {
        (priority, target, values) = try unpackSVCBRdata(header: header, from: &buf)
        self.header = header
    }
    public init(header: RRHeader, rdataTokens tokens: [String], origin: String) throws {
        throw WireError.malformedText("presentation parsing not supported for SVCB")
    }
}

/// HTTPS record (RFC 9460) — identical wire format to SVCB.
public struct HTTPS: RR {
    public var header: RRHeader
    public var priority: UInt16
    public var target: Name
    public var values: [any SVCBValue]

    public init(header: RRHeader, priority: UInt16, target: Name, values: [any SVCBValue] = []) {
        self.header = header; self.priority = priority; self.target = target; self.values = values
    }
    public func packRdata(into buf: inout MessagePacker) throws {
        try packSVCBRdata(priority: priority, target: target, values: values, into: &buf)
    }
    public init(header: RRHeader, rdata buf: inout MessageUnpacker) throws {
        (priority, target, values) = try unpackSVCBRdata(header: header, from: &buf)
        self.header = header
    }
    public init(header: RRHeader, rdataTokens tokens: [String], origin: String) throws {
        throw WireError.malformedText("presentation parsing not supported for HTTPS")
    }
}
