import DNSCore

// EDNS0 (RFC 6891). The OPT pseudo-record repurposes the RR header — CLASS is
// the requestor's UDP payload size and TTL packs extended-rcode/version/flags —
// and its rdata is a sequence of {code, length, data} options. This is a
// bespoke wire format (Go hand-codes it too), so OPT does not use @DNSRecord.

/// Option code constants (RFC 6891 / IANA EDNS0 registry).
public enum EDNS0Code {
    public static let llq: UInt16 = 0x1
    public static let ul: UInt16 = 0x2
    public static let nsid: UInt16 = 0x3
    public static let dau: UInt16 = 0x5
    public static let dhu: UInt16 = 0x6
    public static let n3u: UInt16 = 0x7
    public static let subnet: UInt16 = 0x8
    public static let expire: UInt16 = 0x9
    public static let cookie: UInt16 = 0xa
    public static let tcpKeepalive: UInt16 = 0xb
    public static let padding: UInt16 = 0xc
    public static let ede: UInt16 = 0xf
}

/// A single EDNS0 option. Concrete options encode only their *data* payload;
/// the surrounding {code, length} framing is handled by ``OPT``.
public protocol EDNS0Option: Sendable {
    var code: UInt16 { get }
    func packData() throws -> [UInt8]
}

private func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }
private func be32(_ v: UInt32) -> [UInt8] {
    [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
}

/// NSID (RFC 5001): opaque name-server identifier.
public struct EDNS0_NSID: EDNS0Option {
    public var nsid: [UInt8]
    public init(nsid: [UInt8]) { self.nsid = nsid }
    public var code: UInt16 { EDNS0Code.nsid }
    public func packData() -> [UInt8] { nsid }
}

/// COOKIE (RFC 7873): 8-byte client cookie, optionally + 8..32-byte server cookie.
public struct EDNS0_COOKIE: EDNS0Option {
    public var cookie: [UInt8]
    public init(cookie: [UInt8]) { self.cookie = cookie }
    public var code: UInt16 { EDNS0Code.cookie }
    public func packData() -> [UInt8] { cookie }
}

/// PADDING (RFC 7830).
public struct EDNS0_PADDING: EDNS0Option {
    public var padding: [UInt8]
    public init(padding: [UInt8]) { self.padding = padding }
    public var code: UInt16 { EDNS0Code.padding }
    public func packData() -> [UInt8] { padding }
}

/// Extended DNS Error (RFC 8914): info-code + UTF-8 extra text.
public struct EDNS0_EDE: EDNS0Option {
    public var infoCode: UInt16
    public var extraText: String
    public init(infoCode: UInt16, extraText: String = "") {
        self.infoCode = infoCode; self.extraText = extraText
    }
    public init(data: [UInt8]) throws {
        guard data.count >= 2 else { throw WireError.bufferTooShort(needed: 2, available: data.count) }
        infoCode = UInt16(data[0]) << 8 | UInt16(data[1])
        extraText = String(decoding: data[2...], as: UTF8.self)
    }
    public var code: UInt16 { EDNS0Code.ede }
    public func packData() -> [UInt8] { be16(infoCode) + Array(extraText.utf8) }
}

/// Client Subnet (RFC 7871).
public struct EDNS0_SUBNET: EDNS0Option {
    public var family: UInt16
    public var sourceNetmask: UInt8
    public var sourceScope: UInt8
    public var address: [UInt8] // exactly ceil(sourceNetmask/8) octets on the wire
    public init(family: UInt16, sourceNetmask: UInt8, sourceScope: UInt8, address: [UInt8]) {
        self.family = family; self.sourceNetmask = sourceNetmask
        self.sourceScope = sourceScope; self.address = address
    }
    public init(data: [UInt8]) throws {
        guard data.count >= 4 else { throw WireError.bufferTooShort(needed: 4, available: data.count) }
        family = UInt16(data[0]) << 8 | UInt16(data[1])
        sourceNetmask = data[2]
        sourceScope = data[3]
        address = Array(data[4...])
    }
    public var code: UInt16 { EDNS0Code.subnet }
    public func packData() -> [UInt8] {
        be16(family) + [sourceNetmask, sourceScope] + address
    }
}

/// TCP Keepalive (RFC 7828): idle timeout in 100ms units, or absent (0 bytes).
public struct EDNS0_TCP_KEEPALIVE: EDNS0Option {
    public var timeout: UInt16?
    public init(timeout: UInt16?) { self.timeout = timeout }
    public init(data: [UInt8]) throws {
        switch data.count {
        case 0: timeout = nil
        case 2: timeout = UInt16(data[0]) << 8 | UInt16(data[1])
        default: throw WireError.malformedText("TCP keepalive length must be 0 or 2")
        }
    }
    public var code: UInt16 { EDNS0Code.tcpKeepalive }
    public func packData() -> [UInt8] { timeout.map(be16) ?? [] }
}

/// EXPIRE (RFC 7314): 4-byte value, or empty (0 bytes) in a query.
public struct EDNS0_EXPIRE: EDNS0Option {
    public var expire: UInt32?
    public init(expire: UInt32?) { self.expire = expire }
    public init(data: [UInt8]) throws {
        if data.isEmpty { expire = nil; return }
        guard data.count >= 4 else { throw WireError.bufferTooShort(needed: 4, available: data.count) }
        expire = UInt32(data[0]) << 24 | UInt32(data[1]) << 16 | UInt32(data[2]) << 8 | UInt32(data[3])
    }
    public var code: UInt16 { EDNS0Code.expire }
    public func packData() -> [UInt8] { expire.map(be32) ?? [] }
}

/// Fallback for any option code we don't model specifically: raw data.
public struct EDNS0_LOCAL: EDNS0Option {
    public let code: UInt16
    public var data: [UInt8]
    public init(code: UInt16, data: [UInt8]) { self.code = code; self.data = data }
    public func packData() -> [UInt8] { data }
}

/// Decodes an option's data payload into the appropriate concrete type.
enum EDNS0Registry {
    static func decode(code: UInt16, data: [UInt8]) throws -> any EDNS0Option {
        switch code {
        case EDNS0Code.nsid: return EDNS0_NSID(nsid: data)
        case EDNS0Code.cookie: return EDNS0_COOKIE(cookie: data)
        case EDNS0Code.padding: return EDNS0_PADDING(padding: data)
        case EDNS0Code.ede: return try EDNS0_EDE(data: data)
        case EDNS0Code.subnet: return try EDNS0_SUBNET(data: data)
        case EDNS0Code.tcpKeepalive: return try EDNS0_TCP_KEEPALIVE(data: data)
        case EDNS0Code.expire: return try EDNS0_EXPIRE(data: data)
        default: return EDNS0_LOCAL(code: code, data: data)
        }
    }
}

/// The EDNS0 OPT pseudo-record.
public struct OPT: RR {
    public var header: RRHeader
    public var options: [any EDNS0Option]

    /// Builds an OPT record from EDNS0 parameters (encodes the header fields).
    public init(udpSize: UInt16 = 1232, dnssecOK: Bool = false, version: UInt8 = 0,
                extendedRcodeHigh: UInt8 = 0, z: UInt16 = 0, options: [any EDNS0Option] = []) {
        var ttl: UInt32 = 0
        ttl |= UInt32(extendedRcodeHigh) << 24
        ttl |= UInt32(version) << 16
        ttl |= UInt32(z & 0x3FFF)
        if dnssecOK { ttl |= 0x8000 }
        self.header = RRHeader(name: Name("."), type: .opt, class: RRClass(rawValue: udpSize), ttl: ttl)
        self.options = options
    }

    // MARK: EDNS0 header accessors (repurposed CLASS / TTL fields)

    public var udpSize: UInt16 {
        get { header.class.rawValue }
        set { header.class = RRClass(rawValue: newValue) }
    }
    public var dnssecOK: Bool {
        get { header.ttl & 0x8000 != 0 }
        set { if newValue { header.ttl |= 0x8000 } else { header.ttl &= ~UInt32(0x8000) } }
    }
    public var version: UInt8 {
        get { UInt8((header.ttl & 0x00FF_0000) >> 16) }
        set { header.ttl = header.ttl & 0xFF00_FFFF | (UInt32(newValue) << 16) }
    }
    /// The Z field (low 14 bits of the TTL flags word).
    public var z: UInt16 {
        get { UInt16(header.ttl & 0x3FFF) }
        set { header.ttl = header.ttl & ~UInt32(0x3FFF) | UInt32(newValue & 0x3FFF) }
    }

    // MARK: RR conformance

    public func packRdata(into buf: inout MessagePacker) throws {
        for opt in options {
            buf.appendUInt16(opt.code)
            let data = try opt.packData()
            guard data.count <= Int(UInt16.max) else { throw WireError.valueOutOfRange }
            buf.appendUInt16(UInt16(data.count))
            buf.appendBytes(data)
        }
    }

    public init(header: RRHeader, rdata buf: inout MessageUnpacker) throws {
        self.header = header
        var opts: [any EDNS0Option] = []
        let start = buf.offset
        while buf.offset - start < Int(header.rdlength) {
            let code = try buf.readUInt16()
            let len = Int(try buf.readUInt16())
            let data = try buf.readBytes(len)
            opts.append(try EDNS0Registry.decode(code: code, data: data))
        }
        self.options = opts
    }

    public init(header: RRHeader, rdataTokens tokens: [String], origin: String) throws {
        throw WireError.malformedText("presentation parsing not supported for OPT")
    }
}
