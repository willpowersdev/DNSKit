import DNSCore

// Records with bespoke union / prefix wire formats that the @DNSRecord macro
// can't express: IPSECKEY and AMTRELAY (a gateway whose encoding depends on a
// type field) and APL (a list of address-prefix items). Presentation format is
// not yet implemented for these (the init/render stubs throw).

/// An IPSECKEY/AMTRELAY gateway (RFC 4025 / RFC 8777). The wire "gateway type"
/// is derived from the case: none=0, IPv4=1, IPv6=2, host=3.
public enum Gateway: Sendable, Equatable {
    case none
    case ipv4(IPv4Address)
    case ipv6(IPv6Address)
    case host(Name)

    public var typeCode: UInt8 {
        switch self {
        case .none: return 0
        case .ipv4: return 1
        case .ipv6: return 2
        case .host: return 3
        }
    }

    func pack(into buf: inout MessagePacker) throws {
        switch self {
        case .none: break
        case .ipv4(let a): buf.appendBytes(a.bytes)
        case .ipv6(let a): buf.appendBytes(a.bytes)
        case .host(let n): try buf.appendName(n, compress: false)
        }
    }

    static func unpack(type: UInt8, from buf: inout MessageUnpacker) throws -> Gateway {
        switch type {
        case 0: return .none
        case 1: return .ipv4(IPv4Address(bytes: try buf.readBytes(4)))
        case 2: return .ipv6(IPv6Address(bytes: try buf.readBytes(16)))
        case 3: return .host(try buf.readName())
        default: throw WireError.malformedText("unknown gateway type \(type)")
        }
    }
}

/// IPSECKEY (RFC 4025).
public struct IPSECKEY: RR {
    public var header: RRHeader
    public var precedence: UInt8
    public var algorithm: UInt8
    public var gateway: Gateway
    public var publicKey: [UInt8] // base64 in presentation; rest of rdata

    public init(header: RRHeader, precedence: UInt8, algorithm: UInt8,
                gateway: Gateway, publicKey: [UInt8]) {
        self.header = header; self.precedence = precedence; self.algorithm = algorithm
        self.gateway = gateway; self.publicKey = publicKey
    }

    public func packRdata(into buf: inout MessagePacker) throws {
        buf.appendUInt8(precedence)
        buf.appendUInt8(gateway.typeCode)
        buf.appendUInt8(algorithm)
        try gateway.pack(into: &buf)
        buf.appendBytes(publicKey)
    }

    public init(header: RRHeader, rdata buf: inout MessageUnpacker) throws {
        self.header = header
        let start = buf.offset
        precedence = try buf.readUInt8()
        let gatewayType = try buf.readUInt8()
        algorithm = try buf.readUInt8()
        gateway = try Gateway.unpack(type: gatewayType, from: &buf)
        let consumed = buf.offset - start
        publicKey = try buf.readBytes(Int(header.rdlength) - consumed)
    }

    public init(header: RRHeader, rdataTokens tokens: [String], origin: String) throws {
        throw WireError.malformedText("presentation parsing not supported for IPSECKEY")
    }
}

/// AMTRELAY (RFC 8777). The gateway-type byte carries a discovery flag at 0x80.
public struct AMTRELAY: RR {
    public var header: RRHeader
    public var precedence: UInt8
    public var discovery: Bool
    public var gateway: Gateway

    public init(header: RRHeader, precedence: UInt8, discovery: Bool, gateway: Gateway) {
        self.header = header; self.precedence = precedence
        self.discovery = discovery; self.gateway = gateway
    }

    public func packRdata(into buf: inout MessagePacker) throws {
        buf.appendUInt8(precedence)
        buf.appendUInt8((discovery ? 0x80 : 0) | gateway.typeCode)
        try gateway.pack(into: &buf)
    }

    public init(header: RRHeader, rdata buf: inout MessageUnpacker) throws {
        self.header = header
        precedence = try buf.readUInt8()
        let typeByte = try buf.readUInt8()
        discovery = typeByte & 0x80 != 0
        gateway = try Gateway.unpack(type: typeByte & 0x7f, from: &buf)
    }

    public init(header: RRHeader, rdataTokens tokens: [String], origin: String) throws {
        throw WireError.malformedText("presentation parsing not supported for AMTRELAY")
    }
}

/// A single APL address-prefix item (RFC 3123).
public struct APLPrefix: Sendable, Equatable {
    public var family: UInt16   // 1 = IPv4, 2 = IPv6
    public var prefix: UInt8    // CIDR prefix length
    public var negation: Bool
    public var afdPart: [UInt8] // significant address bytes (trailing zeros trimmed)

    public init(family: UInt16, prefix: UInt8, negation: Bool, afdPart: [UInt8]) {
        self.family = family; self.prefix = prefix
        self.negation = negation; self.afdPart = afdPart
    }
}

/// APL (RFC 3123).
public struct APL: RR {
    public var header: RRHeader
    public var prefixes: [APLPrefix]

    public init(header: RRHeader, prefixes: [APLPrefix]) {
        self.header = header; self.prefixes = prefixes
    }

    public func packRdata(into buf: inout MessagePacker) throws {
        for p in prefixes {
            buf.appendUInt16(p.family)
            buf.appendUInt8(p.prefix)
            guard p.afdPart.count <= 0x7f else { throw WireError.valueOutOfRange }
            buf.appendUInt8((p.negation ? 0x80 : 0) | UInt8(p.afdPart.count))
            buf.appendBytes(p.afdPart)
        }
    }

    public init(header: RRHeader, rdata buf: inout MessageUnpacker) throws {
        self.header = header
        var out: [APLPrefix] = []
        let start = buf.offset
        while buf.offset - start < Int(header.rdlength) {
            let family = try buf.readUInt16()
            let prefix = try buf.readUInt8()
            let nlen = try buf.readUInt8()
            let afd = try buf.readBytes(Int(nlen & 0x7f))
            out.append(APLPrefix(family: family, prefix: prefix, negation: nlen & 0x80 != 0, afdPart: afd))
        }
        self.prefixes = out
    }

    public init(header: RRHeader, rdataTokens tokens: [String], origin: String) throws {
        throw WireError.malformedText("presentation parsing not supported for APL")
    }
}
