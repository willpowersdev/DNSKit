import DNSCore

/// DNS RR type code (RFC 1035 §3.2.2 and successors).
public struct RRType: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let a = RRType(rawValue: 1)
    public static let ns = RRType(rawValue: 2)
    public static let cname = RRType(rawValue: 5)
    public static let soa = RRType(rawValue: 6)
    public static let mx = RRType(rawValue: 15)
    public static let txt = RRType(rawValue: 16)
    public static let aaaa = RRType(rawValue: 28)
}

/// DNS class (almost always `IN`).
public struct RRClass: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let `in` = RRClass(rawValue: 1)
    public static let ch = RRClass(rawValue: 3)
    public static let hs = RRClass(rawValue: 4)
    public static let any = RRClass(rawValue: 255)
}

/// The fixed header that precedes every resource record's rdata.
public struct RRHeader: Sendable, Equatable {
    public var name: Name
    public var type: RRType
    public var `class`: RRClass
    public var ttl: UInt32
    public var rdlength: UInt16

    public init(name: Name, type: RRType, class cls: RRClass = .in,
                ttl: UInt32 = 0, rdlength: UInt16 = 0) {
        self.name = name
        self.type = type
        self.class = cls
        self.ttl = ttl
        self.rdlength = rdlength
    }
}

/// A resource record. Concrete records supply their rdata codec via the
/// `@DNSRecord` macro; the header framing is provided generically here.
public protocol RR: Sendable {
    var header: RRHeader { get set }
    func packRdata(into buf: inout MessagePacker) throws
    init(header: RRHeader, rdata buf: inout MessageUnpacker) throws
}

extension RR {
    /// Packs the full record: header, then rdata with a back-patched RDLENGTH.
    public func pack(into buf: inout MessagePacker) throws {
        try buf.appendName(header.name, compress: true)
        buf.appendUInt16(header.type.rawValue)
        buf.appendUInt16(header.class.rawValue)
        buf.appendUInt32(header.ttl)
        let lenSlot = buf.count
        buf.appendUInt16(0) // RDLENGTH placeholder
        let rdataStart = buf.count
        try packRdata(into: &buf)
        let rdlen = buf.count - rdataStart
        guard rdlen <= Int(UInt16.max) else { throw WireError.valueOutOfRange }
        buf.patchUInt16(at: lenSlot, UInt16(rdlen))
    }

    /// Unpacks a full record of this concrete type from the cursor and verifies
    /// that the rdata consumed matches the declared RDLENGTH.
    public static func unpack(from buf: inout MessageUnpacker) throws -> Self {
        let name = try buf.readName()
        let type = RRType(rawValue: try buf.readUInt16())
        let cls = RRClass(rawValue: try buf.readUInt16())
        let ttl = try buf.readUInt32()
        let rdlength = try buf.readUInt16()
        let header = RRHeader(name: name, type: type, class: cls, ttl: ttl, rdlength: rdlength)
        let start = buf.offset
        let rr = try Self(header: header, rdata: &buf)
        let consumed = buf.offset - start
        guard consumed == Int(rdlength) else {
            throw WireError.rdataLengthMismatch(declared: Int(rdlength), consumed: consumed)
        }
        return rr
    }
}
