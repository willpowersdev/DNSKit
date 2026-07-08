import DNSCore

/// DNS RR type code (RFC 1035 §3.2.2 and successors).
public struct RRType: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let none = RRType(rawValue: 0)
    public static let a = RRType(rawValue: 1)
    public static let ns = RRType(rawValue: 2)
    public static let md = RRType(rawValue: 3)
    public static let mf = RRType(rawValue: 4)
    public static let cname = RRType(rawValue: 5)
    public static let soa = RRType(rawValue: 6)
    public static let mb = RRType(rawValue: 7)
    public static let mg = RRType(rawValue: 8)
    public static let mr = RRType(rawValue: 9)
    public static let null = RRType(rawValue: 10)
    public static let ptr = RRType(rawValue: 12)
    public static let hinfo = RRType(rawValue: 13)
    public static let minfo = RRType(rawValue: 14)
    public static let mx = RRType(rawValue: 15)
    public static let txt = RRType(rawValue: 16)
    public static let rp = RRType(rawValue: 17)
    public static let afsdb = RRType(rawValue: 18)
    public static let x25 = RRType(rawValue: 19)
    public static let isdn = RRType(rawValue: 20)
    public static let rt = RRType(rawValue: 21)
    public static let nsapptr = RRType(rawValue: 23)
    public static let sig = RRType(rawValue: 24)
    public static let key = RRType(rawValue: 25)
    public static let px = RRType(rawValue: 26)
    public static let gpos = RRType(rawValue: 27)
    public static let aaaa = RRType(rawValue: 28)
    public static let loc = RRType(rawValue: 29)
    public static let nxt = RRType(rawValue: 30)
    public static let eid = RRType(rawValue: 31)
    public static let nimloc = RRType(rawValue: 32)
    public static let srv = RRType(rawValue: 33)
    public static let naptr = RRType(rawValue: 35)
    public static let kx = RRType(rawValue: 36)
    public static let cert = RRType(rawValue: 37)
    public static let dname = RRType(rawValue: 39)
    public static let opt = RRType(rawValue: 41)
    public static let apl = RRType(rawValue: 42)
    public static let ds = RRType(rawValue: 43)
    public static let sshfp = RRType(rawValue: 44)
    public static let ipseckey = RRType(rawValue: 45)
    public static let rrsig = RRType(rawValue: 46)
    public static let nsec = RRType(rawValue: 47)
    public static let dnskey = RRType(rawValue: 48)
    public static let dhcid = RRType(rawValue: 49)
    public static let nsec3 = RRType(rawValue: 50)
    public static let nsec3param = RRType(rawValue: 51)
    public static let tlsa = RRType(rawValue: 52)
    public static let smimea = RRType(rawValue: 53)
    public static let hip = RRType(rawValue: 55)
    public static let ninfo = RRType(rawValue: 56)
    public static let rkey = RRType(rawValue: 57)
    public static let talink = RRType(rawValue: 58)
    public static let cds = RRType(rawValue: 59)
    public static let cdnskey = RRType(rawValue: 60)
    public static let openpgpkey = RRType(rawValue: 61)
    public static let csync = RRType(rawValue: 62)
    public static let zonemd = RRType(rawValue: 63)
    public static let svcb = RRType(rawValue: 64)
    public static let https = RRType(rawValue: 65)
    public static let spf = RRType(rawValue: 99)
    public static let uinfo = RRType(rawValue: 100)
    public static let uid = RRType(rawValue: 101)
    public static let gid = RRType(rawValue: 102)
    public static let nid = RRType(rawValue: 104)
    public static let l32 = RRType(rawValue: 105)
    public static let l64 = RRType(rawValue: 106)
    public static let lp = RRType(rawValue: 107)
    public static let eui48 = RRType(rawValue: 108)
    public static let eui64 = RRType(rawValue: 109)
    public static let nxname = RRType(rawValue: 128)
    public static let tkey = RRType(rawValue: 249)
    public static let tsig = RRType(rawValue: 250)
    public static let ixfr = RRType(rawValue: 251)
    public static let axfr = RRType(rawValue: 252)
    public static let any = RRType(rawValue: 255)
    public static let uri = RRType(rawValue: 256)
    public static let caa = RRType(rawValue: 257)
    public static let avc = RRType(rawValue: 258)
    public static let amtrelay = RRType(rawValue: 260)
    public static let resinfo = RRType(rawValue: 261)
    public static let ta = RRType(rawValue: 32768)
    public static let dlv = RRType(rawValue: 32769)
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
    /// Builds the record from presentation-format rdata tokens.
    init(header: RRHeader, rdataTokens tokens: [String], origin: String) throws
    /// The rdata rendered in presentation (zone-file) format.
    func rdataPresentation() throws -> String
}

extension RR {
    /// Default: presentation rendering not yet implemented for this type
    /// (e.g. the hand-written OPT/SVCB records). Overridden by `@DNSRecord`.
    public func rdataPresentation() throws -> String {
        throw WireError.malformedText("presentation rendering not supported for \(Swift.type(of: self))")
    }

    /// The full record in presentation format: `name TTL CLASS TYPE rdata`.
    public func present() throws -> String {
        let type = RRType.mnemonic(header.type)
        let cls = RRClass.mnemonic(header.class)
        return "\(header.name.value)\t\(header.ttl)\t\(cls)\t\(type)\t" + (try rdataPresentation())
    }
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

    /// Full wire bytes of this record, optionally with name compression.
    public func packedBytes(compress: Bool = true) throws -> [UInt8] {
        var buf = MessagePacker(compressionEnabled: compress)
        try pack(into: &buf)
        return buf.bytes
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
