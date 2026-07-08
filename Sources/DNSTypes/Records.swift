import DNSCore

// A representative slice of record types spanning every wire-encoding category
// the Part 0 macro prototype must handle: fixed integers, IPv4/IPv6 rdata,
// (compressible) domain names, character-string lists, and multi-field records.
// The remaining ~95 types are added in Part 2 once the macro is proven.

@DNSRecord
public struct A: RR {
    public var header: RRHeader
    public var a: IPv4Address
}

@DNSRecord
public struct AAAA: RR {
    public var header: RRHeader
    public var aaaa: IPv6Address
}

@DNSRecord
public struct NS: RR {
    public var header: RRHeader
    @Compressed public var ns: Name
}

@DNSRecord
public struct CNAME: RR {
    public var header: RRHeader
    @Compressed public var target: Name
}

@DNSRecord
public struct MX: RR {
    public var header: RRHeader
    public var preference: UInt16
    @Compressed public var mx: Name
}

@DNSRecord
public struct TXT: RR {
    public var header: RRHeader
    public var txt: [String]
}

@DNSRecord
public struct SOA: RR {
    public var header: RRHeader
    @Compressed public var ns: Name
    @Compressed public var mbox: Name
    public var serial: UInt32
    public var refresh: UInt32
    public var retry: UInt32
    public var expire: UInt32
    public var minttl: UInt32
}
