import DNSCore

// All generically-encodable resource records from the Go library's types.go,
// ported as @DNSRecord declarations. Wire order matches Go exactly.
//
// Deferred to later milestones (bespoke union / keyed wire formats):
//   OPT (EDNS0), SVCB, HTTPS  -> Part 3
//   APL, IPSECKEY, AMTRELAY   -> require gateway/prefix codecs
//   TSIG                      -> Part 5
//
// Field-name notes: Go's `Protocol` is a Swift keyword, so DNSKEY-family
// records use `proto`. Everything else keeps the Go name lowerCamelCased.

// MARK: - Names / delegation

@DNSRecord public struct ANY: RR { public var header: RRHeader } // no rdata
@DNSRecord public struct NXNAME: RR { public var header: RRHeader } // no rdata

@DNSRecord public struct NULL: RR {
    public var header: RRHeader
    public var data: [UInt8] // dns:"any" — raw rest of rdata
}

@DNSRecord public struct CNAME: RR {
    public var header: RRHeader
    @Compressed public var target: Name
}

@DNSRecord public struct DNAME: RR {
    public var header: RRHeader
    public var target: Name
}

@DNSRecord public struct NS: RR {
    public var header: RRHeader
    @Compressed public var ns: Name
}

@DNSRecord public struct PTR: RR {
    public var header: RRHeader
    @Compressed public var ptr: Name
}

@DNSRecord public struct NSAPPTR: RR {
    public var header: RRHeader
    public var ptr: Name
}

@DNSRecord public struct MB: RR { public var header: RRHeader; @Compressed public var mb: Name }
@DNSRecord public struct MG: RR { public var header: RRHeader; @Compressed public var mg: Name }
@DNSRecord public struct MR: RR { public var header: RRHeader; @Compressed public var mr: Name }
@DNSRecord public struct MF: RR { public var header: RRHeader; @Compressed public var mf: Name }
@DNSRecord public struct MD: RR { public var header: RRHeader; @Compressed public var md: Name }

@DNSRecord public struct MINFO: RR {
    public var header: RRHeader
    @Compressed public var rmail: Name
    @Compressed public var email: Name
}

@DNSRecord public struct MX: RR {
    public var header: RRHeader
    public var preference: UInt16
    @Compressed public var mx: Name
}

@DNSRecord public struct RP: RR {
    public var header: RRHeader
    public var mbox: Name
    public var txt: Name
}

@DNSRecord public struct SOA: RR {
    public var header: RRHeader
    @Compressed public var ns: Name
    @Compressed public var mbox: Name
    public var serial: UInt32
    public var refresh: UInt32
    public var retry: UInt32
    public var expire: UInt32
    public var minttl: UInt32
}

// MARK: - Addresses / hosts

@DNSRecord public struct A: RR {
    public var header: RRHeader
    public var a: IPv4Address
}

@DNSRecord public struct AAAA: RR {
    public var header: RRHeader
    public var aaaa: IPv6Address
}

@DNSRecord public struct AFSDB: RR {
    public var header: RRHeader
    public var subtype: UInt16
    public var hostname: Name
}

@DNSRecord public struct RT: RR {
    public var header: RRHeader
    public var preference: UInt16
    public var host: Name
}

@DNSRecord public struct KX: RR {
    public var header: RRHeader
    public var preference: UInt16
    public var exchanger: Name
}

@DNSRecord public struct PX: RR {
    public var header: RRHeader
    public var preference: UInt16
    public var map822: Name
    public var mapx400: Name
}

@DNSRecord public struct SRV: RR {
    public var header: RRHeader
    public var priority: UInt16
    public var weight: UInt16
    public var port: UInt16
    public var target: Name
}

// MARK: - Text-ish

@DNSRecord public struct HINFO: RR {
    public var header: RRHeader
    public var cpu: String
    public var os: String
}

@DNSRecord public struct X25: RR {
    public var header: RRHeader
    public var psdnAddress: String
}

@DNSRecord public struct ISDN: RR {
    public var header: RRHeader
    public var address: String
    public var subAddress: String
}

@DNSRecord public struct GPOS: RR {
    public var header: RRHeader
    public var longitude: String
    public var latitude: String
    public var altitude: String
}

@DNSRecord public struct TXT: RR { public var header: RRHeader; public var txt: [String] }
@DNSRecord public struct SPF: RR { public var header: RRHeader; public var txt: [String] }
@DNSRecord public struct AVC: RR { public var header: RRHeader; public var txt: [String] }
@DNSRecord public struct NINFO: RR { public var header: RRHeader; public var zsData: [String] }
@DNSRecord public struct RESINFO: RR { public var header: RRHeader; public var txt: [String] }

@DNSRecord public struct NAPTR: RR {
    public var header: RRHeader
    public var order: UInt16
    public var preference: UInt16
    public var flags: String
    public var service: String
    public var regexp: String
    public var replacement: Name
}

@DNSRecord public struct URI: RR {
    public var header: RRHeader
    public var priority: UInt16
    public var weight: UInt16
    @Octet public var target: String
}

@DNSRecord public struct CAA: RR {
    public var header: RRHeader
    public var flag: UInt8
    public var tag: String
    @Octet public var value: String
}

// MARK: - LOC

@DNSRecord public struct LOC: RR {
    public var header: RRHeader
    public var version: UInt8
    public var size: UInt8
    public var horizPre: UInt8
    public var vertPre: UInt8
    public var latitude: UInt32
    public var longitude: UInt32
    public var altitude: UInt32
}

// MARK: - DNSSEC

@DNSRecord public struct RRSIG: RR {
    public var header: RRHeader
    public var typeCovered: UInt16
    public var algorithm: UInt8
    public var labels: UInt8
    public var origTtl: UInt32
    public var expiration: UInt32
    public var inception: UInt32
    public var keyTag: UInt16
    public var signerName: Name
    @Base64 public var signature: [UInt8] // base64
}

@DNSRecord public struct SIG: RR {
    public var header: RRHeader
    public var typeCovered: UInt16
    public var algorithm: UInt8
    public var labels: UInt8
    public var origTtl: UInt32
    public var expiration: UInt32
    public var inception: UInt32
    public var keyTag: UInt16
    public var signerName: Name
    public var signature: [UInt8]
}

@DNSRecord public struct NSEC: RR {
    public var header: RRHeader
    public var nextDomain: Name
    public var typeBitMap: [UInt16]
}

@DNSRecord public struct NXT: RR {
    public var header: RRHeader
    public var nextDomain: Name
    public var typeBitMap: [UInt16]
}

@DNSRecord public struct DS: RR {
    public var header: RRHeader
    public var keyTag: UInt16
    public var algorithm: UInt8
    public var digestType: UInt8
    public var digest: [UInt8] // hex
}

@DNSRecord public struct DLV: RR {
    public var header: RRHeader
    public var keyTag: UInt16
    public var algorithm: UInt8
    public var digestType: UInt8
    public var digest: [UInt8]
}

@DNSRecord public struct CDS: RR {
    public var header: RRHeader
    public var keyTag: UInt16
    public var algorithm: UInt8
    public var digestType: UInt8
    public var digest: [UInt8]
}

@DNSRecord public struct TA: RR {
    public var header: RRHeader
    public var keyTag: UInt16
    public var algorithm: UInt8
    public var digestType: UInt8
    public var digest: [UInt8]
}

@DNSRecord public struct TALINK: RR {
    public var header: RRHeader
    public var previousName: Name
    public var nextName: Name
}

@DNSRecord public struct SSHFP: RR {
    public var header: RRHeader
    public var algorithm: UInt8
    public var type: UInt8
    public var fingerPrint: [UInt8] // hex
}

@DNSRecord public struct DNSKEY: RR {
    public var header: RRHeader
    public var flags: UInt16
    public var proto: UInt8
    public var algorithm: UInt8
    @Base64 public var publicKey: [UInt8] // base64
}

@DNSRecord public struct KEY: RR {
    public var header: RRHeader
    public var flags: UInt16
    public var proto: UInt8
    public var algorithm: UInt8
    public var publicKey: [UInt8]
}

@DNSRecord public struct CDNSKEY: RR {
    public var header: RRHeader
    public var flags: UInt16
    public var proto: UInt8
    public var algorithm: UInt8
    public var publicKey: [UInt8]
}

@DNSRecord public struct RKEY: RR {
    public var header: RRHeader
    public var flags: UInt16
    public var proto: UInt8
    public var algorithm: UInt8
    public var publicKey: [UInt8]
}

@DNSRecord public struct CERT: RR {
    public var header: RRHeader
    public var type: UInt16
    public var keyTag: UInt16
    public var algorithm: UInt8
    @Base64 public var certificate: [UInt8] // base64
}

@DNSRecord public struct NSEC3: RR {
    public var header: RRHeader
    public var hash: UInt8
    public var flags: UInt8
    public var iterations: UInt16
    public var saltLength: UInt8
    @SizePrefixed("saltLength") public var salt: [UInt8]
    public var hashLength: UInt8
    @SizePrefixed("hashLength") public var nextDomain: [UInt8] // base32-presented hash
    public var typeBitMap: [UInt16]
}

@DNSRecord public struct NSEC3PARAM: RR {
    public var header: RRHeader
    public var hash: UInt8
    public var flags: UInt8
    public var iterations: UInt16
    public var saltLength: UInt8
    @SizePrefixed("saltLength") public var salt: [UInt8]
}

@DNSRecord public struct CSYNC: RR {
    public var header: RRHeader
    public var serial: UInt32
    public var flags: UInt16
    public var typeBitMap: [UInt16]
}

@DNSRecord public struct ZONEMD: RR {
    public var header: RRHeader
    public var serial: UInt32
    public var scheme: UInt8
    public var hash: UInt8
    public var digest: [UInt8] // hex
}

@DNSRecord public struct HIP: RR {
    public var header: RRHeader
    public var hitLength: UInt8
    public var publicKeyAlgorithm: UInt8
    public var publicKeyLength: UInt16
    @SizePrefixed("hitLength") public var hit: [UInt8]
    @SizePrefixed("publicKeyLength") public var publicKey: [UInt8]
    public var rendezvousServers: [Name]
}

@DNSRecord public struct OPENPGPKEY: RR {
    public var header: RRHeader
    @Base64 public var publicKey: [UInt8] // base64
}

// MARK: - Certificates / hashes

@DNSRecord public struct TLSA: RR {
    public var header: RRHeader
    public var usage: UInt8
    public var selector: UInt8
    public var matchingType: UInt8
    public var certificate: [UInt8] // hex
}

@DNSRecord public struct SMIMEA: RR {
    public var header: RRHeader
    public var usage: UInt8
    public var selector: UInt8
    public var matchingType: UInt8
    public var certificate: [UInt8]
}

@DNSRecord public struct DHCID: RR {
    public var header: RRHeader
    @Base64 public var digest: [UInt8] // base64
}

// MARK: - Key exchange / transaction key

@DNSRecord public struct TKEY: RR {
    public var header: RRHeader
    public var algorithm: Name
    public var inception: UInt32
    public var expiration: UInt32
    public var mode: UInt16
    public var error: UInt16
    public var keySize: UInt16
    @SizePrefixed("keySize") public var key: [UInt8]
    public var otherLen: UInt16
    @SizePrefixed("otherLen") public var otherData: [UInt8]
}

// MARK: - Identifiers / locators

@DNSRecord public struct NID: RR {
    public var header: RRHeader
    public var preference: UInt16
    public var nodeID: UInt64
}

@DNSRecord public struct L32: RR {
    public var header: RRHeader
    public var preference: UInt16
    public var locator32: IPv4Address
}

@DNSRecord public struct L64: RR {
    public var header: RRHeader
    public var preference: UInt16
    public var locator64: UInt64
}

@DNSRecord public struct LP: RR {
    public var header: RRHeader
    public var preference: UInt16
    public var fqdn: Name
}

@DNSRecord public struct EUI48: RR {
    public var header: RRHeader
    @UInt48 public var address: UInt64
}

@DNSRecord public struct EUI64: RR {
    public var header: RRHeader
    public var address: UInt64
}

@DNSRecord public struct EID: RR {
    public var header: RRHeader
    public var endpoint: [UInt8] // hex
}

@DNSRecord public struct NIMLOC: RR {
    public var header: RRHeader
    public var locator: [UInt8] // hex
}

// MARK: - Misc / local-use

@DNSRecord public struct UID: RR { public var header: RRHeader; public var uid: UInt32 }
@DNSRecord public struct GID: RR { public var header: RRHeader; public var gid: UInt32 }
@DNSRecord public struct UINFO: RR { public var header: RRHeader; public var uinfo: String }

@DNSRecord public struct RFC3597: RR {
    public var header: RRHeader
    public var rdata: [UInt8] // hex — unknown-type opaque rdata
}
