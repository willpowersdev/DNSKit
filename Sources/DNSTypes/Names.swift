// Mnemonic <-> code tables for RR types and classes, used by presentation
// (zone-file) parsing and rendering. Unknown values use the RFC 3597 generic
// forms `TYPE<n>` / `CLASS<n>`.

extension RRType {
    static let mnemonicToCode: [String: UInt16] = [
        "A": 1, "NS": 2, "MD": 3, "MF": 4, "CNAME": 5, "SOA": 6, "MB": 7, "MG": 8, "MR": 9,
        "NULL": 10, "PTR": 12, "HINFO": 13, "MINFO": 14, "MX": 15, "TXT": 16, "RP": 17,
        "AFSDB": 18, "X25": 19, "ISDN": 20, "RT": 21, "NSAPPTR": 23, "SIG": 24, "KEY": 25,
        "PX": 26, "GPOS": 27, "AAAA": 28, "LOC": 29, "NXT": 30, "EID": 31, "NIMLOC": 32,
        "SRV": 33, "NAPTR": 35, "KX": 36, "CERT": 37, "DNAME": 39, "OPT": 41, "APL": 42,
        "DS": 43, "SSHFP": 44, "IPSECKEY": 45, "RRSIG": 46, "NSEC": 47, "DNSKEY": 48,
        "DHCID": 49, "NSEC3": 50, "NSEC3PARAM": 51, "TLSA": 52, "SMIMEA": 53, "HIP": 55,
        "NINFO": 56, "RKEY": 57, "TALINK": 58, "CDS": 59, "CDNSKEY": 60, "OPENPGPKEY": 61,
        "CSYNC": 62, "ZONEMD": 63, "SVCB": 64, "HTTPS": 65, "SPF": 99, "UINFO": 100,
        "UID": 101, "GID": 102, "NID": 104, "L32": 105, "L64": 106, "LP": 107, "EUI48": 108,
        "EUI64": 109, "NXNAME": 128, "TKEY": 249, "TSIG": 250, "IXFR": 251, "AXFR": 252,
        "ANY": 255, "URI": 256, "CAA": 257, "AVC": 258, "AMTRELAY": 260, "RESINFO": 261,
        "TA": 32768, "DLV": 32769,
    ]
    static let codeToMnemonic: [UInt16: String] = {
        var m = [UInt16: String]()
        for (k, v) in mnemonicToCode { m[v] = k }
        return m
    }()

    public static func mnemonic(_ type: RRType) -> String {
        codeToMnemonic[type.rawValue] ?? "TYPE\(type.rawValue)"
    }
    public static func fromMnemonic(_ s: String) -> RRType? {
        if let code = mnemonicToCode[s.uppercased()] { return RRType(rawValue: code) }
        if s.uppercased().hasPrefix("TYPE"), let n = UInt16(s.dropFirst(4)) { return RRType(rawValue: n) }
        return nil
    }
}

extension RRClass {
    static let mnemonicToCode: [String: UInt16] = [
        "IN": 1, "CH": 3, "HS": 4, "NONE": 254, "ANY": 255,
    ]
    static let codeToMnemonic: [UInt16: String] = {
        var m = [UInt16: String]()
        for (k, v) in mnemonicToCode { m[v] = k }
        return m
    }()

    public static func mnemonic(_ cls: RRClass) -> String {
        codeToMnemonic[cls.rawValue] ?? "CLASS\(cls.rawValue)"
    }
    public static func fromMnemonic(_ s: String) -> RRClass? {
        if let code = mnemonicToCode[s.uppercased()] { return RRClass(rawValue: code) }
        if s.uppercased().hasPrefix("CLASS"), let n = UInt16(s.dropFirst(5)) { return RRClass(rawValue: n) }
        return nil
    }
}
