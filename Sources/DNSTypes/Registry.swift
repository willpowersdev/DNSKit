import DNSCore

/// Maps RR type codes to their concrete Swift types for polymorphic unpacking.
/// This is the single enumeration point of all wire-decodable record types;
/// unknown types fall back to ``RFC3597`` (opaque rdata), matching the Go
/// library's behavior. When new record types are added, register them here.
enum RRRegistry {
    typealias Decoder = @Sendable (RRHeader, inout MessageUnpacker) throws -> any RR

    static let byType: [UInt16: Decoder] = {
        func d<T: RR>(_ type: T.Type) -> Decoder { { h, u in try T(header: h, rdata: &u) } }
        return [
            RRType.a.rawValue: d(A.self),
            RRType.aaaa.rawValue: d(AAAA.self),
            RRType.ns.rawValue: d(NS.self),
            RRType.cname.rawValue: d(CNAME.self),
            RRType.dname.rawValue: d(DNAME.self),
            RRType.ptr.rawValue: d(PTR.self),
            RRType.nsapptr.rawValue: d(NSAPPTR.self),
            RRType.mb.rawValue: d(MB.self),
            RRType.mg.rawValue: d(MG.self),
            RRType.mr.rawValue: d(MR.self),
            RRType.mf.rawValue: d(MF.self),
            RRType.md.rawValue: d(MD.self),
            RRType.minfo.rawValue: d(MINFO.self),
            RRType.mx.rawValue: d(MX.self),
            RRType.rp.rawValue: d(RP.self),
            RRType.soa.rawValue: d(SOA.self),
            RRType.afsdb.rawValue: d(AFSDB.self),
            RRType.rt.rawValue: d(RT.self),
            RRType.kx.rawValue: d(KX.self),
            RRType.px.rawValue: d(PX.self),
            RRType.srv.rawValue: d(SRV.self),
            RRType.hinfo.rawValue: d(HINFO.self),
            RRType.x25.rawValue: d(X25.self),
            RRType.isdn.rawValue: d(ISDN.self),
            RRType.gpos.rawValue: d(GPOS.self),
            RRType.txt.rawValue: d(TXT.self),
            RRType.spf.rawValue: d(SPF.self),
            RRType.avc.rawValue: d(AVC.self),
            RRType.ninfo.rawValue: d(NINFO.self),
            RRType.resinfo.rawValue: d(RESINFO.self),
            RRType.naptr.rawValue: d(NAPTR.self),
            RRType.uri.rawValue: d(URI.self),
            RRType.caa.rawValue: d(CAA.self),
            RRType.loc.rawValue: d(LOC.self),
            RRType.rrsig.rawValue: d(RRSIG.self),
            RRType.sig.rawValue: d(SIG.self),
            RRType.nsec.rawValue: d(NSEC.self),
            RRType.nxt.rawValue: d(NXT.self),
            RRType.ds.rawValue: d(DS.self),
            RRType.dlv.rawValue: d(DLV.self),
            RRType.cds.rawValue: d(CDS.self),
            RRType.ta.rawValue: d(TA.self),
            RRType.talink.rawValue: d(TALINK.self),
            RRType.sshfp.rawValue: d(SSHFP.self),
            RRType.dnskey.rawValue: d(DNSKEY.self),
            RRType.key.rawValue: d(KEY.self),
            RRType.cdnskey.rawValue: d(CDNSKEY.self),
            RRType.rkey.rawValue: d(RKEY.self),
            RRType.cert.rawValue: d(CERT.self),
            RRType.nsec3.rawValue: d(NSEC3.self),
            RRType.nsec3param.rawValue: d(NSEC3PARAM.self),
            RRType.csync.rawValue: d(CSYNC.self),
            RRType.zonemd.rawValue: d(ZONEMD.self),
            RRType.hip.rawValue: d(HIP.self),
            RRType.openpgpkey.rawValue: d(OPENPGPKEY.self),
            RRType.tlsa.rawValue: d(TLSA.self),
            RRType.smimea.rawValue: d(SMIMEA.self),
            RRType.dhcid.rawValue: d(DHCID.self),
            RRType.tkey.rawValue: d(TKEY.self),
            RRType.nid.rawValue: d(NID.self),
            RRType.l32.rawValue: d(L32.self),
            RRType.l64.rawValue: d(L64.self),
            RRType.lp.rawValue: d(LP.self),
            RRType.eui48.rawValue: d(EUI48.self),
            RRType.eui64.rawValue: d(EUI64.self),
            RRType.eid.rawValue: d(EID.self),
            RRType.nimloc.rawValue: d(NIMLOC.self),
            RRType.uid.rawValue: d(UID.self),
            RRType.gid.rawValue: d(GID.self),
            RRType.uinfo.rawValue: d(UINFO.self),
            RRType.null.rawValue: d(NULL.self),
            RRType.any.rawValue: d(ANY.self),
            RRType.nxname.rawValue: d(NXNAME.self),
            RRType.opt.rawValue: d(OPT.self),
            RRType.svcb.rawValue: d(SVCB.self),
            RRType.https.rawValue: d(HTTPS.self),
            RRType.tsig.rawValue: d(TSIG.self),
        ]
    }()

    static func decode(header: RRHeader, from buf: inout MessageUnpacker) throws -> any RR {
        if let decoder = byType[header.type.rawValue] {
            return try decoder(header, &buf)
        }
        return try RFC3597(header: header, rdata: &buf)
    }
}

/// Reads one resource record (header + rdata) from the cursor, dispatching to
/// the concrete type by its type code and verifying the RDLENGTH.
public func unpackRR(from buf: inout MessageUnpacker) throws -> any RR {
    let name = try buf.readName()
    let type = RRType(rawValue: try buf.readUInt16())
    let cls = RRClass(rawValue: try buf.readUInt16())
    let ttl = try buf.readUInt32()
    let rdlength = try buf.readUInt16()
    let header = RRHeader(name: name, type: type, class: cls, ttl: ttl, rdlength: rdlength)
    let start = buf.offset
    let rr = try RRRegistry.decode(header: header, from: &buf)
    let consumed = buf.offset - start
    guard consumed == Int(rdlength) else {
        throw WireError.rdataLengthMismatch(declared: Int(rdlength), consumed: consumed)
    }
    return rr
}
