import DNSCore

/// Builds a DNS dynamic-update message (RFC 2136). The message reuses the
/// standard sections with UPDATE semantics: the question is the zone, the
/// answer section holds prerequisites, and the authority section holds the
/// updates. Deletions use empty-rdata (`ANY`) records with special class/type,
/// exactly as the Go library does.
public struct DNSUpdate {
    public private(set) var message: Msg
    private let zoneClass: RRClass

    public init(zone: Name, class zoneClass: RRClass = .in, id: UInt16 = 0) {
        self.zoneClass = zoneClass
        var header = MsgHeader(id: id)
        header.opcode = Opcode.update
        self.message = Msg(header: header, questions: [Question(zone.fqdn, .soa, zoneClass)])
    }

    // MARK: Prerequisites (answer section)

    /// Require that a name is in use (has at least one RR). RFC 2136 §2.4.4.
    public mutating func requireNameInUse(_ name: Name) {
        message.answers.append(empty(name, .any, .any))
    }
    /// Require that a name is not in use. RFC 2136 §2.4.5.
    public mutating func requireNameNotInUse(_ name: Name) {
        message.answers.append(empty(name, .any, .none))
    }
    /// Require that an RRset exists (value-independent). RFC 2136 §2.4.1.
    public mutating func requireRRsetExists(_ name: Name, _ type: RRType) {
        message.answers.append(empty(name, type, .any))
    }
    /// Require that an RRset does not exist. RFC 2136 §2.4.3.
    public mutating func requireRRsetAbsent(_ name: Name, _ type: RRType) {
        message.answers.append(empty(name, type, .none))
    }

    // MARK: Updates (authority section)

    /// Add records to the zone. RFC 2136 §2.5.1.
    public mutating func insert(_ records: [any RR]) {
        for var rr in records {
            rr.header.class = zoneClass
            message.authorities.append(rr)
        }
    }
    /// Delete an entire RRset. RFC 2136 §2.5.2.
    public mutating func removeRRset(_ name: Name, _ type: RRType) {
        message.authorities.append(empty(name, type, .any))
    }
    /// Delete all RRsets at a name. RFC 2136 §2.5.3.
    public mutating func removeName(_ name: Name) {
        message.authorities.append(empty(name, .any, .any))
    }
    /// Delete specific records from an RRset. RFC 2136 §2.5.4.
    public mutating func remove(_ records: [any RR]) {
        for var rr in records {
            rr.header.class = .none
            rr.header.ttl = 0
            message.authorities.append(rr)
        }
    }

    /// An empty-rdata record (RDLENGTH 0) carrying the given header fields.
    private func empty(_ name: Name, _ type: RRType, _ cls: RRClass) -> ANY {
        ANY(header: RRHeader(name: name.fqdn, type: type, class: cls, ttl: 0))
    }
}
