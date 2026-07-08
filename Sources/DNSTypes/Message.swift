import DNSCore

/// A DNS message header (RFC 1035 §4.1.1). Flag bits mirror the Go `MsgHdr`.
public struct MsgHeader: Sendable, Equatable {
    public var id: UInt16
    public var response: Bool            // QR
    public var opcode: Int               // 0...15
    public var authoritative: Bool       // AA
    public var truncated: Bool           // TC
    public var recursionDesired: Bool    // RD
    public var recursionAvailable: Bool  // RA
    public var zero: Bool                // Z
    public var authenticatedData: Bool   // AD
    public var checkingDisabled: Bool    // CD
    public var rcode: Int                // base 4-bit rcode

    public init(id: UInt16 = 0, response: Bool = false, opcode: Int = 0,
                authoritative: Bool = false, truncated: Bool = false,
                recursionDesired: Bool = false, recursionAvailable: Bool = false,
                zero: Bool = false, authenticatedData: Bool = false,
                checkingDisabled: Bool = false, rcode: Int = 0) {
        self.id = id; self.response = response; self.opcode = opcode
        self.authoritative = authoritative; self.truncated = truncated
        self.recursionDesired = recursionDesired; self.recursionAvailable = recursionAvailable
        self.zero = zero; self.authenticatedData = authenticatedData
        self.checkingDisabled = checkingDisabled; self.rcode = rcode
    }

    /// The 16-bit flags field (second word of the header).
    public var bits: UInt16 {
        get {
            var b: UInt16 = 0
            if response { b |= 1 << 15 }
            b |= (UInt16(opcode) & 0xF) << 11
            if authoritative { b |= 1 << 10 }
            if truncated { b |= 1 << 9 }
            if recursionDesired { b |= 1 << 8 }
            if recursionAvailable { b |= 1 << 7 }
            if zero { b |= 1 << 6 }
            if authenticatedData { b |= 1 << 5 }
            if checkingDisabled { b |= 1 << 4 }
            b |= UInt16(rcode) & 0xF
            return b
        }
        set {
            response = newValue & (1 << 15) != 0
            opcode = Int((newValue >> 11) & 0xF)
            authoritative = newValue & (1 << 10) != 0
            truncated = newValue & (1 << 9) != 0
            recursionDesired = newValue & (1 << 8) != 0
            recursionAvailable = newValue & (1 << 7) != 0
            zero = newValue & (1 << 6) != 0
            authenticatedData = newValue & (1 << 5) != 0
            checkingDisabled = newValue & (1 << 4) != 0
            rcode = Int(newValue & 0xF)
        }
    }
}

/// A question-section entry (RFC 1035 §4.1.2).
public struct Question: Sendable, Equatable {
    public var name: Name
    public var qtype: RRType
    public var qclass: RRClass

    public init(_ name: Name, _ qtype: RRType, _ qclass: RRClass = .in) {
        self.name = name; self.qtype = qtype; self.qclass = qclass
    }

    func pack(into buf: inout MessagePacker) throws {
        try buf.appendName(name, compress: true)
        buf.appendUInt16(qtype.rawValue)
        buf.appendUInt16(qclass.rawValue)
    }

    init(from buf: inout MessageUnpacker) throws {
        name = try buf.readName()
        qtype = RRType(rawValue: try buf.readUInt16())
        qclass = RRClass(rawValue: try buf.readUInt16())
    }
}

/// A complete DNS message.
public struct Msg: Sendable {
    public var header: MsgHeader
    public var questions: [Question]
    public var answers: [any RR]
    public var authorities: [any RR]
    public var additionals: [any RR]

    public init(header: MsgHeader = MsgHeader(),
                questions: [Question] = [], answers: [any RR] = [],
                authorities: [any RR] = [], additionals: [any RR] = []) {
        self.header = header
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additionals = additionals
    }

    /// Serializes the message to wire format. Names are compressed unless
    /// `compress` is false.
    public func pack(compress: Bool = true) throws -> [UInt8] {
        var buf = MessagePacker(compressionEnabled: compress)
        buf.appendUInt16(header.id)
        buf.appendUInt16(header.bits)
        buf.appendUInt16(UInt16(questions.count))
        buf.appendUInt16(UInt16(answers.count))
        buf.appendUInt16(UInt16(authorities.count))
        buf.appendUInt16(UInt16(additionals.count))
        for q in questions { try q.pack(into: &buf) }
        for rr in answers { try rr.pack(into: &buf) }
        for rr in authorities { try rr.pack(into: &buf) }
        for rr in additionals { try rr.pack(into: &buf) }
        return buf.bytes
    }

    /// Builds a response skeleton for this query: same id/opcode/question, with
    /// the QR (response) bit set and the answer sections empty.
    public func makeReply() -> Msg {
        var h = header
        h.response = true
        h.authoritative = false
        h.truncated = false
        return Msg(header: h, questions: questions)
    }

    /// Parses a message from wire format.
    public init(unpacking bytes: [UInt8]) throws {
        var u = MessageUnpacker(bytes)
        let id = try u.readUInt16()
        let bits = try u.readUInt16()
        let qd = Int(try u.readUInt16())
        let an = Int(try u.readUInt16())
        let ns = Int(try u.readUInt16())
        let ar = Int(try u.readUInt16())

        var hdr = MsgHeader(id: id)
        hdr.bits = bits
        self.header = hdr

        self.questions = try (0..<qd).map { _ in try Question(from: &u) }
        self.answers = try (0..<an).map { _ in try unpackRR(from: &u) }
        self.authorities = try (0..<ns).map { _ in try unpackRR(from: &u) }
        self.additionals = try (0..<ar).map { _ in try unpackRR(from: &u) }
    }
}
