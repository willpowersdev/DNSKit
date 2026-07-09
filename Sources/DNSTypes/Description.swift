import DNSCore

// Human-readable descriptions (dig-style) for common ergonomics.

extension RRType: CustomStringConvertible {
    public var description: String { RRType.mnemonic(self) }
}

extension RRClass: CustomStringConvertible {
    public var description: String { RRClass.mnemonic(self) }
}

extension Question: CustomStringConvertible {
    public var description: String { ";\(name.value)\t\(qclass)\t\(qtype)" }
}

extension Msg: CustomStringConvertible {
    public var description: String {
        var s = ";; ->>HEADER<<- opcode: \(header.opcode), rcode: \(header.rcode), id: \(header.id)\n"
        s += ";; flags:"
        if header.response { s += " qr" }
        if header.authoritative { s += " aa" }
        if header.truncated { s += " tc" }
        if header.recursionDesired { s += " rd" }
        if header.recursionAvailable { s += " ra" }
        s += "; QUERY: \(questions.count), ANSWER: \(answers.count), "
        s += "AUTHORITY: \(authorities.count), ADDITIONAL: \(additionals.count)\n"

        if !questions.isEmpty {
            s += "\n;; QUESTION SECTION:\n"
            for q in questions { s += "\(q)\n" }
        }
        func section(_ title: String, _ rrs: [any RR]) {
            guard !rrs.isEmpty else { return }
            s += "\n;; \(title):\n"
            for rr in rrs {
                s += ((try? rr.present()) ?? "\(rr.header.name.value)\t\(rr.header.ttl)\t\(rr.header.class)\t\(rr.header.type)\t<unprintable>") + "\n"
            }
        }
        section("ANSWER SECTION", answers)
        section("AUTHORITY SECTION", authorities)
        section("ADDITIONAL SECTION", additionals)
        return s
    }
}
