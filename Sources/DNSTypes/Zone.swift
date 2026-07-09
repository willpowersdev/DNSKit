import Foundation
import DNSCore

// Presentation (zone-file) format: a lexer for a single RR line, helpers used
// by the macro-generated render/parse code, and NewRR for building a record
// from its textual form. Full zone-file directives ($ORIGIN/$TTL/$INCLUDE/
// $GENERATE, multi-line records) are a later increment.

// MARK: Helpers referenced by macro-generated code

/// Qualifies a presentation name against an origin (append origin if relative).
func dnsQualify(_ token: String, origin: String) -> Name {
    if token == "@" { return Name(origin.isEmpty ? "." : origin) }
    if token.hasSuffix(".") { return Name(token) }        // already absolute
    if origin == "." || origin.isEmpty { return Name(token + ".") }
    return Name(token + "." + origin)
}

/// Renders a character-string in double quotes with minimal escaping.
func dnsQuoteString(_ s: String) -> String {
    var out = "\""
    for ch in s {
        if ch == "\"" || ch == "\\" { out.append("\\") }
        out.append(ch)
    }
    out.append("\"")
    return out
}

func dnsRenderHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func dnsParseHex(_ s: String) throws -> [UInt8] {
    let chars = Array(s)
    guard chars.count % 2 == 0 else { throw WireError.malformedText("odd-length hex") }
    var out: [UInt8] = []
    out.reserveCapacity(chars.count / 2)
    var i = 0
    while i < chars.count {
        guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else {
            throw WireError.malformedText("bad hex digit")
        }
        out.append(UInt8(hi << 4 | lo)); i += 2
    }
    return out
}

func dnsRenderBase64(_ bytes: [UInt8]) -> String {
    Data(bytes).base64EncodedString()
}

func dnsParseBase64(_ s: String) throws -> [UInt8] {
    guard let data = Data(base64Encoded: s) else { throw WireError.malformedText("bad base64") }
    return Array(data)
}

// MARK: Lexer

/// Splits a presentation-format line into tokens: whitespace-separated, with
/// double-quoted strings kept whole, `;` comments stripped, `()` continuation
/// characters ignored, and backslash escapes decoded.
public func lexPresentationLine(_ line: String) -> [String] {
    var tokens: [String] = []
    var current = ""
    var inToken = false
    var inQuote = false
    var chars = Array(line)
    var i = 0
    func flush() { if inToken { tokens.append(current); current = ""; inToken = false } }

    while i < chars.count {
        let c = chars[i]
        if inQuote {
            if c == "\\", i + 1 < chars.count {
                current.append(chars[i + 1]); i += 2; continue
            }
            if c == "\"" { inQuote = false; i += 1; continue }
            current.append(c); i += 1; continue
        }
        switch c {
        case "\"":
            inToken = true; inQuote = true; i += 1
        case ";":
            i = chars.count // comment to end of line
        case " ", "\t", "\r", "\n":
            flush(); i += 1
        case "(", ")":
            flush(); i += 1 // continuation markers: treat as whitespace
        case "\\":
            inToken = true
            if i + 1 < chars.count { current.append(chars[i + 1]); i += 2 } else { i += 1 }
        default:
            inToken = true; current.append(c); i += 1
        }
    }
    flush()
    return tokens
}

// MARK: NewRR

public enum ZoneError: Error, Sendable {
    case empty
    case missingType
    case unknownType(String)
    case unsupportedType(String)
}

/// Maps a type code to a closure that builds the record from rdata tokens.
enum PresentationRegistry {
    typealias Parser = @Sendable (RRHeader, [String], String) throws -> any RR
    static let byType: [UInt16: Parser] = {
        func p<T: RR>(_ t: T.Type) -> Parser { { h, toks, o in try T(header: h, rdataTokens: toks, origin: o) } }
        return [
            RRType.a.rawValue: p(A.self), RRType.aaaa.rawValue: p(AAAA.self),
            RRType.ns.rawValue: p(NS.self), RRType.cname.rawValue: p(CNAME.self),
            RRType.dname.rawValue: p(DNAME.self), RRType.ptr.rawValue: p(PTR.self),
            RRType.mx.rawValue: p(MX.self), RRType.txt.rawValue: p(TXT.self),
            RRType.spf.rawValue: p(SPF.self), RRType.soa.rawValue: p(SOA.self),
            RRType.srv.rawValue: p(SRV.self), RRType.naptr.rawValue: p(NAPTR.self),
            RRType.caa.rawValue: p(CAA.self), RRType.uri.rawValue: p(URI.self),
            RRType.ds.rawValue: p(DS.self), RRType.cds.rawValue: p(CDS.self),
            RRType.dlv.rawValue: p(DLV.self), RRType.dnskey.rawValue: p(DNSKEY.self),
            RRType.cdnskey.rawValue: p(CDNSKEY.self), RRType.key.rawValue: p(KEY.self),
            RRType.rrsig.rawValue: p(RRSIG.self), RRType.tlsa.rawValue: p(TLSA.self),
            RRType.smimea.rawValue: p(SMIMEA.self), RRType.sshfp.rawValue: p(SSHFP.self),
            RRType.cert.rawValue: p(CERT.self), RRType.kx.rawValue: p(KX.self),
            RRType.rp.rawValue: p(RP.self), RRType.hinfo.rawValue: p(HINFO.self),
            RRType.afsdb.rawValue: p(AFSDB.self), RRType.dhcid.rawValue: p(DHCID.self),
            RRType.openpgpkey.rawValue: p(OPENPGPKEY.self),
            RRType.nsec.rawValue: p(NSEC.self), RRType.csync.rawValue: p(CSYNC.self),
            RRType.nxt.rawValue: p(NXT.self),
            RRType.svcb.rawValue: p(SVCB.self), RRType.https.rawValue: p(HTTPS.self),
        ]
    }()
}

/// Parses a single resource record from presentation format, e.g.
/// `NewRR("example.com. 3600 IN MX 10 mail.example.com.")`.
///
/// Grammar: `<name> [TTL] [CLASS] <TYPE> <rdata...>`. TTL and CLASS are optional
/// and may appear in either order. `origin` qualifies relative names and `@`.
public func NewRR(_ text: String, origin: String = ".", defaultTTL: UInt32 = 3600) throws -> any RR {
    try newRR(tokens: lexPresentationLine(text), origin: origin, defaultTTL: defaultTTL)
}

/// Builds a record from already-lexed tokens (owner first).
func newRR(tokens: [String], origin: String, defaultTTL: UInt32) throws -> any RR {
    guard let owner = tokens.first else { throw ZoneError.empty }
    var idx = 1

    var ttl = defaultTTL
    var cls = RRClass.in
    var type: RRType? = nil

    // TTL and CLASS are optional and order-independent; the first token that is
    // a known type mnemonic ends the prelude.
    while idx < tokens.count {
        let tok = tokens[idx]
        if let t = RRType.fromMnemonic(tok) { type = t; idx += 1; break }
        if let n = UInt32(tok) { ttl = n; idx += 1; continue }
        if let c = RRClass.fromMnemonic(tok) { cls = c; idx += 1; continue }
        throw ZoneError.unknownType(tok)
    }
    guard let type else { throw ZoneError.missingType }

    let header = RRHeader(name: dnsQualify(owner, origin: origin), type: type, class: cls, ttl: ttl)
    let rdata = Array(tokens[idx...])

    guard let parser = PresentationRegistry.byType[type.rawValue] else {
        throw ZoneError.unsupportedType(RRType.mnemonic(type))
    }
    return try parser(header, rdata, origin)
}

/// Parses a zone file into resource records. Supports multi-line records via
/// parentheses, `$ORIGIN` and `$TTL` directives, blank-owner inheritance, and
/// comments. (`$INCLUDE`/`$GENERATE` are not yet handled and are skipped.)
public func parseZone(_ text: String, origin: String = ".", defaultTTL: UInt32 = 3600) throws -> [any RR] {
    var currentOrigin = origin
    var currentTTL = defaultTTL
    var lastOwner: String? = nil
    var records: [any RR] = []

    for (line, ownerOmitted) in logicalLines(text) {
        var tokens = lexPresentationLine(line)
        guard let first = tokens.first else { continue }

        if first.hasPrefix("$") {
            switch first.uppercased() {
            case "$ORIGIN":
                if tokens.count > 1 { currentOrigin = tokens[1].hasSuffix(".") ? tokens[1] : tokens[1] + "." }
            case "$TTL":
                if tokens.count > 1, let ttl = UInt32(tokens[1]) { currentTTL = ttl }
            default:
                break // $INCLUDE / $GENERATE not yet supported
            }
            continue
        }

        if ownerOmitted {
            guard let owner = lastOwner else { throw ZoneError.empty }
            tokens.insert(owner, at: 0)
        }
        lastOwner = tokens[0]
        records.append(try newRR(tokens: tokens, origin: currentOrigin, defaultTTL: currentTTL))
    }
    return records
}

/// Groups physical lines into logical records, joining lines inside unclosed
/// parentheses. Returns each logical line with whether its owner was omitted
/// (i.e. the first physical line began with whitespace).
private func logicalLines(_ text: String) -> [(line: String, ownerOmitted: Bool)] {
    var result: [(String, Bool)] = []
    var depth = 0
    var buffer = ""
    var ownerOmitted = false

    for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
        let line = String(rawLine)
        // Comments end at the physical newline, so strip them before joining
        // continuation lines (otherwise an inline comment would swallow the
        // rest of a multi-line record).
        let cleaned = stripComment(line)
        if depth == 0 {
            buffer = cleaned
            ownerOmitted = line.first.map { $0 == " " || $0 == "\t" } ?? false
        } else {
            buffer += " " + cleaned
        }
        depth += parenDelta(line)
        if depth <= 0 {
            depth = 0
            if !lexPresentationLine(buffer).isEmpty { result.append((buffer, ownerOmitted)) }
            buffer = ""
        }
    }
    if !buffer.isEmpty, !lexPresentationLine(buffer).isEmpty { result.append((buffer, ownerOmitted)) }
    return result
}

/// Removes an unquoted `;` comment from a physical line.
private func stripComment(_ line: String) -> String {
    var inQuote = false
    var i = line.startIndex
    while i < line.endIndex {
        let c = line[i]
        if inQuote {
            if c == "\\" { i = line.index(after: i); if i >= line.endIndex { break } }
            else if c == "\"" { inQuote = false }
        } else if c == "\"" {
            inQuote = true
        } else if c == ";" {
            return String(line[line.startIndex..<i])
        }
        i = line.index(after: i)
    }
    return line
}

/// Net parenthesis nesting change on a line, ignoring quotes and comments.
private func parenDelta(_ line: String) -> Int {
    var depth = 0
    var inQuote = false
    var i = line.startIndex
    while i < line.endIndex {
        let c = line[i]
        if inQuote {
            if c == "\\" { i = line.index(after: i) }
            else if c == "\"" { inQuote = false }
        } else {
            switch c {
            case "\"": inQuote = true
            case ";": return depth // comment to end of line
            case "(": depth += 1
            case ")": depth -= 1
            default: break
            }
        }
        if i < line.endIndex { i = line.index(after: i) }
    }
    return depth
}
