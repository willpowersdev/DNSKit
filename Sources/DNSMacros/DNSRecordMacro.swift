import SwiftSyntax
import SwiftSyntaxMacros
import SwiftCompilerPlugin

private struct MacroError: Error, CustomStringConvertible {
    let description: String
    init(_ m: String) { description = m }
}

/// A parsed rdata field: its property name, Swift type, and the wire-kind
/// markers that disambiguate encodings the Swift type alone cannot (the analog
/// of Go's `dns:"..."` struct tags).
private struct Field {
    let name: String
    let type: String
    var compressed = false          // @Compressed: cdomain-name
    var octet = false               // @Octet: rest-of-rdata as a raw string
    var uint48 = false              // @UInt48: 6-octet integer
    var sizeField: String? = nil    // @SizePrefixed("lenField"): byte count from another field
}

/// `@DNSRecord` — generates the wire codec (`packRdata` + `init(header:rdata:)`)
/// and a memberwise initializer for a resource-record struct, from its stored
/// properties. This replaces the hand-generated `zmsg.go` in the Go library.
public struct DNSRecordMacro: MemberMacro {
    public static func expansion(
        of node: AttributeSyntax,
        providingMembersOf declaration: some DeclGroupSyntax,
        in context: some MacroExpansionContext
    ) throws -> [DeclSyntax] {
        guard let structDecl = declaration.as(StructDeclSyntax.self) else {
            throw MacroError("@DNSRecord can only be applied to a struct")
        }

        var fields: [Field] = []
        for member in structDecl.memberBlock.members {
            guard let varDecl = member.decl.as(VariableDeclSyntax.self) else { continue }
            var compressed = false, octet = false, uint48 = false
            var sizeField: String? = nil
            for element in varDecl.attributes {
                guard let attr = element.as(AttributeSyntax.self),
                      let id = attr.attributeName.as(IdentifierTypeSyntax.self)?.name.text else { continue }
                switch id {
                case "Compressed": compressed = true
                case "Octet": octet = true
                case "UInt48": uint48 = true
                case "SizePrefixed":
                    if let args = attr.arguments?.as(LabeledExprListSyntax.self),
                       let lit = args.first?.expression.as(StringLiteralExprSyntax.self) {
                        sizeField = lit.segments.description
                    }
                default: break
                }
            }
            for binding in varDecl.bindings {
                guard binding.accessorBlock == nil,
                      let pat = binding.pattern.as(IdentifierPatternSyntax.self),
                      let type = binding.typeAnnotation?.type else { continue }
                fields.append(Field(name: pat.identifier.text, type: type.trimmedDescription,
                                    compressed: compressed, octet: octet,
                                    uint48: uint48, sizeField: sizeField))
            }
        }

        let rdataFields = fields.filter { $0.name != "header" }

        // Memberwise initializer (the compiler no longer synthesizes one once we
        // add init(header:rdata:), so we provide it explicitly).
        let initParams = fields.map { "\($0.name): \($0.type)" }.joined(separator: ", ")
        let initBody = fields.map { "self.\($0.name) = \($0.name)" }.joined(separator: "\n        ")
        let memberwiseInit: DeclSyntax = """
        public init(\(raw: initParams)) {
            \(raw: initBody)
        }
        """

        // packRdata
        let packStmts = try rdataFields.map { try packStatement($0) }.joined(separator: "\n        ")
        let packRdata: DeclSyntax = """
        public func packRdata(into buf: inout MessagePacker) throws {
            \(raw: packStmts.isEmpty ? "// no rdata" : packStmts)
        }
        """

        // init(header:rdata:)
        let readStmts = try rdataFields.map { try readStatement($0) }.joined(separator: "\n        ")
        let rdataInit: DeclSyntax = """
        public init(header: RRHeader, rdata buf: inout MessageUnpacker) throws {
            let _rdstart = buf.offset
            _ = _rdstart
            \(raw: readStmts.isEmpty ? "// no rdata" : readStmts)
            self.header = header
        }
        """

        return [memberwiseInit, packRdata, rdataInit]
    }

    private static func packStatement(_ f: Field) throws -> String {
        switch f.type {
        case "UInt8":  return "buf.appendUInt8(self.\(f.name))"
        case "UInt16": return "buf.appendUInt16(self.\(f.name))"
        case "UInt32": return "buf.appendUInt32(self.\(f.name))"
        case "UInt64": return f.uint48 ? "buf.appendUInt48(self.\(f.name))"
                                       : "buf.appendUInt64(self.\(f.name))"
        case "Name":   return "try buf.appendName(self.\(f.name), compress: \(f.compressed))"
        case "[Name]": return "for _n in self.\(f.name) { try buf.appendName(_n, compress: false) }"
        case "IPv4Address", "IPv6Address": return "buf.appendBytes(self.\(f.name).bytes)"
        case "String":
            return f.octet ? "buf.appendBytes(Array(self.\(f.name).utf8))"
                           : "try buf.appendCharacterString(self.\(f.name))"
        case "[String]": return "for _s in self.\(f.name) { try buf.appendCharacterString(_s) }"
        case "[UInt8]":  return "buf.appendBytes(self.\(f.name))" // opaque or size-prefixed: raw bytes
        case "[UInt16]": return "buf.appendNSECBitmap(self.\(f.name))"
        default: throw MacroError("@DNSRecord: unsupported field type '\(f.type)' for '\(f.name)'")
        }
    }

    /// Expression for "octets of rdata remaining after the fields read so far".
    private static let restLen = "(Int(header.rdlength) - (buf.offset - _rdstart))"

    private static func readStatement(_ f: Field) throws -> String {
        switch f.type {
        case "UInt8":  return "self.\(f.name) = try buf.readUInt8()"
        case "UInt16": return "self.\(f.name) = try buf.readUInt16()"
        case "UInt32": return "self.\(f.name) = try buf.readUInt32()"
        case "UInt64": return f.uint48 ? "self.\(f.name) = try buf.readUInt48()"
                                       : "self.\(f.name) = try buf.readUInt64()"
        case "Name":   return "self.\(f.name) = try buf.readName()"
        case "[Name]":
            return """
            do { var _a = [Name](); while \(restLen) > 0 { _a.append(try buf.readName()) }; self.\(f.name) = _a }
            """
        case "IPv4Address": return "self.\(f.name) = IPv4Address(bytes: try buf.readBytes(4))"
        case "IPv6Address": return "self.\(f.name) = IPv6Address(bytes: try buf.readBytes(16))"
        case "String":
            return f.octet
                ? "self.\(f.name) = String(decoding: try buf.readBytes(\(restLen)), as: UTF8.self)"
                : "self.\(f.name) = try buf.readCharacterString()"
        case "[String]":
            return """
            do { var _arr = [String](); while \(restLen) > 0 { _arr.append(try buf.readCharacterString()) }; self.\(f.name) = _arr }
            """
        case "[UInt8]":
            if let lenField = f.sizeField {
                return "self.\(f.name) = try buf.readBytes(Int(self.\(lenField)))"
            }
            return "self.\(f.name) = try buf.readBytes(\(restLen))"
        case "[UInt16]":
            return "self.\(f.name) = try buf.readNSECBitmap(byteCount: \(restLen))"
        default: throw MacroError("@DNSRecord: unsupported field type '\(f.type)' for '\(f.name)'")
        }
    }
}

/// Backs the wire-kind marker attributes (`@Compressed`, `@Octet`, `@UInt48`,
/// `@SizePrefixed`). Each expands to nothing; the markers exist only so
/// `@DNSRecord` can read them off a property (the analog of Go's struct tags).
public struct MarkerMacro: PeerMacro {
    public static func expansion(
        of node: AttributeSyntax,
        providingPeersOf declaration: some DeclSyntaxProtocol,
        in context: some MacroExpansionContext
    ) throws -> [DeclSyntax] { [] }
}

@main
struct DNSMacrosPlugin: CompilerPlugin {
    let providingMacros: [Macro.Type] = [DNSRecordMacro.self, MarkerMacro.self]
}
