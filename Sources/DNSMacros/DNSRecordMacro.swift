import SwiftSyntax
import SwiftSyntaxMacros
import SwiftCompilerPlugin

private struct MacroError: Error, CustomStringConvertible {
    let description: String
    init(_ m: String) { description = m }
}

/// A parsed rdata field: its property name, Swift type, and whether it carries
/// the `@Compressed` marker (the analog of Go's `cdomain-name` struct tag).
private struct Field {
    let name: String
    let type: String
    let compressed: Bool
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
            let compressed = varDecl.attributes.contains { element in
                element.as(AttributeSyntax.self)?
                    .attributeName.as(IdentifierTypeSyntax.self)?.name.text == "Compressed"
            }
            for binding in varDecl.bindings {
                guard binding.accessorBlock == nil,
                      let pat = binding.pattern.as(IdentifierPatternSyntax.self),
                      let type = binding.typeAnnotation?.type else { continue }
                fields.append(Field(name: pat.identifier.text,
                                    type: type.trimmedDescription,
                                    compressed: compressed))
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
        case "Name":   return "try buf.appendName(self.\(f.name), compress: \(f.compressed))"
        case "IPv4Address", "IPv6Address": return "buf.appendBytes(self.\(f.name).bytes)"
        case "String": return "try buf.appendCharacterString(self.\(f.name))"
        case "[String]": return "for _s in self.\(f.name) { try buf.appendCharacterString(_s) }"
        default: throw MacroError("@DNSRecord: unsupported field type '\(f.type)' for '\(f.name)'")
        }
    }

    private static func readStatement(_ f: Field) throws -> String {
        switch f.type {
        case "UInt8":  return "self.\(f.name) = try buf.readUInt8()"
        case "UInt16": return "self.\(f.name) = try buf.readUInt16()"
        case "UInt32": return "self.\(f.name) = try buf.readUInt32()"
        case "Name":   return "self.\(f.name) = try buf.readName()"
        case "IPv4Address": return "self.\(f.name) = IPv4Address(bytes: try buf.readBytes(4))"
        case "IPv6Address": return "self.\(f.name) = IPv6Address(bytes: try buf.readBytes(16))"
        case "String": return "self.\(f.name) = try buf.readCharacterString()"
        case "[String]":
            return """
            var _arr = [String]()
            while buf.offset - _rdstart < Int(header.rdlength) { _arr.append(try buf.readCharacterString()) }
            self.\(f.name) = _arr
            """
        default: throw MacroError("@DNSRecord: unsupported field type '\(f.type)' for '\(f.name)'")
        }
    }
}

/// `@Compressed` — a marker on a `Name` field indicating it may be compressed
/// (the analog of Go's `cdomain-name` tag). Expands to nothing; it exists so
/// `@DNSRecord` can read it off the property.
public struct CompressedMacro: PeerMacro {
    public static func expansion(
        of node: AttributeSyntax,
        providingPeersOf declaration: some DeclSyntaxProtocol,
        in context: some MacroExpansionContext
    ) throws -> [DeclSyntax] { [] }
}

@main
struct DNSMacrosPlugin: CompilerPlugin {
    let providingMacros: [Macro.Type] = [DNSRecordMacro.self, CompressedMacro.self]
}
