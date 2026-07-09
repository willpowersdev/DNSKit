import Foundation
import DNSCore

/// Parsed `resolv.conf` configuration (RFC-style), mirroring the fields the Go
/// library's `clientconfig.go` exposes.
public struct ClientConfig: Sendable, Equatable {
    public var nameservers: [String]
    public var search: [String]
    public var port: Int
    public var ndots: Int
    public var timeoutSeconds: Int
    public var attempts: Int

    public init(nameservers: [String] = [], search: [String] = [], port: Int = 53,
                ndots: Int = 1, timeoutSeconds: Int = 5, attempts: Int = 2) {
        self.nameservers = nameservers
        self.search = search
        self.port = port
        self.ndots = ndots
        self.timeoutSeconds = timeoutSeconds
        self.attempts = attempts
    }

    /// Parses the textual contents of a resolv.conf file.
    public init(parsing text: String) {
        self.init()
        for rawLine in text.split(whereSeparator: \.isNewline) {
            // Strip comments (# or ;) and surrounding whitespace.
            var line = Substring(rawLine)
            if let hash = line.firstIndex(where: { $0 == "#" || $0 == ";" }) {
                line = line[..<hash]
            }
            let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let keyword = fields.first else { continue }
            let args = Array(fields.dropFirst())
            switch keyword {
            case "nameserver":
                if let ns = args.first { nameservers.append(ns) }
            case "domain":
                if let d = args.first { search = [d] }
            case "search":
                search = args
            case "options":
                for opt in args {
                    if let v = Self.optionValue(opt, "ndots:") { ndots = v }
                    else if let v = Self.optionValue(opt, "timeout:") { timeoutSeconds = v }
                    else if let v = Self.optionValue(opt, "attempts:") { attempts = v }
                }
            default:
                break
            }
        }
    }

    private static func optionValue(_ opt: String, _ prefix: String) -> Int? {
        guard opt.hasPrefix(prefix) else { return nil }
        return Int(opt.dropFirst(prefix.count))
    }

    /// Loads a resolv.conf-style file, returning nil if it can't be read.
    public static func fromSystem(path: String = "/etc/resolv.conf") -> ClientConfig? {
        try? load(fromPath: path)
    }

    /// Loads the host's default resolver configuration.
    ///
    /// This is the one place that touches OS-specific facilities, so it is gated
    /// by platform. On platforms without a resolver file it throws
    /// ``DNSError/unsupportedPlatform``; everything else in the package is
    /// platform-neutral.
    public static func systemDefault() throws -> ClientConfig {
        #if os(macOS) || os(iOS)
        // Apple platforms: /etc/resolv.conf is present on macOS; on sandboxed
        // iOS it may be unreadable, which surfaces as a thrown error.
        return try load(fromPath: "/etc/resolv.conf")
        #elseif os(Linux)
        // Linux: /etc/resolv.conf is the canonical resolver configuration.
        return try load(fromPath: "/etc/resolv.conf")
        #else
        throw DNSError.unsupportedPlatform
        #endif
    }

    private static func load(fromPath path: String) throws -> ClientConfig {
        ClientConfig(parsing: try String(contentsOfFile: path, encoding: .utf8))
    }
}
