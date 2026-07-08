import Foundation

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

    /// Loads `/etc/resolv.conf` (or another path). Returns nil if unreadable.
    public static func fromSystem(path: String = "/etc/resolv.conf") -> ClientConfig? {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        return ClientConfig(parsing: text)
    }
}
