import DNSCore
import DNSTypes
import NIOCore
import NIOConcurrencyHelpers

/// Handles a DNS request and returns the response to send, or `nil` to stay
/// silent (drop the request). The Swift-idiomatic analog of Go's `Handler` +
/// `ResponseWriter`.
public protocol DNSResponder: Sendable {
    func respond(to request: Msg, from client: SocketAddress) async -> Msg?
}

/// Closure-based responder adapter (analog of Go's `HandlerFunc`).
public struct HandlerFunc: DNSResponder {
    private let fn: @Sendable (Msg, SocketAddress) async -> Msg?
    public init(_ fn: @escaping @Sendable (Msg, SocketAddress) async -> Msg?) { self.fn = fn }
    public func respond(to request: Msg, from client: SocketAddress) async -> Msg? {
        await fn(request, client)
    }
}

/// Routes requests to responders by the query name, choosing the registered
/// zone that is the longest label-suffix of the name (root `.` matches all).
/// Unmatched queries get a REFUSED reply.
public final class ServeMux: DNSResponder {
    private struct Route { let labels: [[UInt8]]; let handler: any DNSResponder }
    private let routes = NIOLockedValueBox<[Route]>([])

    public init() {}

    /// Registers a handler for a zone (and everything under it).
    public func register(_ zone: Name, _ handler: any DNSResponder) {
        let labels = (try? zone.fqdn.labels().map { $0.map { lowercase($0) } }) ?? []
        routes.withLockedValue { $0.append(Route(labels: labels, handler: handler)) }
    }

    public func respond(to request: Msg, from client: SocketAddress) async -> Msg? {
        guard let question = request.questions.first else { return nil }
        let nameLabels = (try? question.name.fqdn.labels().map { $0.map { lowercase($0) } }) ?? []

        let handler = routes.withLockedValue { list -> (any DNSResponder)? in
            var best: (depth: Int, handler: any DNSResponder)? = nil
            for route in list where isSuffix(route.labels, of: nameLabels) {
                if best == nil || route.labels.count > best!.depth {
                    best = (route.labels.count, route.handler)
                }
            }
            return best?.handler
        }

        guard let handler else {
            var reply = request.makeReply()
            reply.header.rcode = 5 // REFUSED
            return reply
        }
        return await handler.respond(to: request, from: client)
    }

    /// True if `zone` is a label-suffix of `name` (root, zero labels, matches all).
    private func isSuffix(_ zone: [[UInt8]], of name: [[UInt8]]) -> Bool {
        guard zone.count <= name.count else { return false }
        let tail = name.suffix(zone.count)
        return Array(tail) == zone
    }

    private func lowercase(_ b: UInt8) -> UInt8 {
        (b >= 65 && b <= 90) ? b + 32 : b
    }
}
