import DNSCore
import DNSTypes
import NIOCore
import NIOPosix
import NIOConcurrencyHelpers
import NIOSSL

public enum DNSClientError: Error, Sendable, Equatable {
    case timeout
    case idMismatch(sent: UInt16, received: UInt16)
    case emptyResponse
    case noNameservers
    case connectionClosed
}

/// How a query is carried to the server.
public enum DNSTransport: Sendable, Equatable {
    /// Plain UDP (default). Falls back to TCP when the reply is truncated.
    case udp
    /// Plain TCP.
    case tcp
    /// DNS-over-TLS (RFC 7858): TCP wrapped in TLS, default port 853.
    case tls

    /// The IANA-assigned default port for this transport (53, or 853 for TLS).
    public var defaultPort: Int { self == .tls ? 853 : 53 }
    var streamed: Bool { self != .udp }
}

/// An asynchronous DNS resolver over UDP, TCP, and TLS (DoT), built on SwiftNIO.
///
/// `query`/`exchange` are one-shot: they open a connection, exchange one
/// message, and close it — mirroring the Go library's `Client.Exchange`. To
/// avoid a fresh connection (and, for TLS, a fresh handshake) per query, open a
/// persistent ``DNSConnection`` with ``connect(to:port:transport:serverName:timeout:)``
/// and reuse it — the analog of the Go library's `Conn`.
public final class DNSClient: Sendable {
    private let group: EventLoopGroup
    private let ownsGroup: Bool
    private let tlsConfiguration: TLSConfiguration
    private let tlsContext = NIOLockedValueBox<NIOSSLContext?>(nil)

    /// Creates a client. Provide a `tlsConfiguration` to customize DoT
    /// certificate verification (the default verifies against the system trust
    /// store); pass your own `group` to share an event loop.
    public init(group: EventLoopGroup? = nil,
                tlsConfiguration: TLSConfiguration = .makeClientConfiguration()) {
        if let group {
            self.group = group
            self.ownsGroup = false
        } else {
            self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            self.ownsGroup = true
        }
        self.tlsConfiguration = tlsConfiguration
    }

    /// Lazily builds and caches the TLS context (parsing the trust store once).
    private func sslContext() throws -> NIOSSLContext {
        try tlsContext.withLockedValue { cached in
            if let cached { return cached }
            let context = try NIOSSLContext(configuration: tlsConfiguration)
            cached = context
            return context
        }
    }

    /// Shuts down the owned event-loop group. No-op if a group was injected.
    public func shutdown() async throws {
        if ownsGroup { try await group.shutdownGracefully() }
    }

    // MARK: One-shot API (opens and closes a connection per call)

    /// Builds a recursive query for `name`/`type` and exchanges it with `server`.
    /// For `.tls`, `serverName` is the hostname the certificate is verified
    /// against (defaults to `server`); pass it when connecting by IP.
    public func query(_ name: String, _ type: RRType, server: String, port: Int? = nil,
                      transport: DNSTransport = .udp, serverName: String? = nil,
                      dnssecOK: Bool = false, timeout: TimeAmount = .seconds(5)) async throws -> Msg {
        var header = MsgHeader(id: UInt16.random(in: 0...UInt16.max))
        header.recursionDesired = true
        var msg = Msg(header: header, questions: [Question(Name(name).fqdn, type)])
        if dnssecOK {
            msg.additionals = [OPT(udpSize: 1232, dnssecOK: true)]
        }
        return try await exchange(msg, server: server, port: port, transport: transport,
                                  serverName: serverName, timeout: timeout)
    }

    /// Exchanges a fully-formed message with a server over a freshly-opened
    /// connection, retrying over TCP if a UDP reply is truncated. Equivalent to
    /// `connect(...)`, one `exchange`, then `close` — for repeated queries,
    /// keep a ``DNSConnection`` instead.
    public func exchange(_ msg: Msg, server: String, port: Int? = nil,
                        transport: DNSTransport = .udp, serverName: String? = nil,
                        timeout: TimeAmount = .seconds(5)) async throws -> Msg {
        let connection = try await connect(to: server, port: port, transport: transport,
                                           serverName: serverName, timeout: timeout)
        var reply: Msg
        do {
            reply = try await connection.exchange(msg, timeout: timeout)
        } catch {
            await connection.close()
            throw error
        }
        await connection.close()

        // Truncated UDP reply -> retry over TCP (same host, port 53).
        if transport == .udp && reply.header.truncated {
            let tcp = try await connect(to: server, port: port ?? 53, transport: .tcp,
                                        serverName: serverName, timeout: timeout)
            do {
                reply = try await tcp.exchange(msg, timeout: timeout)
            } catch {
                await tcp.close()
                throw error
            }
            await tcp.close()
        }
        return reply
    }

    // MARK: Persistent connections

    /// Opens a persistent connection for reuse across many queries. TLS/TCP
    /// handshakes happen once, here, rather than on every exchange. The caller
    /// owns the connection and must ``DNSConnection/close()`` it when done.
    public func connect(to server: String, port: Int? = nil, transport: DNSTransport = .tcp,
                       serverName: String? = nil, timeout: TimeAmount = .seconds(5)) async throws -> DNSConnection {
        let address = try resolve(host: server, port: port ?? transport.defaultPort)
        let hostname = serverName ?? server
        let queueBox = group.next().makePromise(of: NIOLoopBound<FrameQueue>.self)

        let channel: Channel
        switch transport {
        case .udp:
            channel = try await DatagramBootstrap(group: group)
                .channelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 4096))
                .channelInitializer { ch in
                    let queue = FrameQueue()
                    queueBox.succeed(NIOLoopBound(queue, eventLoop: ch.eventLoop))
                    return ch.pipeline.addHandler(DatagramFrameHandler(queue: queue))
                }
                .connect(to: address).get()
        case .tcp:
            channel = try await ClientBootstrap(group: group)
                .connectTimeout(timeout)
                .channelInitializer { ch in
                    let queue = FrameQueue()
                    queueBox.succeed(NIOLoopBound(queue, eventLoop: ch.eventLoop))
                    return ch.pipeline.addHandler(StreamFrameHandler(queue: queue))
                }
                .connect(to: address).get()
        case .tls:
            let context = try sslContext()
            // TLS SNI / hostname verification can't use a bare IP address.
            let sni: String? = (try? SocketAddress(ipAddress: hostname, port: 0)) != nil ? nil : hostname
            channel = try await ClientBootstrap(group: group)
                .connectTimeout(timeout)
                .channelInitializer { ch in
                    do {
                        let tls = try NIOSSLClientHandler(context: context, serverHostname: sni)
                        let queue = FrameQueue()
                        queueBox.succeed(NIOLoopBound(queue, eventLoop: ch.eventLoop))
                        // addHandlers (not flatMap) so the non-Sendable queue is
                        // never captured in an escaping @Sendable callback.
                        return ch.pipeline.addHandlers([tls, StreamFrameHandler(queue: queue)])
                    } catch {
                        return ch.eventLoop.makeFailedFuture(error)
                    }
                }
                .connect(to: address).get()
        }

        let queue = try await queueBox.futureResult.get()
        // When the channel closes, unblock any waiting reader.
        channel.closeFuture.whenComplete { _ in queue.value.fail(DNSClientError.connectionClosed) }
        return DNSConnection(channel: channel, transport: transport, frameQueue: queue)
    }

    /// Performs a zone transfer (AXFR by default) over TCP, reading the stream
    /// of response messages until the closing SOA, and returns all answer
    /// records in order (including the leading and trailing SOA).
    public func transfer(zone: String, type: RRType = .axfr, server: String, port: Int = 53,
                        timeout: TimeAmount = .seconds(30)) async throws -> [any RR] {
        let address = try resolve(host: server, port: port)
        let query = Msg(header: MsgHeader(id: UInt16.random(in: 0...UInt16.max)),
                        questions: [Question(Name(zone).fqdn, type)])
        let request = try query.pack()

        let loop = group.next()
        let promise = loop.makePromise(of: [any RR].self)
        let channel = try await ClientBootstrap(group: group)
            .channelInitializer { ch in ch.pipeline.addHandler(ZoneTransferHandler(promise: promise)) }
            .connect(to: address).get()

        let timeoutTask = channel.eventLoop.scheduleTask(in: timeout) { promise.fail(DNSClientError.timeout) }
        var out = channel.allocator.buffer(capacity: request.count + 2)
        out.writeInteger(UInt16(request.count))
        out.writeBytes(request)
        do {
            try await channel.writeAndFlush(out).get()
            let records = try await promise.futureResult.get()
            timeoutTask.cancel()
            try? await channel.close().get()
            return records
        } catch {
            timeoutTask.cancel()
            try? await channel.close().get()
            throw error
        }
    }

    private func resolve(host: String, port: Int) throws -> SocketAddress {
        if let addr = try? SocketAddress(ipAddress: host, port: port) { return addr }
        return try SocketAddress.makeAddressResolvingHost(host, port: port)
    }
}

/// A persistent connection to a DNS server, reusable across many exchanges —
/// the analog of the Go library's `Conn`. TCP/TLS handshakes happen once, at
/// ``DNSClient/connect(to:port:transport:serverName:timeout:)``; each
/// ``exchange(_:timeout:)`` sends a query and reads its reply on the same
/// socket. Exchanges are serialized (one in flight at a time).
public actor DNSConnection {
    public let transport: DNSTransport
    private let channel: Channel
    private let eventLoop: EventLoop
    private let frameQueue: NIOLoopBound<FrameQueue>
    private var closed = false

    init(channel: Channel, transport: DNSTransport, frameQueue: NIOLoopBound<FrameQueue>) {
        self.channel = channel
        self.transport = transport
        self.eventLoop = channel.eventLoop
        self.frameQueue = frameQueue
    }

    /// Sends `msg` and returns the matching reply. A stream (TCP/TLS) reply with
    /// a mismatched id is an error (RFC-style `ErrId`); UDP skips stale replies.
    /// On timeout or mismatch the connection is closed, since its stream would
    /// otherwise be desynchronized.
    public func exchange(_ msg: Msg, timeout: TimeAmount = .seconds(5)) async throws -> Msg {
        guard !closed else { throw DNSClientError.connectionClosed }

        let request = try msg.pack()
        var out = channel.allocator.buffer(capacity: request.count + 2)
        if transport.streamed { out.writeInteger(UInt16(request.count)) }
        out.writeBytes(request)
        try await channel.writeAndFlush(out).get()

        let loop = eventLoop
        let queue = frameQueue
        while true {
            let promise = loop.makePromise(of: [UInt8].self)
            loop.execute { queue.value.read(into: promise) }
            let deadline = loop.scheduleTask(in: timeout) { queue.value.cancelRead(DNSClientError.timeout) }

            let frame: [UInt8]
            do {
                frame = try await promise.futureResult.get()
            } catch {
                deadline.cancel()
                await forceClose()
                throw error
            }
            deadline.cancel()

            let reply = try Msg(unpacking: frame)
            if reply.header.id == msg.header.id { return reply }
            if transport.streamed {
                await forceClose()
                throw DNSClientError.idMismatch(sent: msg.header.id, received: reply.header.id)
            }
            // UDP: a stale reply to an earlier, timed-out query — keep reading.
        }
    }

    /// Closes the connection.
    public func close() async { await forceClose() }

    private func forceClose() async {
        guard !closed else { return }
        closed = true
        try? await channel.close().get()
    }
}

/// Buffers inbound message frames and hands them to a single waiting reader.
/// All methods must run on the channel's event loop.
final class FrameQueue {
    private var frames: CircularBuffer<[UInt8]> = []
    private var waiter: EventLoopPromise<[UInt8]>?
    private var closedError: Error?

    func deliver(_ frame: [UInt8]) {
        if let waiter {
            self.waiter = nil
            waiter.succeed(frame)
        } else {
            frames.append(frame)
        }
    }

    func read(into promise: EventLoopPromise<[UInt8]>) {
        if let closedError { promise.fail(closedError); return }
        if !frames.isEmpty { promise.succeed(frames.removeFirst()); return }
        waiter = promise
    }

    func cancelRead(_ error: Error) {
        if let waiter {
            self.waiter = nil
            waiter.fail(error)
        }
    }

    func fail(_ error: Error) {
        if closedError == nil { closedError = error }
        if let waiter {
            self.waiter = nil
            waiter.fail(error)
        }
    }
}

/// Extracts 2-byte length-prefixed message frames from a TCP/TLS stream.
private final class StreamFrameHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private let queue: FrameQueue
    private var acc: [UInt8] = []
    init(queue: FrameQueue) { self.queue = queue }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        acc.append(contentsOf: buf.readBytes(length: buf.readableBytes) ?? [])
        while acc.count >= 2 {
            let length = Int(acc[0]) << 8 | Int(acc[1])
            guard acc.count >= 2 + length else { break }
            let frame = Array(acc[2..<2 + length])
            acc.removeFirst(2 + length)
            queue.deliver(frame)
        }
    }
    func channelInactive(context: ChannelHandlerContext) {
        queue.fail(DNSClientError.connectionClosed)
        context.fireChannelInactive()
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        queue.fail(error)
        context.close(promise: nil)
    }
}

/// Hands each datagram payload (a whole message) to the frame queue.
private final class DatagramFrameHandler: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    private let queue: FrameQueue
    init(queue: FrameQueue) { self.queue = queue }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data).data
        queue.deliver(buf.readBytes(length: buf.readableBytes) ?? [])
    }
    func channelInactive(context: ChannelHandlerContext) {
        queue.fail(DNSClientError.connectionClosed)
        context.fireChannelInactive()
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        queue.fail(error)
        context.close(promise: nil)
    }
}

/// Reads a stream of 2-byte length-prefixed messages for a zone transfer,
/// accumulating answer records until the closing SOA (the second SOA seen).
private final class ZoneTransferHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private let promise: EventLoopPromise<[any RR]>
    private var acc: [UInt8] = []
    private var collected: [any RR] = []
    private var soaCount = 0
    private var completed = false
    init(promise: EventLoopPromise<[any RR]>) { self.promise = promise }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !completed else { return }
        var buf = unwrapInboundIn(data)
        acc.append(contentsOf: buf.readBytes(length: buf.readableBytes) ?? [])

        while acc.count >= 2 {
            let length = Int(acc[0]) << 8 | Int(acc[1])
            guard acc.count >= 2 + length else { break }
            let frame = Array(acc[2..<2 + length])
            acc.removeFirst(2 + length)
            do {
                let msg = try Msg(unpacking: frame)
                for rr in msg.answers {
                    collected.append(rr)
                    if rr.header.type == .soa { soaCount += 1 }
                }
            } catch {
                finish(context: context) { self.promise.fail(error) }
                return
            }
            if soaCount >= 2 {  // leading + trailing SOA => transfer complete
                let records = collected
                finish(context: context) { self.promise.succeed(records) }
                return
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        finish(context: context) { self.promise.fail(error) }
    }

    private func finish(context: ChannelHandlerContext, _ resolve: () -> Void) {
        guard !completed else { return }
        completed = true
        resolve()
        context.close(promise: nil)
    }
}
