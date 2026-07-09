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
/// Exchanges a ``Msg`` with a server and returns the parsed reply. UDP queries
/// automatically retry over TCP when the reply is truncated (TC bit). TLS uses
/// NIOSSL, which runs on Apple platforms and Linux alike.
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

    // MARK: High-level API

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

    /// Exchanges a fully-formed message with a server over the given transport,
    /// retrying over TCP if a UDP reply is truncated.
    public func exchange(_ msg: Msg, server: String, port: Int? = nil,
                        transport: DNSTransport = .udp, serverName: String? = nil,
                        timeout: TimeAmount = .seconds(5)) async throws -> Msg {
        let address = try resolve(host: server, port: port ?? transport.defaultPort)
        let request = try msg.pack()
        let hostname = serverName ?? server

        let replyBytes = try await exchangeRaw(query: request, to: address, transport: transport,
                                               serverName: hostname, timeout: timeout)
        guard !replyBytes.isEmpty else { throw DNSClientError.emptyResponse }
        var reply = try Msg(unpacking: replyBytes)

        // Truncated UDP reply -> retry over TCP (same host, port 53).
        if transport == .udp && reply.header.truncated {
            let tcpAddress = try resolve(host: server, port: port ?? 53)
            let tcpBytes = try await exchangeRaw(query: request, to: tcpAddress, transport: .tcp,
                                                 serverName: hostname, timeout: timeout)
            guard !tcpBytes.isEmpty else { throw DNSClientError.emptyResponse }
            reply = try Msg(unpacking: tcpBytes)
        }

        guard reply.header.id == msg.header.id else {
            throw DNSClientError.idMismatch(sent: msg.header.id, received: reply.header.id)
        }
        return reply
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

    // MARK: Wire exchange

    private func exchangeRaw(query: [UInt8], to server: SocketAddress, transport: DNSTransport,
                            serverName: String, timeout: TimeAmount) async throws -> [UInt8] {
        let loop = group.next()
        let promise = loop.makePromise(of: [UInt8].self)

        let channel: Channel
        switch transport {
        case .udp:
            channel = try await DatagramBootstrap(group: group)
                .channelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 4096))
                .channelInitializer { ch in
                    ch.pipeline.addHandler(UDPResponseHandler(promise: promise))
                }
                .connect(to: server).get()
        case .tcp:
            channel = try await ClientBootstrap(group: group)
                .channelInitializer { ch in
                    ch.pipeline.addHandler(TCPResponseHandler(promise: promise))
                }
                .connect(to: server).get()
        case .tls:
            let context = try sslContext()
            // TLS SNI / hostname verification can't use a bare IP address.
            let sni: String? = (try? SocketAddress(ipAddress: serverName, port: 0)) != nil ? nil : serverName
            channel = try await ClientBootstrap(group: group)
                .channelInitializer { ch in
                    do {
                        let tls = try NIOSSLClientHandler(context: context, serverHostname: sni)
                        return ch.pipeline.addHandler(tls).flatMap {
                            ch.pipeline.addHandler(TCPResponseHandler(promise: promise))
                        }
                    } catch {
                        return ch.eventLoop.makeFailedFuture(error)
                    }
                }
                .connect(to: server).get()
        }

        let timeoutTask = channel.eventLoop.scheduleTask(in: timeout) {
            promise.fail(DNSClientError.timeout)
        }

        // TCP and TLS both frame the message with a 2-byte length prefix.
        var out = channel.allocator.buffer(capacity: query.count + 2)
        if transport.streamed { out.writeInteger(UInt16(query.count)) }
        out.writeBytes(query)

        do {
            try await channel.writeAndFlush(out).get()
            let bytes = try await promise.futureResult.get()
            timeoutTask.cancel()
            try? await channel.close().get()
            return bytes
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

/// Collects a single datagram reply (the payload is the whole message) and
/// fulfills the promise. A connected UDP channel still delivers envelopes.
private final class UDPResponseHandler: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    private let promise: EventLoopPromise<[UInt8]>
    private var completed = false
    init(promise: EventLoopPromise<[UInt8]>) { self.promise = promise }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !completed else { return }
        var buf = unwrapInboundIn(data).data
        completed = true
        promise.succeed(buf.readBytes(length: buf.readableBytes) ?? [])
        context.close(promise: nil)
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        guard !completed else { return }
        completed = true
        promise.fail(error)
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

/// Collects a single 2-byte length-prefixed reply from a TCP stream.
private final class TCPResponseHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private let promise: EventLoopPromise<[UInt8]>
    private var acc: [UInt8] = []
    private var completed = false
    init(promise: EventLoopPromise<[UInt8]>) { self.promise = promise }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !completed else { return }
        var buf = unwrapInboundIn(data)
        acc.append(contentsOf: buf.readBytes(length: buf.readableBytes) ?? [])
        guard acc.count >= 2 else { return }
        let length = Int(acc[0]) << 8 | Int(acc[1])
        if acc.count >= 2 + length {
            completed = true
            promise.succeed(Array(acc[2..<2 + length]))
            context.close(promise: nil)
        }
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        guard !completed else { return }
        completed = true
        promise.fail(error)
        context.close(promise: nil)
    }
}
