import DNSCore
import DNSTypes
import NIOCore
import NIOPosix

public enum DNSClientError: Error, Sendable, Equatable {
    case timeout
    case idMismatch(sent: UInt16, received: UInt16)
    case emptyResponse
    case noNameservers
}

/// An asynchronous DNS resolver over UDP and TCP, built on SwiftNIO.
///
/// Exchanges a ``Msg`` with a server and returns the parsed reply. UDP queries
/// automatically retry over TCP when the reply is truncated (TC bit).
public final class DNSClient: Sendable {
    private let group: EventLoopGroup
    private let ownsGroup: Bool

    public init() {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.ownsGroup = true
    }

    public init(group: EventLoopGroup) {
        self.group = group
        self.ownsGroup = false
    }

    /// Shuts down the owned event-loop group. No-op if a group was injected.
    public func shutdown() async throws {
        if ownsGroup { try await group.shutdownGracefully() }
    }

    // MARK: High-level API

    /// Builds a recursive query for `name`/`type` and exchanges it with `server`.
    public func query(_ name: String, _ type: RRType, server: String, port: Int = 53,
                      useTCP: Bool = false, dnssecOK: Bool = false,
                      timeout: TimeAmount = .seconds(5)) async throws -> Msg {
        var header = MsgHeader(id: UInt16.random(in: 0...UInt16.max))
        header.recursionDesired = true
        var msg = Msg(header: header, questions: [Question(Name(name).fqdn, type)])
        if dnssecOK {
            msg.additionals = [OPT(udpSize: 1232, dnssecOK: true)]
        }
        return try await exchange(msg, server: server, port: port, useTCP: useTCP, timeout: timeout)
    }

    /// Exchanges a fully-formed message with a server, retrying over TCP if the
    /// UDP reply is truncated.
    public func exchange(_ msg: Msg, server: String, port: Int = 53, useTCP: Bool = false,
                        timeout: TimeAmount = .seconds(5)) async throws -> Msg {
        let address = try resolve(host: server, port: port)
        let request = try msg.pack()

        let replyBytes = try await exchangeRaw(query: request, to: address, useTCP: useTCP, timeout: timeout)
        guard !replyBytes.isEmpty else { throw DNSClientError.emptyResponse }
        var reply = try Msg(unpacking: replyBytes)

        // Truncated UDP reply -> retry over TCP.
        if !useTCP && reply.header.truncated {
            let tcpBytes = try await exchangeRaw(query: request, to: address, useTCP: true, timeout: timeout)
            guard !tcpBytes.isEmpty else { throw DNSClientError.emptyResponse }
            reply = try Msg(unpacking: tcpBytes)
        }

        guard reply.header.id == msg.header.id else {
            throw DNSClientError.idMismatch(sent: msg.header.id, received: reply.header.id)
        }
        return reply
    }

    // MARK: Wire exchange

    private func exchangeRaw(query: [UInt8], to server: SocketAddress,
                            useTCP: Bool, timeout: TimeAmount) async throws -> [UInt8] {
        let loop = group.next()
        let promise = loop.makePromise(of: [UInt8].self)

        let channel: Channel
        if useTCP {
            channel = try await ClientBootstrap(group: group)
                .channelInitializer { ch in
                    ch.pipeline.addHandler(TCPResponseHandler(promise: promise))
                }
                .connect(to: server).get()
        } else {
            channel = try await DatagramBootstrap(group: group)
                .channelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 4096))
                .channelInitializer { ch in
                    ch.pipeline.addHandler(UDPResponseHandler(promise: promise))
                }
                .connect(to: server).get()
        }

        let timeoutTask = channel.eventLoop.scheduleTask(in: timeout) {
            promise.fail(DNSClientError.timeout)
        }

        var out = channel.allocator.buffer(capacity: query.count + 2)
        if useTCP { out.writeInteger(UInt16(query.count)) }
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
