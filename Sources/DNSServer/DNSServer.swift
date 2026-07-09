import DNSCore
import DNSTypes
import NIOCore
import NIOPosix
import NIOSSL

/// An asynchronous DNS server listening on UDP and TCP, dispatching each
/// request to a ``DNSResponder`` (e.g. a ``ServeMux``).
public actor DNSServer {
    private let group: EventLoopGroup
    private let ownsGroup: Bool
    private let responder: any DNSResponder
    private var udpChannel: Channel?
    private var tcpChannel: Channel?

    public init(responder: any DNSResponder, group: EventLoopGroup? = nil) {
        self.responder = responder
        if let group {
            self.group = group
            self.ownsGroup = false
        } else {
            self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            self.ownsGroup = true
        }
    }

    /// The port actually bound (useful when starting on port 0).
    public var boundPort: Int? { udpChannel?.localAddress?.port ?? tcpChannel?.localAddress?.port }

    /// Binds UDP and TCP on `host:port`. When `port` is 0 an ephemeral port is
    /// chosen for UDP and reused for TCP so both share the same port.
    public func start(host: String = "127.0.0.1", port: Int = 0) async throws {
        let responder = self.responder
        let udp = try await DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 4096))
            .channelInitializer { ch in
                ch.pipeline.addHandler(UDPServerHandler(responder: responder))
            }
            .bind(host: host, port: port).get()
        self.udpChannel = udp

        let effectivePort = udp.localAddress?.port ?? port
        let tcp = try await ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { ch in
                ch.pipeline.addHandler(TCPServerHandler(responder: responder))
            }
            .bind(host: host, port: effectivePort).get()
        self.tcpChannel = tcp
    }

    /// Binds a DNS-over-TLS listener (RFC 7858): TCP wrapped in TLS. DoT is
    /// TCP-only, so no UDP listener is created. Requires a `tlsConfiguration`
    /// with the server's certificate chain and private key.
    public func startTLS(host: String = "127.0.0.1", port: Int = 853,
                        tlsConfiguration: TLSConfiguration) async throws {
        let responder = self.responder
        let sslContext = try NIOSSLContext(configuration: tlsConfiguration)
        let tcp = try await ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { ch in
                ch.pipeline.addHandler(NIOSSLServerHandler(context: sslContext)).flatMap {
                    ch.pipeline.addHandler(TCPServerHandler(responder: responder))
                }
            }
            .bind(host: host, port: port).get()
        self.tcpChannel = tcp
    }

    /// Closes the listeners and shuts down the owned event-loop group.
    public func shutdown() async throws {
        try? await udpChannel?.close().get()
        try? await tcpChannel?.close().get()
        udpChannel = nil
        tcpChannel = nil
        if ownsGroup { try await group.shutdownGracefully() }
    }
}

/// Decodes a datagram, invokes the responder, and writes the reply back to the
/// sender.
private final class UDPServerHandler: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    private let responder: any DNSResponder
    init(responder: any DNSResponder) { self.responder = responder }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        var buf = envelope.data
        let bytes = buf.readBytes(length: buf.readableBytes) ?? []
        guard let request = try? Msg(unpacking: bytes) else { return }

        let channel = context.channel
        let allocator = context.channel.allocator
        let remote = envelope.remoteAddress
        let responder = self.responder
        Task {
            guard let response = await responder.respond(to: request, from: remote),
                  let out = try? response.pack() else { return }
            var ob = allocator.buffer(capacity: out.count)
            ob.writeBytes(out)
            channel.writeAndFlush(AddressedEnvelope(remoteAddress: remote, data: ob), promise: nil)
        }
    }
}

/// Frames requests/replies with a 2-byte length prefix over a TCP connection.
/// Multiple queries per connection are supported; replies may complete out of
/// order (DNS matches by message ID).
private final class TCPServerHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let responder: any DNSResponder
    private var acc: [UInt8] = []
    init(responder: any DNSResponder) { self.responder = responder }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        acc.append(contentsOf: buf.readBytes(length: buf.readableBytes) ?? [])

        while acc.count >= 2 {
            let length = Int(acc[0]) << 8 | Int(acc[1])
            guard acc.count >= 2 + length else { break }
            let frame = Array(acc[2..<2 + length])
            acc.removeFirst(2 + length)
            guard let request = try? Msg(unpacking: frame) else { continue }

            let channel = context.channel
            let allocator = context.channel.allocator
            let remote = context.remoteAddress ?? (try? SocketAddress(ipAddress: "0.0.0.0", port: 0))!
            let responder = self.responder
            Task {
                guard let response = await responder.respond(to: request, from: remote),
                      let out = try? response.pack() else { return }
                var ob = allocator.buffer(capacity: out.count + 2)
                ob.writeInteger(UInt16(out.count))
                ob.writeBytes(out)
                channel.writeAndFlush(ob, promise: nil)
            }
        }
    }
}
