import DNSCore
import DNSTypes
import NIOCore
import NIOPosix

/// A minimal in-process DNS responder used to exercise the client's UDP/TCP
/// paths without external network access. Given the raw query bytes, `reply`
/// returns the raw response bytes (or nil to stay silent, forcing a timeout).
enum TestResponder {
    /// Builds a standard reply echoing the question and adding the given answers,
    /// optionally setting the TC (truncated) bit.
    static func makeReply(query: [UInt8], truncated: Bool, answers: [any RR]) -> [UInt8]? {
        guard let q = try? Msg(unpacking: query) else { return nil }
        var h = q.header
        h.response = true
        h.recursionAvailable = true
        h.truncated = truncated
        let msg = Msg(header: h, questions: q.questions, answers: truncated ? [] : answers)
        return try? msg.pack()
    }
}

final class UDPResponderHandler: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    private let reply: @Sendable ([UInt8]) -> [UInt8]?
    init(reply: @escaping @Sendable ([UInt8]) -> [UInt8]?) { self.reply = reply }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let env = unwrapInboundIn(data)
        var buf = env.data
        let bytes = buf.readBytes(length: buf.readableBytes) ?? []
        guard let response = reply(bytes) else { return }
        var out = context.channel.allocator.buffer(capacity: response.count)
        out.writeBytes(response)
        context.writeAndFlush(wrapOutboundOut(AddressedEnvelope(remoteAddress: env.remoteAddress, data: out)),
                              promise: nil)
    }
}

final class TCPResponderHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    private let reply: @Sendable ([UInt8]) -> [UInt8]?
    private var acc: [UInt8] = []
    init(reply: @escaping @Sendable ([UInt8]) -> [UInt8]?) { self.reply = reply }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        acc.append(contentsOf: buf.readBytes(length: buf.readableBytes) ?? [])
        guard acc.count >= 2 else { return }
        let length = Int(acc[0]) << 8 | Int(acc[1])
        guard acc.count >= 2 + length else { return }
        let query = Array(acc[2..<2 + length])
        acc.removeFirst(2 + length)
        guard let response = reply(query) else { return }
        var out = context.channel.allocator.buffer(capacity: response.count + 2)
        out.writeInteger(UInt16(response.count))
        out.writeBytes(response)
        context.writeAndFlush(wrapOutboundOut(out), promise: nil)
    }
}

/// Starts loopback UDP and/or TCP responders on a shared port.
struct LocalDNSServer {
    let group: EventLoopGroup
    var udp: Channel?
    var tcp: Channel?
    var port: Int { udp?.localAddress?.port ?? tcp?.localAddress?.port ?? 0 }

    static func startUDP(group: EventLoopGroup,
                        reply: @escaping @Sendable ([UInt8]) -> [UInt8]?) async throws -> Channel {
        try await DatagramBootstrap(group: group)
            .channelInitializer { ch in ch.pipeline.addHandler(UDPResponderHandler(reply: reply)) }
            .bind(host: "127.0.0.1", port: 0).get()
    }

    static func startTCP(group: EventLoopGroup, port: Int,
                        reply: @escaping @Sendable ([UInt8]) -> [UInt8]?) async throws -> Channel {
        try await ServerBootstrap(group: group)
            .childChannelInitializer { ch in ch.pipeline.addHandler(TCPResponderHandler(reply: reply)) }
            .bind(host: "127.0.0.1", port: port).get()
    }
}
