import XCTest
import DNSCore
import DNSTypes
import NIOCore
import NIOPosix
@testable import DNSClient

/// Sends a fixed set of pre-framed responses once a query arrives, to exercise
/// the client reading a MULTI-message AXFR stream over one TCP connection.
private final class MultiFrameHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    private let frames: [[UInt8]]
    private var sent = false
    init(frames: [[UInt8]]) { self.frames = frames }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !sent else { return }
        sent = true
        for frame in frames {
            var b = context.channel.allocator.buffer(capacity: frame.count + 2)
            b.writeInteger(UInt16(frame.count))
            b.writeBytes(frame)
            context.writeAndFlush(wrapOutboundOut(b), promise: nil)
        }
    }
}

final class ZoneTransferTests: XCTestCase {
    private func frame(_ answers: [any RR]) throws -> [UInt8] {
        try Msg(header: MsgHeader(id: 5, response: true), answers: answers).pack()
    }

    func testAXFRAcrossMultipleMessages() async throws {
        let soa = SOA(header: RRHeader(name: Name("example.com."), type: .soa, ttl: 3600),
                      ns: Name("ns1.example.com."), mbox: Name("hostmaster.example.com."),
                      serial: 1, refresh: 2, retry: 3, expire: 4, minttl: 5)
        let a1 = A(header: RRHeader(name: Name("a.example.com."), type: .a, ttl: 300), a: IPv4Address("192.0.2.1"))
        let a2 = A(header: RRHeader(name: Name("b.example.com."), type: .a, ttl: 300), a: IPv4Address("192.0.2.2"))
        // Two messages: [SOA, a1] then [a2, SOA]. The closing SOA ends the transfer.
        let frames = [try frame([soa, a1]), try frame([a2, soa])]

        let serverGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await ServerBootstrap(group: serverGroup)
            .childChannelInitializer { ch in ch.pipeline.addHandler(MultiFrameHandler(frames: frames)) }
            .bind(host: "127.0.0.1", port: 0).get()
        let port = server.localAddress!.port!

        let client = DNSClient()
        let records = try await client.transfer(zone: "example.com.", server: "127.0.0.1",
                                                port: port, timeout: .seconds(2))
        XCTAssertEqual(records.count, 4)
        XCTAssertTrue(records.first is SOA)
        XCTAssertTrue(records.last is SOA)
        XCTAssertEqual((records[1] as? A)?.a.description, "192.0.2.1")
        XCTAssertEqual((records[2] as? A)?.a.description, "192.0.2.2")

        try await client.shutdown()
        try await server.close()
        try await serverGroup.shutdownGracefully()
    }
}
