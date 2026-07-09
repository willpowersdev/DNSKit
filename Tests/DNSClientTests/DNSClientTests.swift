import XCTest
import DNSCore
import DNSTypes
import NIOCore
import NIOPosix
@testable import DNSClient

final class DNSClientTests: XCTestCase {
    private static func answerA(_ ip: String) -> A {
        A(header: RRHeader(name: Name("example.com."), type: .a, ttl: 300), a: IPv4Address(ip)!)
    }

    func testUDPQueryEndToEnd() async throws {
        let serverGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let answers: [any RR] = [Self.answerA("192.0.2.1")]
        let udp = try await LocalDNSServer.startUDP(group: serverGroup) { q in
            TestResponder.makeReply(query: q, truncated: false, answers: answers)
        }
        let port = udp.localAddress!.port!

        let client = DNSClient()
        let reply = try await client.query("example.com.", .a, server: "127.0.0.1", port: port,
                                           timeout: .seconds(2))
        XCTAssertTrue(reply.header.response)
        XCTAssertEqual(reply.answers.count, 1)
        XCTAssertEqual((reply.answers.first as? A)?.a.description, "192.0.2.1")

        try await client.shutdown()
        try await serverGroup.shutdownGracefully()
    }

    func testTCPQueryEndToEnd() async throws {
        let serverGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let answers: [any RR] = [Self.answerA("192.0.2.9")]
        let tcp = try await LocalDNSServer.startTCP(group: serverGroup, port: 0) { q in
            TestResponder.makeReply(query: q, truncated: false, answers: answers)
        }
        let port = tcp.localAddress!.port!

        let client = DNSClient()
        let reply = try await client.query("example.com.", .a, server: "127.0.0.1", port: port,
                                           transport: .tcp, timeout: .seconds(2))
        XCTAssertEqual((reply.answers.first as? A)?.a.description, "192.0.2.9")

        try await client.shutdown()
        try await serverGroup.shutdownGracefully()
    }

    func testTruncationFallsBackToTCP() async throws {
        let serverGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let tcpAnswers: [any RR] = [Self.answerA("192.0.2.42")]
        // UDP responder returns a truncated (TC=1) empty reply...
        let udp = try await LocalDNSServer.startUDP(group: serverGroup) { q in
            TestResponder.makeReply(query: q, truncated: true, answers: [])
        }
        let port = udp.localAddress!.port!
        // ...and a TCP responder on the same port returns the full answer.
        let tcp = try await LocalDNSServer.startTCP(group: serverGroup, port: port) { q in
            TestResponder.makeReply(query: q, truncated: false, answers: tcpAnswers)
        }

        let client = DNSClient()
        let reply = try await client.query("example.com.", .a, server: "127.0.0.1", port: port,
                                           timeout: .seconds(2))
        XCTAssertFalse(reply.header.truncated)
        XCTAssertEqual((reply.answers.first as? A)?.a.description, "192.0.2.42")

        try await client.shutdown()
        try await udp.close()
        try await tcp.close()
        try await serverGroup.shutdownGracefully()
    }

    /// Real query against a public resolver. Skips (not fails) when the test
    /// environment has no outbound network.
    func testLiveQueryPublicResolver() async throws {
        let client = DNSClient()
        do {
            let reply = try await client.query("example.com.", .a, server: "8.8.8.8", timeout: .seconds(3))
            XCTAssertTrue(reply.header.response)
            XCTAssertFalse(reply.answers.isEmpty)
            XCTAssertTrue(reply.answers.contains { $0 is A })
            try await client.shutdown()
        } catch {
            try? await client.shutdown()
            throw XCTSkip("no outbound network / resolver unreachable: \(error)")
        }
    }

    /// Real DNS-over-TLS query against Cloudflare's public resolver, with full
    /// certificate verification. Skips when the environment has no outbound DoT.
    func testLiveDoTQuery() async throws {
        let client = DNSClient()
        do {
            let reply = try await client.query("example.com.", .a, server: "1.1.1.1",
                                               transport: .tls, serverName: "cloudflare-dns.com",
                                               timeout: .seconds(4))
            XCTAssertTrue(reply.header.response)
            XCTAssertTrue(reply.answers.contains { $0 is A })
            try await client.shutdown()
        } catch {
            try? await client.shutdown()
            throw XCTSkip("no outbound DoT / resolver unreachable: \(error)")
        }
    }

    func testTimeoutWhenServerSilent() async throws {
        let serverGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        // Responder that never replies -> the client must time out.
        let udp = try await LocalDNSServer.startUDP(group: serverGroup) { _ in nil }
        let port = udp.localAddress!.port!

        let client = DNSClient()
        do {
            _ = try await client.query("example.com.", .a, server: "127.0.0.1", port: port,
                                       timeout: .milliseconds(300))
            XCTFail("expected timeout")
        } catch let e as DNSClientError {
            XCTAssertEqual(e, .timeout)
        }

        try await client.shutdown()
        try await serverGroup.shutdownGracefully()
    }
}
