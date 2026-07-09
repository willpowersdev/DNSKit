import XCTest
import DNSCore
import DNSTypes
import DNSClient
@testable import DNSServer

final class ServerTests: XCTestCase {
    /// A responder that answers every matched query with one A record.
    private static func answering(_ ip: String) -> HandlerFunc {
        HandlerFunc { request, _ in
            var reply = request.makeReply()
            reply.header.recursionAvailable = true
            guard let q = request.questions.first else { return reply }
            reply.answers = [A(header: RRHeader(name: q.name, type: .a, ttl: 60), a: IPv4Address(ip)!)]
            return reply
        }
    }

    func testClientServerOverUDP() async throws {
        let mux = ServeMux()
        mux.register(Name("example.com."), Self.answering("192.0.2.10"))
        let server = DNSServer(responder: mux)
        try await server.start()
        let port = await server.boundPort!

        let client = DNSClient()
        let reply = try await client.query("www.example.com.", .a, server: "127.0.0.1", port: port,
                                           timeout: .seconds(2))
        XCTAssertTrue(reply.header.response)
        XCTAssertEqual((reply.answers.first as? A)?.a.description, "192.0.2.10")

        try await client.shutdown()
        try await server.shutdown()
    }

    func testClientServerOverTCP() async throws {
        let mux = ServeMux()
        mux.register(Name("example.com."), Self.answering("192.0.2.20"))
        let server = DNSServer(responder: mux)
        try await server.start()
        let port = await server.boundPort!

        let client = DNSClient()
        let reply = try await client.query("host.example.com.", .a, server: "127.0.0.1", port: port,
                                           useTCP: true, timeout: .seconds(2))
        XCTAssertEqual((reply.answers.first as? A)?.a.description, "192.0.2.20")

        try await client.shutdown()
        try await server.shutdown()
    }

    func testUnmatchedZoneReturnsRefused() async throws {
        let mux = ServeMux()
        mux.register(Name("example.com."), Self.answering("192.0.2.30"))
        let server = DNSServer(responder: mux)
        try await server.start()
        let port = await server.boundPort!

        let client = DNSClient()
        let reply = try await client.query("nowhere.test.", .a, server: "127.0.0.1", port: port,
                                           timeout: .seconds(2))
        XCTAssertEqual(reply.header.rcode, 5) // REFUSED
        XCTAssertTrue(reply.answers.isEmpty)

        try await client.shutdown()
        try await server.shutdown()
    }

    func testZoneTransferSingleMessage() async throws {
        let soa = SOA(header: RRHeader(name: Name("example.com."), type: .soa, ttl: 3600),
                      ns: Name("ns1.example.com."), mbox: Name("hostmaster.example.com."),
                      serial: 2024010101, refresh: 7200, retry: 3600, expire: 1209600, minttl: 300)
        let records: [any RR] = [
            soa,
            A(header: RRHeader(name: Name("example.com."), type: .a, ttl: 300), a: IPv4Address("192.0.2.1")),
            A(header: RRHeader(name: Name("www.example.com."), type: .a, ttl: 300), a: IPv4Address("192.0.2.2")),
            soa,
        ]
        let mux = ServeMux()
        mux.register(Name("example.com."), HandlerFunc { req, _ in
            var reply = req.makeReply()
            reply.answers = records
            return reply
        })
        let server = DNSServer(responder: mux)
        try await server.start()
        let port = await server.boundPort!

        let client = DNSClient()
        let transferred = try await client.transfer(zone: "example.com.", server: "127.0.0.1",
                                                    port: port, timeout: .seconds(2))
        XCTAssertEqual(transferred.count, 4)
        XCTAssertTrue(transferred.first is SOA)
        XCTAssertTrue(transferred.last is SOA)
        XCTAssertEqual((transferred[1] as? A)?.a.description, "192.0.2.1")

        try await client.shutdown()
        try await server.shutdown()
    }

    func testLongestSuffixRouting() async throws {
        let mux = ServeMux()
        mux.register(Name("."), Self.answering("10.0.0.1"))                 // catch-all
        mux.register(Name("sub.example.com."), Self.answering("10.0.0.2"))  // more specific
        let server = DNSServer(responder: mux)
        try await server.start()
        let port = await server.boundPort!

        let client = DNSClient()
        let specific = try await client.query("a.sub.example.com.", .a, server: "127.0.0.1", port: port,
                                              timeout: .seconds(2))
        XCTAssertEqual((specific.answers.first as? A)?.a.description, "10.0.0.2")

        let fallback = try await client.query("elsewhere.net.", .a, server: "127.0.0.1", port: port,
                                             timeout: .seconds(2))
        XCTAssertEqual((fallback.answers.first as? A)?.a.description, "10.0.0.1")

        try await client.shutdown()
        try await server.shutdown()
    }
}
