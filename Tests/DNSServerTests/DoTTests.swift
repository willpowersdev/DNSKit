import XCTest
import DNSCore
import DNSTypes
import DNSClient
import NIOSSL
@testable import DNSServer

/// End-to-end DNS-over-TLS: the real DNSServer (TLS listener) answered by the
/// real DNSClient (TLS transport), over a loopback connection with a throwaway
/// self-signed certificate.
final class DoTTests: XCTestCase {
    // Self-signed EC cert (CN=DNSKit Test) generated for this test only.
    private static let certPEM = """
    -----BEGIN CERTIFICATE-----
    MIIBgTCCASegAwIBAgIUQsacutRup8q+JSZ6XXv1YQ4FP/YwCgYIKoZIzj0EAwIw
    FjEUMBIGA1UEAwwLRE5TS2l0IFRlc3QwHhcNMjYwNzA5MDI1NDExWhcNMzYwNzA2
    MDI1NDExWjAWMRQwEgYDVQQDDAtETlNLaXQgVGVzdDBZMBMGByqGSM49AgEGCCqG
    SM49AwEHA0IABKzAfjQR2MiuNXQN6yCZrmyMTRn2MMg6rwMzxSWpWNFqTu5qMb0E
    FhPNx9He7NHdldzAqW9M0BxtM/ySJZnkMKSjUzBRMB0GA1UdDgQWBBSqOlYb8Kln
    GMT3Mz9IbIsDbFlcpzAfBgNVHSMEGDAWgBSqOlYb8KlnGMT3Mz9IbIsDbFlcpzAP
    BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIHsgEQtZg9ZBK2WQ/v7b
    wTbOtPcchl9pI/LZ8S8clLsXAiEAq2GCvtkqXjEdilSoVb87Jh2QJguARsIn7CkW
    mtcyPKM=
    -----END CERTIFICATE-----
    """
    private static let keyPEM = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIKgwi2oHuCbn8G0bAYzrh6cWJkPkgboUf3K5e6txv2H9oAoGCCqGSM49
    AwEHoUQDQgAErMB+NBHYyK41dA3rIJmubIxNGfYwyDqvAzPFJalY0WpO7moxvQQW
    E83H0d7s0d2V3MCpb0zQHG0z/JIlmeQwpA==
    -----END EC PRIVATE KEY-----
    """

    func testDoTClientServerRoundTrip() async throws {
        let cert = try NIOSSLCertificate(bytes: Array(Self.certPEM.utf8), format: .pem)
        let key = try NIOSSLPrivateKey(bytes: Array(Self.keyPEM.utf8), format: .pem)
        let serverTLS = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(cert)], privateKey: .privateKey(key))

        let mux = ServeMux()
        mux.register(Name("secure.example."), HandlerFunc { request, _ in
            var reply = request.makeReply()
            reply.answers = [A(header: RRHeader(name: Name("secure.example."), type: .a, ttl: 60),
                               a: IPv4Address("192.0.2.77"))]
            return reply
        })
        let server = DNSServer(responder: mux)
        try await server.startTLS(host: "127.0.0.1", port: 0, tlsConfiguration: serverTLS)
        let port = await server.boundPort!

        // Self-signed cert isn't in any trust store, so the test client disables
        // verification. (Production uses the default, which verifies.)
        var clientTLS = TLSConfiguration.makeClientConfiguration()
        clientTLS.certificateVerification = .none
        let client = DNSClient(tlsConfiguration: clientTLS)

        let reply = try await client.query("secure.example.", .a, server: "127.0.0.1",
                                           port: port, transport: .tls, timeout: .seconds(3))
        XCTAssertTrue(reply.header.response)
        XCTAssertEqual((reply.answers.first as? A)?.a.description, "192.0.2.77")

        try await client.shutdown()
        try await server.shutdown()
    }

    /// A single DoT connection (one TLS handshake) serving several queries.
    func testDoTConnectionReuse() async throws {
        let cert = try NIOSSLCertificate(bytes: Array(Self.certPEM.utf8), format: .pem)
        let key = try NIOSSLPrivateKey(bytes: Array(Self.keyPEM.utf8), format: .pem)
        let serverTLS = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(cert)], privateKey: .privateKey(key))

        let mux = ServeMux()
        mux.register(Name("secure.example."), HandlerFunc { request, _ in
            var reply = request.makeReply()
            let name = request.questions.first?.name ?? Name("secure.example.")
            reply.answers = [A(header: RRHeader(name: name, type: .a, ttl: 60),
                               a: IPv4Address("192.0.2.88"))]
            return reply
        })
        let server = DNSServer(responder: mux)
        try await server.startTLS(host: "127.0.0.1", port: 0, tlsConfiguration: serverTLS)
        let port = await server.boundPort!

        var clientTLS = TLSConfiguration.makeClientConfiguration()
        clientTLS.certificateVerification = .none
        let client = DNSClient(tlsConfiguration: clientTLS)

        // Handshake once, then reuse the connection for several queries.
        let connection = try await client.connect(to: "127.0.0.1", port: port, transport: .tls,
                                                  timeout: .seconds(3))
        for i in 0..<3 {
            let query = Msg(header: MsgHeader(id: UInt16(200 + i)),
                            questions: [Question(Name("host\(i).secure.example."), .a)])
            let reply = try await connection.exchange(query, timeout: .seconds(3))
            XCTAssertEqual(reply.header.id, UInt16(200 + i))
            XCTAssertEqual((reply.answers.first as? A)?.a.description, "192.0.2.88")
        }

        await connection.close()
        try await client.shutdown()
        try await server.shutdown()
    }
}
