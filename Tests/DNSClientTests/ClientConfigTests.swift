import XCTest
@testable import DNSClient

final class ClientConfigTests: XCTestCase {
    func testParsesNameserversSearchAndOptions() {
        let conf = """
        # a comment
        nameserver 8.8.8.8
        nameserver 2001:4860:4860::8888
        search example.com corp.example.com
        options ndots:2 timeout:3 attempts:4
        """
        let c = ClientConfig(parsing: conf)
        XCTAssertEqual(c.nameservers, ["8.8.8.8", "2001:4860:4860::8888"])
        XCTAssertEqual(c.search, ["example.com", "corp.example.com"])
        XCTAssertEqual(c.ndots, 2)
        XCTAssertEqual(c.timeoutSeconds, 3)
        XCTAssertEqual(c.attempts, 4)
    }

    func testDomainSetsSingleSearch() {
        let c = ClientConfig(parsing: "domain example.org\nnameserver 1.1.1.1\n")
        XCTAssertEqual(c.search, ["example.org"])
        XCTAssertEqual(c.nameservers, ["1.1.1.1"])
    }

    func testDefaultsAndCommentsAndTrailingComments() {
        let c = ClientConfig(parsing: "nameserver 9.9.9.9 ; inline comment\n; full comment line\n")
        XCTAssertEqual(c.nameservers, ["9.9.9.9"])
        XCTAssertEqual(c.ndots, 1)      // default
        XCTAssertEqual(c.timeoutSeconds, 5)
        XCTAssertEqual(c.attempts, 2)
        XCTAssertEqual(c.port, 53)
    }
}
