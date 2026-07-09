import XCTest
import DNSCore
@testable import DNSTypes

final class ZoneFileTests: XCTestCase {
    func testParsesZoneWithDirectivesAndContinuation() throws {
        let zone = """
        $ORIGIN example.com.
        $TTL 3600
        @   IN SOA ns1 hostmaster (
                2024010101 ; serial
                7200 3600 1209600 300 )
            IN NS  ns1
        ns1 IN A   192.0.2.1
        www 60 IN A 192.0.2.2   ; explicit TTL
        """
        let records = try parseZone(zone)
        XCTAssertEqual(records.count, 4)

        let soa = try XCTUnwrap(records[0] as? SOA)
        XCTAssertEqual(soa.header.name.value, "example.com.")
        XCTAssertEqual(soa.ns.value, "ns1.example.com.")       // relative -> qualified
        XCTAssertEqual(soa.serial, 2024010101)                 // spanned multiple lines
        XCTAssertEqual(soa.minttl, 300)

        // Blank owner inherits the previous owner (@ -> example.com.).
        XCTAssertTrue(records[1] is NS)
        XCTAssertEqual(records[1].header.name.value, "example.com.")

        XCTAssertEqual(records[2].header.name.value, "ns1.example.com.")
        XCTAssertEqual((records[2] as? A)?.a.description, "192.0.2.1")
        XCTAssertEqual(records[3].header.name.value, "www.example.com.")
        XCTAssertEqual(records[3].header.ttl, 60)              // explicit per-record TTL
    }

    func testNSECBitmapRoundTripsThroughPresentation() throws {
        let nsec = try NewRR("example.com. 3600 IN NSEC a.example.com. A MX RRSIG NSEC")
        let text = try nsec.present()
        XCTAssertTrue(text.contains("A MX RRSIG NSEC"))
        let reparsed = try NewRR(text)
        XCTAssertEqual(try reparsed.packedBytes(compress: false),
                       try nsec.packedBytes(compress: false))
    }

    func testGenerateDirective() throws {
        let zone = """
        $ORIGIN example.com.
        $GENERATE 1-3 host$ A 192.0.2.$
        $GENERATE 10-11 srv${0,2,d} A 10.0.0.1
        """
        let records = try parseZone(zone)
        XCTAssertEqual(records.count, 5)
        XCTAssertEqual(records[0].header.name.value, "host1.example.com.")
        XCTAssertEqual((records[0] as? A)?.a.description, "192.0.2.1")
        XCTAssertEqual(records[2].header.name.value, "host3.example.com.")
        XCTAssertEqual((records[2] as? A)?.a.description, "192.0.2.3")
        // ${0,2,d} zero-pads to width 2.
        XCTAssertEqual(records[3].header.name.value, "srv10.example.com.")
        XCTAssertEqual(records[4].header.name.value, "srv11.example.com.")
    }

    func testMsgDescription() {
        let msg = Msg(header: MsgHeader(id: 1234, response: true, recursionAvailable: true),
                      questions: [Question(Name("example.com."), .a)],
                      answers: [A(header: RRHeader(name: Name("example.com."), type: .a, ttl: 300),
                                  a: IPv4Address("192.0.2.1"))])
        let text = msg.description
        XCTAssertTrue(text.contains("QUESTION SECTION"))
        XCTAssertTrue(text.contains("ANSWER SECTION"))
        XCTAssertTrue(text.contains("192.0.2.1"))
        XCTAssertTrue(text.contains("qr"))
    }
}
