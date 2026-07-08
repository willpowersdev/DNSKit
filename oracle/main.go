// Command oracle emits golden wire-format vectors from the real miekg/dns
// library, for differential testing against the SwiftDNS port. Each record is
// packed with compression DISABLED so the bytes depend only on the per-type
// rdata codec (compression is unit-tested separately on the Swift side).
//
// Run: go run ./oracle > Tests/DNSTypesTests/oracle.json
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"

	"github.com/miekg/dns"
)

func hexOf(rr dns.RR) string {
	buf := make([]byte, 65535)
	off, err := dns.PackRR(rr, buf, 0, nil, false) // compress = false
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf[:off])
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func hx(b []byte) string  { return hex.EncodeToString(b) }

// seq returns bytes 0,1,2,...,n-1 (matches Swift's Array(0..<n)).
func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func main() {
	h := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: "example.com.", Rrtype: t, Class: dns.ClassINET, Ttl: 300}
	}
	out := map[string]string{}

	out["A"] = hexOf(&dns.A{Hdr: h(dns.TypeA), A: net.ParseIP("192.0.2.1")})
	out["AAAA"] = hexOf(&dns.AAAA{Hdr: h(dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::1")})
	out["MX"] = hexOf(&dns.MX{Hdr: h(dns.TypeMX), Preference: 10, Mx: "mail.example.com."})
	out["NS"] = hexOf(&dns.NS{Hdr: h(dns.TypeNS), Ns: "ns1.example.com."})
	out["CNAME"] = hexOf(&dns.CNAME{Hdr: h(dns.TypeCNAME), Target: "target.example.com."})
	out["SOA"] = hexOf(&dns.SOA{Hdr: h(dns.TypeSOA), Ns: "ns1.example.com.", Mbox: "hostmaster.example.com.",
		Serial: 2024010101, Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 3600})
	out["SRV"] = hexOf(&dns.SRV{Hdr: h(dns.TypeSRV), Priority: 1, Weight: 5, Port: 8080, Target: "svc.example.com."})
	out["TXT"] = hexOf(&dns.TXT{Hdr: h(dns.TypeTXT), Txt: []string{"hello", "world"}})
	out["HINFO"] = hexOf(&dns.HINFO{Hdr: h(dns.TypeHINFO), Cpu: "Intel", Os: "Linux"})
	out["NAPTR"] = hexOf(&dns.NAPTR{Hdr: h(dns.TypeNAPTR), Order: 100, Preference: 10,
		Flags: "U", Service: "E2U+sip", Regexp: "!^.*$!sip:x@y!", Replacement: "."})
	out["CAA"] = hexOf(&dns.CAA{Hdr: h(dns.TypeCAA), Flag: 0, Tag: "issue", Value: "letsencrypt.org"})
	out["URI"] = hexOf(&dns.URI{Hdr: h(dns.TypeURI), Priority: 10, Weight: 1, Target: "https://example.com/path"})
	out["LOC"] = hexOf(&dns.LOC{Hdr: h(dns.TypeLOC), Version: 0, Size: 0x33, HorizPre: 0x16, VertPre: 0x13,
		Latitude: 2147483648, Longitude: 2147483648, Altitude: 10000000})
	out["EUI48"] = hexOf(&dns.EUI48{Hdr: h(dns.TypeEUI48), Address: 0x001122334455})
	out["EUI64"] = hexOf(&dns.EUI64{Hdr: h(dns.TypeEUI64), Address: 0x0011223344556677})
	out["NID"] = hexOf(&dns.NID{Hdr: h(dns.TypeNID), Preference: 10, NodeID: 0xABCD123456789F00})
	out["L64"] = hexOf(&dns.L64{Hdr: h(dns.TypeL64), Preference: 10, Locator64: 0x0011223344556677})
	out["DS"] = hexOf(&dns.DS{Hdr: h(dns.TypeDS), KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: hx([]byte{0xAB, 0xCD, 0xEF})})
	out["DNSKEY"] = hexOf(&dns.DNSKEY{Hdr: h(dns.TypeDNSKEY), Flags: 256, Protocol: 3, Algorithm: 8, PublicKey: b64(seq(40))})
	out["RRSIG"] = hexOf(&dns.RRSIG{Hdr: h(dns.TypeRRSIG), TypeCovered: dns.TypeA, Algorithm: 8, Labels: 2,
		OrigTtl: 3600, Expiration: 1700000000, Inception: 1699000000, KeyTag: 54321,
		SignerName: "example.com.", Signature: b64(seq(64))})
	out["TLSA"] = hexOf(&dns.TLSA{Hdr: h(dns.TypeTLSA), Usage: 3, Selector: 1, MatchingType: 1, Certificate: hx(seq(32))})
	out["CERT"] = hexOf(&dns.CERT{Hdr: h(dns.TypeCERT), Type: 1, KeyTag: 1234, Algorithm: 8, Certificate: b64(seq(20))})
	out["NSEC"] = hexOf(&dns.NSEC{Hdr: h(dns.TypeNSEC), NextDomain: "next.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeMX, dns.TypeRRSIG, dns.TypeNSEC}})
	out["CSYNC"] = hexOf(&dns.CSYNC{Hdr: h(dns.TypeCSYNC), Serial: 66, Flags: 3,
		TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA}})
	out["TKEY"] = hexOf(&dns.TKEY{Hdr: h(dns.TypeTKEY), Algorithm: "hmac-sha256.", Inception: 1, Expiration: 2,
		Mode: 3, Error: 0, KeySize: 16, Key: hx(seq(16)), OtherLen: 2, OtherData: hx([]byte{0xFF, 0xEE})})

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
