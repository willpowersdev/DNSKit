// Command oracle emits golden wire-format vectors from the real miekg/dns
// library, for differential testing against the SwiftDNS port. Each record is
// packed with compression DISABLED so the bytes depend only on the per-type
// rdata codec (compression is unit-tested separately on the Swift side).
//
// Run: go run ./oracle > Tests/DNSTypesTests/oracle.json
package main

import (
	"crypto"
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

	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232, Ttl: 0x8000}}
	opt.Option = []dns.EDNS0{
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "aabb"},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0001020304050607"},
		&dns.EDNS0_EDE{InfoCode: 6, ExtraText: "bad"},
		&dns.EDNS0_PADDING{Padding: []byte{0, 0, 0, 0}},
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 0, Address: net.IP{192, 0, 2, 0}},
		&dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: 100},
		&dns.EDNS0_EXPIRE{Expire: 86400},
	}
	out["OPT"] = hexOf(opt)

	svcb := &dns.SVCB{Hdr: h(dns.TypeSVCB), Priority: 1, Target: "svc.example.com."}
	svcb.Value = []dns.SVCBKeyValue{
		&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_IPV4HINT}},
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 443},
		&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}},
		&dns.SVCBECHConfig{ECH: []byte{0xAB, 0xCD}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2001:db8::1")}},
		&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
		&dns.SVCBLocal{KeyCode: 65280, Data: []byte("xyz")},
	}
	out["SVCB"] = hexOf(svcb)

	https := &dns.HTTPS{SVCB: dns.SVCB{Hdr: h(dns.TypeHTTPS), Priority: 0, Target: "."}}
	https.Value = []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h3"}}}
	out["HTTPS"] = hexOf(https)

	writeJSON("Tests/DNSTypesTests/oracle.json", out)

	// Full messages: emit both compressed and uncompressed wire bytes. The
	// Swift side compares uncompressed bytes exactly (well-defined) and checks
	// that it can DECOMPRESS the compressed form (compression itself is
	// implementation-defined, so we don't require byte-identical compression).
	rh := func(name string, t uint16, ttl uint32) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
	}

	query := new(dns.Msg)
	query.Id = 0x1234
	query.RecursionDesired = true
	query.Question = []dns.Question{{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}

	resp := new(dns.Msg)
	resp.Id = 0x1234
	resp.Response = true
	resp.Authoritative = true
	resp.RecursionDesired = true
	resp.RecursionAvailable = true
	resp.Question = []dns.Question{{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	resp.Answer = []dns.RR{
		&dns.A{Hdr: rh("www.example.com.", dns.TypeA, 300), A: net.ParseIP("192.0.2.1")},
		&dns.A{Hdr: rh("www.example.com.", dns.TypeA, 300), A: net.ParseIP("192.0.2.2")},
	}
	resp.Ns = []dns.RR{
		&dns.NS{Hdr: rh("example.com.", dns.TypeNS, 3600), Ns: "ns1.example.com."},
		&dns.NS{Hdr: rh("example.com.", dns.TypeNS, 3600), Ns: "ns2.example.com."},
	}
	resp.Extra = []dns.RR{
		&dns.A{Hdr: rh("ns1.example.com.", dns.TypeA, 3600), A: net.ParseIP("192.0.2.53")},
	}

	msgs := map[string]map[string]string{
		"query":    packMsg(query),
		"response": packMsg(resp),
	}
	writeJSON("Tests/DNSTypesTests/oracle_messages.json", msgs)

	// Zone-file (presentation) lines: parse with miekg, pack uncompressed. The
	// Swift side parses the same line and must produce identical wire bytes.
	zoneLines := []string{
		"example.com. 3600 IN A 192.0.2.1",
		"example.com. 3600 IN AAAA 2001:db8::1",
		"example.com. 3600 IN NS ns1.example.com.",
		"example.com. 3600 IN CNAME target.example.com.",
		"example.com. 3600 IN PTR host.example.com.",
		"example.com. 3600 IN MX 10 mail.example.com.",
		"example.com. 3600 IN KX 10 kx.example.com.",
		`example.com. 3600 IN TXT "hello" "world"`,
		"example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600",
		"_sip._tcp.example.com. 3600 IN SRV 1 5 5060 sipserver.example.com.",
		`example.com. 3600 IN NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:x@y!" .`,
		`example.com. 3600 IN CAA 0 issue "letsencrypt.org"`,
		`example.com. 3600 IN HINFO "Intel" "Linux"`,
		"example.com. 3600 IN RP admin.example.com. txt.example.com.",
		"example.com. 3600 IN DS 12345 8 2 abcdef",
		"example.com. 3600 IN DNSKEY 256 3 8 AAECAwQFBgcICQoLDA0ODw==",
		"example.com. 3600 IN TLSA 3 1 1 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"example.com. 3600 IN SSHFP 1 1 00010203040506070809",
		"example.com. 3600 IN CERT 1 1234 8 AAECAwQFBgcICQoLDA0ODxAREhM=",
		"example.com. 3600 IN NSEC a.example.com. A MX RRSIG NSEC",
		"example.com. 3600 IN CSYNC 66 3 A NS AAAA",
	}
	type zoneVec struct {
		Line string `json:"line"`
		Hex  string `json:"hex"`
	}
	var zone []zoneVec
	for _, line := range zoneLines {
		rr, err := dns.NewRR(line)
		if err != nil {
			panic(err)
		}
		buf := make([]byte, 65535)
		off, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			panic(err)
		}
		zone = append(zone, zoneVec{Line: line, Hex: hex.EncodeToString(buf[:off])})
	}
	writeJSON("Tests/DNSTypesTests/oracle_zone.json", zone)

	// DNSSEC: generate a key per algorithm, sign an A RRset, and emit the
	// DNSKEY/RRSIG/RRset/DS wire bytes + key tag. The Swift side reconstructs
	// the signing data and VERIFIES miekg's signature (interop), and checks
	// the key tag and DS digest.
	type dnssecVec struct {
		Alg    uint8    `json:"alg"`
		Dnskey string   `json:"dnskey"`
		Rrsig  string   `json:"rrsig"`
		Rrset  []string `json:"rrset"`
		Ds     string   `json:"ds"`
		KeyTag uint16   `json:"keytag"`
	}
	algs := []struct {
		a    uint8
		bits int
	}{
		{dns.ECDSAP256SHA256, 256},
		{dns.ECDSAP384SHA384, 384},
		{dns.ED25519, 256},
		{dns.RSASHA256, 2048},
	}
	var dvecs []dnssecVec
	for _, ab := range algs {
		key := &dns.DNSKEY{Hdr: rh("example.com.", dns.TypeDNSKEY, 3600), Flags: 257, Protocol: 3, Algorithm: ab.a}
		priv, err := key.Generate(ab.bits)
		if err != nil {
			panic(err)
		}
		a1 := &dns.A{Hdr: rh("example.com.", dns.TypeA, 3600), A: net.ParseIP("192.0.2.1")}
		a2 := &dns.A{Hdr: rh("example.com.", dns.TypeA, 3600), A: net.ParseIP("192.0.2.2")}
		rrset := []dns.RR{a1, a2}
		sig := &dns.RRSIG{Hdr: rh("example.com.", dns.TypeRRSIG, 3600),
			TypeCovered: dns.TypeA, Algorithm: ab.a, Labels: 2, OrigTtl: 3600,
			Expiration: 1700000000, Inception: 1600000000, KeyTag: key.KeyTag(), SignerName: "example.com."}
		if err := sig.Sign(priv.(crypto.Signer), rrset); err != nil {
			panic(err)
		}
		ds := key.ToDS(dns.SHA256)
		dvecs = append(dvecs, dnssecVec{
			Alg: ab.a, Dnskey: hexOf(key), Rrsig: hexOf(sig),
			Rrset: []string{hexOf(a1), hexOf(a2)}, Ds: hexOf(ds), KeyTag: key.KeyTag(),
		})
	}
	// Name-bearing RRset (MX, with mixed-case target names) to exercise the
	// RFC 4034 §6.2 canonical-form lowercasing.
	mxKey := &dns.DNSKEY{Hdr: rh("example.com.", dns.TypeDNSKEY, 3600), Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	mxPriv, err := mxKey.Generate(256)
	if err != nil {
		panic(err)
	}
	mx1 := &dns.MX{Hdr: rh("example.com.", dns.TypeMX, 3600), Preference: 10, Mx: "Mail.EXAMPLE.com."}
	mx2 := &dns.MX{Hdr: rh("example.com.", dns.TypeMX, 3600), Preference: 20, Mx: "Backup.Example.COM."}
	mxSet := []dns.RR{mx1, mx2}
	mxSig := &dns.RRSIG{Hdr: rh("example.com.", dns.TypeRRSIG, 3600),
		TypeCovered: dns.TypeMX, Algorithm: dns.ECDSAP256SHA256, Labels: 2, OrigTtl: 3600,
		Expiration: 1700000000, Inception: 1600000000, KeyTag: mxKey.KeyTag(), SignerName: "example.com."}
	if err := mxSig.Sign(mxPriv.(crypto.Signer), mxSet); err != nil {
		panic(err)
	}
	dvecs = append(dvecs, dnssecVec{
		Alg: dns.ECDSAP256SHA256, Dnskey: hexOf(mxKey), Rrsig: hexOf(mxSig),
		Rrset: []string{hexOf(mx1), hexOf(mx2)}, Ds: hexOf(mxKey.ToDS(dns.SHA256)), KeyTag: mxKey.KeyTag(),
	})
	writeJSON("Tests/DNSSECTests/oracle_dnssec.json", dvecs)

	// TSIG: sign a query with miekg and emit the wire bytes + key.
	tmsg := new(dns.Msg)
	tmsg.Id = 0x1234
	tmsg.SetQuestion("example.com.", dns.TypeA)
	tsecret := seq(16)
	tmsg.SetTsig("test.key.", dns.HmacSHA256, 300, 1600000000)
	tsigWire, _, err := dns.TsigGenerate(tmsg, base64.StdEncoding.EncodeToString(tsecret), "", false)
	if err != nil {
		panic(err)
	}
	writeJSON("Tests/DNSSECTests/oracle_tsig.json", map[string]string{
		"keyName":   "test.key.",
		"algorithm": dns.HmacSHA256,
		"secretHex": hx(tsecret),
		"wire":      hex.EncodeToString(tsigWire),
	})

	// Dynamic UPDATE (RFC 2136): build with miekg, pack uncompressed. The Swift
	// DNSUpdate builder must produce identical bytes.
	upd := new(dns.Msg)
	upd.SetUpdate("example.com.")
	upd.Id = 0x1234
	upd.NameUsed([]dns.RR{&dns.A{Hdr: rh("must.example.com.", dns.TypeA, 0)}})
	upd.Insert([]dns.RR{&dns.A{Hdr: rh("host.example.com.", dns.TypeA, 3600), A: net.ParseIP("192.0.2.10")}})
	upd.RemoveRRset([]dns.RR{&dns.TXT{Hdr: rh("old.example.com.", dns.TypeTXT, 0)}})
	upd.RemoveName([]dns.RR{&dns.A{Hdr: rh("gone.example.com.", dns.TypeA, 0)}})
	upd.Compress = false
	updWire, err := upd.Pack()
	if err != nil {
		panic(err)
	}
	writeJSON("Tests/DNSTypesTests/oracle_update.json", map[string]string{
		"wire": hex.EncodeToString(updWire),
	})

	// NSEC3 hashing (RFC 5155): miekg's HashName returns the base32hex hash.
	nsec3 := dns.HashName("host.example.com.", dns.SHA1, 12, "aabbccdd")
	writeJSON("Tests/DNSSECTests/oracle_nsec3.json", map[string]string{
		"name":       "host.example.com.",
		"saltHex":    "aabbccdd",
		"iterations": "12",
		"hash":       nsec3, // base32hex, uppercase
	})
}

func packMsg(m *dns.Msg) map[string]string {
	m.Compress = false
	un, err := m.Pack()
	if err != nil {
		panic(err)
	}
	m.Compress = true
	co, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return map[string]string{
		"uncompressed": hex.EncodeToString(un),
		"compressed":   hex.EncodeToString(co),
	}
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}
