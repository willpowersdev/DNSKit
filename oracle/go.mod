// Standalone module for the differential-test oracle. It fetches the upstream
// miekg/dns library (rather than depending on the in-repo Go sources, which
// have been replaced by the Swift port) and regenerates the golden vectors
// under ../Tests. Run with: cd oracle && go run .
module swiftdns-oracle

go 1.23

require github.com/miekg/dns v1.1.62

require (
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
)
