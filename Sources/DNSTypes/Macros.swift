/// Generates the rdata wire codec and a memberwise initializer for a record
/// struct. See ``DNSRecordMacro`` in the DNSMacros target.
@attached(member, names: named(init), named(packRdata), named(rdataPresentation), named(withLowercasedNames))
public macro DNSRecord() = #externalMacro(module: "DNSMacros", type: "DNSRecordMacro")

/// Marks a `Name` field as eligible for message compression (Go's `cdomain-name`).
@attached(peer)
public macro Compressed() = #externalMacro(module: "DNSMacros", type: "MarkerMacro")

/// Marks a `String` / `[UInt8]` field as the raw rest-of-rdata (Go's `octet` /
/// `any` / trailing `hex`/`base64`), i.e. no length prefix.
@attached(peer)
public macro Octet() = #externalMacro(module: "DNSMacros", type: "MarkerMacro")

/// Marks a `UInt64` field as a 6-octet (48-bit) integer (Go's `uint48`).
@attached(peer)
public macro UInt48() = #externalMacro(module: "DNSMacros", type: "MarkerMacro")

/// Marks a `[UInt8]` field as base64 in presentation format (else hex).
@attached(peer)
public macro Base64() = #externalMacro(module: "DNSMacros", type: "MarkerMacro")

/// Marks a `[UInt8]` field whose length comes from another (already-decoded)
/// numeric field, named by `field` (Go's `size-hex:` / `size-base64:` tags).
@attached(peer)
public macro SizePrefixed(_ field: String) = #externalMacro(module: "DNSMacros", type: "MarkerMacro")
