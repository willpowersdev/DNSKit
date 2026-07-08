/// Generates the rdata wire codec and a memberwise initializer for a record
/// struct. See ``DNSRecordMacro`` in the DNSMacros target.
@attached(member, names: named(init), named(packRdata))
public macro DNSRecord() = #externalMacro(module: "DNSMacros", type: "DNSRecordMacro")

/// Marks a `Name` field as eligible for message compression (Go's `cdomain-name`).
@attached(peer)
public macro Compressed() = #externalMacro(module: "DNSMacros", type: "CompressedMacro")
