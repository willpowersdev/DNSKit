/// Append-only writer for DNS wire format, carrying the message-global name
/// compression table. Offsets used for compression are absolute from the start
/// of the message, matching the `compressionMap` in Go's `msg.go`.
public struct MessagePacker: Sendable {
    public private(set) var bytes: [UInt8] = []
    /// Maps lowercased presentation names to their absolute offset in `bytes`.
    private var compression: [String: Int] = [:]

    public init() {}

    public var count: Int { bytes.count }

    public mutating func appendUInt8(_ v: UInt8) { bytes.append(v) }

    public mutating func appendUInt16(_ v: UInt16) {
        bytes.append(UInt8(v >> 8)); bytes.append(UInt8(v & 0xff))
    }

    public mutating func appendUInt32(_ v: UInt32) {
        bytes.append(UInt8((v >> 24) & 0xff))
        bytes.append(UInt8((v >> 16) & 0xff))
        bytes.append(UInt8((v >> 8) & 0xff))
        bytes.append(UInt8(v & 0xff))
    }

    /// Writes a 48-bit big-endian integer (6 octets); used by EUI48 and TSIG.
    public mutating func appendUInt48(_ v: UInt64) {
        for shift in stride(from: 40, through: 0, by: -8) {
            bytes.append(UInt8((v >> UInt64(shift)) & 0xff))
        }
    }

    public mutating func appendUInt64(_ v: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8((v >> UInt64(shift)) & 0xff))
        }
    }

    public mutating func appendBytes(_ b: [UInt8]) { bytes.append(contentsOf: b) }

    /// Writes an NSEC/NSEC3/CSYNC type bitmap (RFC 4034 §4.1.2): window blocks
    /// of `(window, length, bitmap)` covering the given sorted type codes.
    public mutating func appendNSECBitmap(_ types: [UInt16]) {
        let sorted = types.sorted()
        var i = 0
        while i < sorted.count {
            let window = UInt8(sorted[i] >> 8)
            var block = [UInt8](repeating: 0, count: 32)
            var maxByte = -1
            while i < sorted.count, UInt8(sorted[i] >> 8) == window {
                let lo = Int(sorted[i] & 0xff)
                block[lo / 8] |= UInt8(0x80) >> (lo % 8)
                if lo / 8 > maxByte { maxByte = lo / 8 }
                i += 1
            }
            appendUInt8(window)
            appendUInt8(UInt8(maxByte + 1))
            appendBytes(Array(block[0...maxByte]))
        }
    }

    /// Writes a length-prefixed character-string (max 255 octets).
    public mutating func appendCharacterString(_ s: String) throws {
        let raw = Array(s.utf8)
        guard raw.count <= 255 else { throw WireError.characterStringTooLong(length: raw.count) }
        bytes.append(UInt8(raw.count))
        bytes.append(contentsOf: raw)
    }

    /// Writes a domain name, optionally using / populating the compression table.
    public mutating func appendName(_ name: Name, compress: Bool) throws {
        let labels = try name.labels()
        // Enforce the 255-octet wire limit (labels + length bytes + root).
        let wireLen = labels.reduce(1) { $0 + 1 + $1.count }
        guard wireLen <= 255 else { throw WireError.nameTooLong }

        var idx = 0
        while idx < labels.count {
            let suffix = Name.from(labels: Array(labels[idx...])).value.lowercased()
            if let ptr = compression[suffix] {
                bytes.append(UInt8(0xC0 | UInt8(ptr >> 8)))
                bytes.append(UInt8(ptr & 0xff))
                return
            }
            let here = bytes.count
            if compress && here <= 0x3FFF {
                compression[suffix] = here
            }
            let label = labels[idx]
            bytes.append(UInt8(label.count))
            bytes.append(contentsOf: label)
            idx += 1
        }
        bytes.append(0) // root terminator
    }

    /// Overwrites a previously reserved 2-byte slot (used to back-patch RDLENGTH).
    public mutating func patchUInt16(at offset: Int, _ v: UInt16) {
        bytes[offset] = UInt8(v >> 8)
        bytes[offset + 1] = UInt8(v & 0xff)
    }
}

/// Cursor-based reader for DNS wire format.
public struct MessageUnpacker: Sendable {
    public let bytes: [UInt8]
    public private(set) var offset: Int

    public init(_ bytes: [UInt8], offset: Int = 0) {
        self.bytes = bytes
        self.offset = offset
    }

    public var remaining: Int { bytes.count - offset }

    public mutating func readUInt8() throws -> UInt8 {
        guard offset < bytes.count else { throw WireError.bufferTooShort(needed: 1, available: remaining) }
        defer { offset += 1 }
        return bytes[offset]
    }

    public mutating func readUInt16() throws -> UInt16 {
        guard remaining >= 2 else { throw WireError.bufferTooShort(needed: 2, available: remaining) }
        let v = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        offset += 2
        return v
    }

    public mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else { throw WireError.bufferTooShort(needed: 4, available: remaining) }
        let v = UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16
              | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
        offset += 4
        return v
    }

    public mutating func readUInt48() throws -> UInt64 {
        guard remaining >= 6 else { throw WireError.bufferTooShort(needed: 6, available: remaining) }
        var v: UInt64 = 0
        for _ in 0..<6 { v = (v << 8) | UInt64(bytes[offset]); offset += 1 }
        return v
    }

    public mutating func readUInt64() throws -> UInt64 {
        guard remaining >= 8 else { throw WireError.bufferTooShort(needed: 8, available: remaining) }
        var v: UInt64 = 0
        for _ in 0..<8 { v = (v << 8) | UInt64(bytes[offset]); offset += 1 }
        return v
    }

    public mutating func readBytes(_ n: Int) throws -> [UInt8] {
        guard remaining >= n else { throw WireError.bufferTooShort(needed: n, available: remaining) }
        let slice = Array(bytes[offset..<offset + n])
        offset += n
        return slice
    }

    public mutating func readCharacterString() throws -> String {
        let len = Int(try readUInt8())
        let raw = try readBytes(len)
        return String(decoding: raw, as: UTF8.self)
    }

    /// Reads an NSEC-style type bitmap occupying the next `byteCount` octets.
    public mutating func readNSECBitmap(byteCount: Int) throws -> [UInt16] {
        let end = offset + byteCount
        guard end <= bytes.count else { throw WireError.bufferTooShort(needed: byteCount, available: remaining) }
        var types: [UInt16] = []
        while offset < end {
            let window = UInt16(try readUInt8())
            let length = Int(try readUInt8())
            guard length >= 1, length <= 32 else { throw WireError.malformedText("bad NSEC window length") }
            let block = try readBytes(length)
            for (bi, byte) in block.enumerated() {
                var mask: UInt8 = 0x80
                for bit in 0..<8 {
                    if byte & mask != 0 { types.append(window << 8 | UInt16(bi * 8 + bit)) }
                    mask >>= 1
                }
            }
        }
        return types
    }

    /// Reads a domain name, following compression pointers (which must point
    /// strictly backward to avoid loops).
    public mutating func readName() throws -> Name {
        var labels: [[UInt8]] = []
        var pos = offset
        var jumped = false
        var jumpBudget = 255

        while true {
            guard pos < bytes.count else {
                throw WireError.bufferTooShort(needed: 1, available: bytes.count - pos)
            }
            let len = Int(bytes[pos])
            if len == 0 {
                pos += 1
                if !jumped { offset = pos }
                break
            }
            if len & 0xC0 == 0xC0 {
                guard pos + 1 < bytes.count else {
                    throw WireError.bufferTooShort(needed: 2, available: bytes.count - pos)
                }
                let ptr = (len & 0x3F) << 8 | Int(bytes[pos + 1])
                if !jumped { offset = pos + 2; jumped = true }
                guard ptr < pos else { throw WireError.badCompressionPointer(offset: ptr) }
                pos = ptr
                jumpBudget -= 1
                guard jumpBudget > 0 else { throw WireError.badCompressionPointer(offset: ptr) }
                continue
            }
            guard len <= 63 else { throw WireError.labelTooLong(length: len) }
            let start = pos + 1
            guard start + len <= bytes.count else {
                throw WireError.bufferTooShort(needed: len, available: bytes.count - start)
            }
            labels.append(Array(bytes[start..<start + len]))
            pos = start + len
        }
        return Name.from(labels: labels)
    }
}
