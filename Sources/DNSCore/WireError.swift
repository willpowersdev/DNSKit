/// Errors raised while reading or writing DNS wire format.
///
/// Mirrors the error conditions in the Go implementation's `msg_helpers.go`
/// and `msg.go` (e.g. `ErrBuf`, `ErrRdata`, overflow / truncation checks).
public enum WireError: Error, Equatable, Sendable {
    /// Read past the end of the buffer / not enough bytes remaining.
    case bufferTooShort(needed: Int, available: Int)
    /// A domain name exceeded 255 octets or a label exceeded 63 octets.
    case nameTooLong
    case labelTooLong(length: Int)
    /// A compression pointer pointed forward or into a loop.
    case badCompressionPointer(offset: Int)
    /// A character-string exceeded 255 octets.
    case characterStringTooLong(length: Int)
    /// RDATA length in the header did not match the bytes actually consumed.
    case rdataLengthMismatch(declared: Int, consumed: Int)
    /// A value could not be represented in the target width.
    case valueOutOfRange
    /// Presentation-format text was malformed (used by the zone scanner later).
    case malformedText(String)
}
