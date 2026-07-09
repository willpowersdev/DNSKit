/// Errors that are not specific to wire parsing. In particular, operations that
/// depend on OS-specific facilities throw ``unsupportedPlatform`` on platforms
/// where they aren't available (see the conditional-compilation blocks in the
/// client). Wire-level failures use ``WireError`` instead.
public enum DNSError: Error, Sendable, Equatable {
    /// The requested operation isn't supported on the current platform.
    case unsupportedPlatform
}
