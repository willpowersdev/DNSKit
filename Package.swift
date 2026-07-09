// swift-tools-version: 6.0
import PackageDescription
import CompilerPluginSupport

let package = Package(
    name: "DNSKit",
    // Minimum Apple OS versions. Linux has no such floor and is supported too;
    // SwiftPM builds it whenever these platform constraints don't apply.
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        // A single umbrella product: consumers `import DNSKit`. The internal
        // modules below are implementation detail.
        .library(name: "DNSKit", targets: ["DNSKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-syntax.git", from: "600.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        // Pure wire primitives: buffers, names, addresses, errors. No dependencies.
        .target(name: "DNSCore"),

        // Compiler-plugin target holding the macro implementations that replace
        // Go's generated zmsg.go / ztypes.go / zduplicate.go.
        .macro(
            name: "DNSMacros",
            dependencies: [
                .product(name: "SwiftSyntax", package: "swift-syntax"),
                .product(name: "SwiftSyntaxMacros", package: "swift-syntax"),
                .product(name: "SwiftCompilerPlugin", package: "swift-syntax"),
            ]
        ),

        // The RR protocol and the record structs, annotated with @DNSRecord.
        .target(name: "DNSTypes", dependencies: ["DNSCore", "DNSMacros"]),

        // Async resolver over UDP/TCP on SwiftNIO.
        .target(name: "DNSClient", dependencies: [
            "DNSCore", "DNSTypes",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
        ]),

        // DNS server (handler + mux + UDP/TCP listeners) on SwiftNIO.
        .target(name: "DNSServer", dependencies: [
            "DNSCore", "DNSTypes",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
        ]),

        // DNSSEC: key tags, DS digests, RRSIG signing/verification.
        .target(name: "DNSSEC", dependencies: [
            "DNSCore", "DNSTypes",
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "_CryptoExtras", package: "swift-crypto"),
        ]),

        // Umbrella module: re-exports everything for a single `import DNSKit`.
        .target(name: "DNSKit", dependencies: ["DNSCore", "DNSTypes", "DNSClient", "DNSServer", "DNSSEC"]),

        .testTarget(name: "DNSKitTests", dependencies: ["DNSKit"]),
        .testTarget(name: "DNSCoreTests", dependencies: ["DNSCore"]),
        .testTarget(name: "DNSTypesTests", dependencies: ["DNSTypes", "DNSCore"]),
        .testTarget(name: "DNSClientTests", dependencies: [
            "DNSClient", "DNSCore", "DNSTypes",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
        ]),
        .testTarget(name: "DNSServerTests", dependencies: [
            "DNSServer", "DNSClient", "DNSCore", "DNSTypes",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
        ]),
        .testTarget(name: "DNSSECTests", dependencies: [
            "DNSSEC", "DNSCore", "DNSTypes",
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "_CryptoExtras", package: "swift-crypto"),
        ]),
    ]
)
