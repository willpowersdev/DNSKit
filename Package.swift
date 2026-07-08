// swift-tools-version: 6.0
import PackageDescription
import CompilerPluginSupport

let package = Package(
    name: "SwiftDNS",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "DNSCore", targets: ["DNSCore"]),
        .library(name: "DNSTypes", targets: ["DNSTypes"]),
        .library(name: "DNSClient", targets: ["DNSClient"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-syntax.git", from: "600.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
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

        .testTarget(name: "DNSCoreTests", dependencies: ["DNSCore"]),
        .testTarget(name: "DNSTypesTests", dependencies: ["DNSTypes", "DNSCore"]),
        .testTarget(name: "DNSClientTests", dependencies: [
            "DNSClient", "DNSCore", "DNSTypes",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
        ]),
    ]
)
