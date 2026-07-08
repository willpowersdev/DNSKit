// swift-tools-version: 6.0
import PackageDescription
import CompilerPluginSupport

let package = Package(
    name: "SwiftDNS",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "DNSCore", targets: ["DNSCore"]),
        .library(name: "DNSTypes", targets: ["DNSTypes"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-syntax.git", from: "600.0.0"),
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

        .testTarget(name: "DNSCoreTests", dependencies: ["DNSCore"]),
        .testTarget(name: "DNSTypesTests", dependencies: ["DNSTypes", "DNSCore"]),
    ]
)
