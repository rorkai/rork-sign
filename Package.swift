// swift-tools-version: 6.0

import PackageDescription

// Prefer native CryptoKit on Apple hosts to avoid linking Swift Crypto's
// compatibility product as a standalone framework.
#if canImport(CryptoKit)
let platformCryptoDependencies: [Target.Dependency] = [
    .product(name: "CryptoExtras", package: "swift-crypto"),
]
#else
let platformCryptoDependencies: [Target.Dependency] = [
    .product(name: "Crypto", package: "swift-crypto"),
    .product(name: "CryptoExtras", package: "swift-crypto"),
]
#endif

// New swift-log manifests track the Swift toolchain that introduced their
// package features. These ranges let each supported compiler select the newest
// source-compatible release it can evaluate.
#if compiler(>=6.2)
let swiftLog: Package.Dependency = .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0")
#elseif compiler(>=6.1)
let swiftLog: Package.Dependency = .package(url: "https://github.com/apple/swift-log.git", "1.6.0"..<"1.11.0")
#else
let swiftLog: Package.Dependency = .package(url: "https://github.com/apple/swift-log.git", "1.6.0"..<"1.10.0")
#endif

let package = Package(
    name: "rork-sign",
    platforms: [
        .macOS(.v13),
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "RorkSign",
            targets: ["RorkSign"]
        ),
        .library(
            name: "RorkSignObjC",
            targets: ["RorkSignObjC"]
        ),
        .executable(
            name: "rorksign",
            targets: ["RorkSignCLI"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
        swiftLog,
        .package(
            url: "https://github.com/rorkai/swift-zip-archive.git",
            revision: "89b8b71477f6764783ef4b3e47c6cc996d3bb7f0"
        ),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "RorkSign",
            dependencies: platformCryptoDependencies + [
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ZipArchive", package: "swift-zip-archive"),
            ],
            path: "Sources/RorkSign"
        ),
        .target(
            name: "RorkSignObjC",
            dependencies: [
                "RorkSign",
            ],
            path: "Sources/RorkSignObjC"
        ),
        .executableTarget(
            name: "RorkSignCLI",
            dependencies: [
                "RorkSign",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/RorkSignCLI"
        ),
        .testTarget(
            name: "RorkSignTests",
            dependencies: [
                "RorkSign",
                "RorkSignObjC",
                .product(name: "ZipArchive", package: "swift-zip-archive"),
            ],
            path: "Tests/RorkSignTests"
        ),
    ]
)
