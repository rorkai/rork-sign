// swift-tools-version: 6.3

import PackageDescription

// Prefer native CryptoKit on Apple hosts while making Swift Crypto available
// when the same manifest cross-compiles RorkSign for WASI.
#if canImport(CryptoKit)
let platformCryptoDependencies: [Target.Dependency] = [
    .product(name: "CryptoExtras", package: "swift-crypto"),
    .product(
        name: "Crypto",
        package: "swift-crypto",
        condition: .when(platforms: [.wasi])
    ),
]
#else
let platformCryptoDependencies: [Target.Dependency] = [
    .product(name: "Crypto", package: "swift-crypto"),
    .product(name: "CryptoExtras", package: "swift-crypto"),
]
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
        .library(
            name: "RorkSignWeb",
            targets: ["RorkSignWeb"]
        ),
        .executable(
            name: "rorksign",
            targets: ["RorkSignCLI"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/rorkai/swift-crypto.git",
            exact: "4.5.0-rork.1"
        ),
        .package(
            url: "https://github.com/apple/swift-log.git",
            from: "1.6.0"
        ),
        .package(
            url: "https://github.com/rorkai/swift-zip-archive.git",
            exact: "0.8.1-rork.3"
        ),
        .package(
            url: "https://github.com/apple/swift-argument-parser.git",
            from: "1.3.0"
        ),
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
        .target(
            name: "RorkSignWeb",
            dependencies: [
                "RorkSign",
            ]
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
                "RorkSignWeb",
                .product(name: "ZipArchive", package: "swift-zip-archive"),
            ],
            path: "Tests/RorkSignTests"
        ),
    ]
)
