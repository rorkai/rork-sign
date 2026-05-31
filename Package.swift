// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "rork-sign-swift",
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
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", from: "0.9.20"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "RorkSign",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
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
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
            ],
            path: "Sources/RorkSignCLI"
        ),
        .testTarget(
            name: "RorkSignTests",
            dependencies: [
                "RorkSign",
                "RorkSignObjC",
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
            ],
            path: "Tests/RorkSignTests"
        ),
    ]
)
