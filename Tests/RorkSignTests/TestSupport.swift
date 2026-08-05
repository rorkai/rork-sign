#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
import RorkSign
import XCTest

struct OpenSSLFixture {
    let directory: URL
    let identity: SigningIdentity
    let certificatePEM: String
    let privateKeyPEM: String
    let certificateURL: URL
    let privateKeyURL: URL

    /// Creates a temporary self-signed identity for cryptographic tests.
    ///
    /// - Parameter codeSigning: Adds digital-signature key usage and the code-signing
    ///   extended key usage when the identity will be passed to Apple's `codesign`.
    init(codeSigning: Bool = false) throws {
        let openssl = URL(fileURLWithPath: "/usr/bin/openssl")
        guard FileManager.default.fileExists(atPath: openssl.path) else {
            throw XCTSkip("OpenSSL is required for CMS verification.")
        }

        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        privateKeyURL = directory.appendingPathComponent("key.pem")
        certificateURL = directory.appendingPathComponent("cert.pem")
        var certificateArguments = [
            "req",
            "-x509",
            "-newkey", "rsa:2048",
            "-keyout", privateKeyURL.path,
            "-out", certificateURL.path,
            "-nodes",
            "-subj", "/CN=RorkSignTest/O=Rork Sign Tests",
            "-days", "1",
            "-sha256",
        ]
        if codeSigning {
            certificateArguments.append(contentsOf: [
                "-addext", "keyUsage=critical,digitalSignature",
                "-addext", "extendedKeyUsage=codeSigning",
            ])
        }
        try runCommand(openssl, arguments: certificateArguments)

        certificatePEM = try String(contentsOf: certificateURL, encoding: .utf8)
        privateKeyPEM = try String(contentsOf: privateKeyURL, encoding: .utf8)
        identity = try SigningIdentity(certificatePEM: certificatePEM, privateKeyPEM: privateKeyPEM)
    }

    func pkcs12(password: String, useAES: Bool, additionalCertificateURL: URL? = nil) throws -> Data {
        try pkcs12(
            password: password,
            keyPBE: useAES ? "AES-256-CBC" : nil,
            certPBE: useAES ? "AES-256-CBC" : nil,
            additionalCertificateURL: additionalCertificateURL
        )
    }

    func pkcs12(
        password: String,
        keyPBE: String?,
        certPBE: String? = nil,
        additionalCertificateURL: URL? = nil,
        legacyProvider: Bool = false,
        opensslURL: URL = URL(fileURLWithPath: "/usr/bin/openssl")
    ) throws -> Data {
        let pkcs12URL = directory.appendingPathComponent(UUID().uuidString + ".p12")
        var arguments = [
            "pkcs12",
            "-export",
            "-inkey", privateKeyURL.path,
            "-in", certificateURL.path,
            "-out", pkcs12URL.path,
            "-password", "pass:\(password)",
        ]
        if legacyProvider {
            arguments.append("-legacy")
        }
        if let additionalCertificateURL {
            arguments.append(contentsOf: [
                "-certfile", additionalCertificateURL.path,
            ])
        }
        if let keyPBE {
            arguments.append(contentsOf: [
                "-keypbe", keyPBE,
            ])
        }
        if let certPBE {
            arguments.append(contentsOf: [
                "-certpbe", certPBE,
            ])
        }
        try runCommand(opensslURL, arguments: arguments)
        return try Data(contentsOf: pkcs12URL)
    }

    func encryptedPrivateKeyPEM(password: String) throws -> String {
        let encryptedKeyURL = directory.appendingPathComponent(UUID().uuidString + "-encrypted-key.pem")
        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: [
                "pkcs8",
                "-topk8",
                "-in", privateKeyURL.path,
                "-out", encryptedKeyURL.path,
                "-v2", "aes-256-cbc",
                "-passout", "pass:\(password)",
            ]
        )
        return try String(contentsOf: encryptedKeyURL, encoding: .utf8)
    }

    func encryptedPrivateKeyDER(password: String) throws -> Data {
        let encryptedKeyURL = directory.appendingPathComponent(UUID().uuidString + "-encrypted-key.der")
        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: [
                "pkcs8",
                "-topk8",
                "-in", privateKeyURL.path,
                "-outform", "DER",
                "-out", encryptedKeyURL.path,
                "-v2", "aes-256-cbc",
                "-passout", "pass:\(password)",
            ]
        )
        return try Data(contentsOf: encryptedKeyURL)
    }

    func traditionalEncryptedPrivateKeyPEM(password: String, cipher: TraditionalPEMCipher) throws -> String {
        let encryptedKeyURL = directory.appendingPathComponent(UUID().uuidString + "-traditional-key.pem")
        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: [
                "rsa",
                "-in", privateKeyURL.path,
                cipher.opensslFlag,
                "-out", encryptedKeyURL.path,
                "-passout", "pass:\(password)",
            ]
        )
        return try String(contentsOf: encryptedKeyURL, encoding: .utf8)
    }

    func selfSignedCertificate(commonName: String) throws -> (url: URL, der: Data) {
        try selfSignedCertificate(
            commonName: commonName,
            ocspResponderURL: nil,
            crlDistributionPointURL: nil
        )
    }

    func selfSignedCertificate(
        commonName: String,
        ocspResponderURL: String?
    ) throws -> (url: URL, der: Data) {
        try selfSignedCertificate(
            commonName: commonName,
            ocspResponderURL: ocspResponderURL,
            crlDistributionPointURL: nil
        )
    }

    func selfSignedCertificate(
        commonName: String,
        ocspResponderURL: String?,
        crlDistributionPointURL: String?
    ) throws -> (url: URL, der: Data) {
        let privateKeyURL = directory.appendingPathComponent(UUID().uuidString + "-key.pem")
        let certificateURL = directory.appendingPathComponent(UUID().uuidString + "-cert.pem")
        let certificateDERURL = directory.appendingPathComponent(UUID().uuidString + "-cert.der")
        var requestArguments = [
            "req",
            "-x509",
            "-newkey", "rsa:2048",
            "-keyout", privateKeyURL.path,
            "-out", certificateURL.path,
            "-nodes",
            "-subj", "/CN=\(commonName)",
            "-days", "1",
            "-sha256",
        ]
        if let ocspResponderURL {
            requestArguments.append(contentsOf: [
                "-addext", "authorityInfoAccess=OCSP;URI:\(ocspResponderURL)",
            ])
        }
        if let crlDistributionPointURL {
            requestArguments.append(contentsOf: [
                "-addext", "crlDistributionPoints=URI:\(crlDistributionPointURL)",
            ])
        }
        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: requestArguments
        )
        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: [
                "x509",
                "-in", certificateURL.path,
                "-outform", "DER",
                "-out", certificateDERURL.path,
            ]
        )
        return (certificateURL, try Data(contentsOf: certificateDERURL))
    }

    func verifyDetachedCMS(_ cms: Data, content: Data) throws {
        let cmsURL = directory.appendingPathComponent(UUID().uuidString + ".cms")
        let contentURL = directory.appendingPathComponent(UUID().uuidString + ".content")
        let outputURL = directory.appendingPathComponent(UUID().uuidString + ".out")
        try cms.write(to: cmsURL)
        try content.write(to: contentURL)

        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: [
                "cms",
                "-verify",
                "-inform", "DER",
                "-in", cmsURL.path,
                "-content", contentURL.path,
                "-noverify",
                "-binary",
                "-out", outputURL.path,
            ]
        )
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}

struct OpenSSLCertificateChainFixture {
    let directory: URL
    let issuerCertificateURL: URL
    let issuerPrivateKeyURL: URL
    let leafCertificateURL: URL
    let leafPrivateKeyURL: URL
    let chainPEM: String

    init(
        issuerExtensions: [String] = ["basicConstraints=critical,CA:TRUE"],
        leafExtensions: [String] = [
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=digitalSignature",
        ]
    ) throws {
        let openssl = URL(fileURLWithPath: "/usr/bin/openssl")
        guard FileManager.default.fileExists(atPath: openssl.path) else {
            throw XCTSkip("OpenSSL is required for certificate-chain fixtures.")
        }

        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        issuerPrivateKeyURL = directory.appendingPathComponent("issuer-key.pem")
        issuerCertificateURL = directory.appendingPathComponent("issuer-cert.pem")
        leafPrivateKeyURL = directory.appendingPathComponent("leaf-key.pem")
        let leafCSRURL = directory.appendingPathComponent("leaf.csr")
        leafCertificateURL = directory.appendingPathComponent("leaf-cert.pem")
        let leafExtensionsURL = directory.appendingPathComponent("leaf.ext")

        var issuerArguments = [
            "req",
            "-x509",
            "-newkey", "rsa:2048",
            "-keyout", issuerPrivateKeyURL.path,
            "-out", issuerCertificateURL.path,
            "-nodes",
            "-subj", "/CN=RorkSignChainRoot/O=Rork Sign Tests",
            "-days", "1",
            "-sha256",
        ]
        for ext in issuerExtensions {
            issuerArguments.append(contentsOf: ["-addext", ext])
        }
        try runCommand(openssl, arguments: issuerArguments)
        try runCommand(
            openssl,
            arguments: [
                "req",
                "-newkey", "rsa:2048",
                "-keyout", leafPrivateKeyURL.path,
                "-out", leafCSRURL.path,
                "-nodes",
                "-subj", "/CN=RorkSignChainLeaf/O=Rork Sign Tests",
                "-sha256",
            ]
        )
        try Data((leafExtensions.joined(separator: "\n") + "\n").utf8).write(to: leafExtensionsURL)
        try runCommand(
            openssl,
            arguments: [
                "x509",
                "-req",
                "-in", leafCSRURL.path,
                "-CA", issuerCertificateURL.path,
                "-CAkey", issuerPrivateKeyURL.path,
                "-CAcreateserial",
                "-out", leafCertificateURL.path,
                "-days", "1",
                "-sha256",
                "-extfile", leafExtensionsURL.path,
            ]
        )

        chainPEM = try String(contentsOf: leafCertificateURL, encoding: .utf8)
            + "\n"
            + String(contentsOf: issuerCertificateURL, encoding: .utf8)
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}

struct OpenSSLThreeLevelCertificateChainFixture {
    let directory: URL
    let rootCertificateURL: URL
    let rootPrivateKeyURL: URL
    let intermediateCertificateURL: URL
    let intermediatePrivateKeyURL: URL
    let leafCertificateURL: URL
    let leafPrivateKeyURL: URL
    let chainPEM: String

    init(
        rootExtensions: [String] = [
            "basicConstraints=critical,CA:TRUE,pathlen:1",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        intermediateExtensions: [String] = [
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        leafExtensions: [String] = [
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature",
        ]
    ) throws {
        let openssl = URL(fileURLWithPath: "/usr/bin/openssl")
        guard FileManager.default.fileExists(atPath: openssl.path) else {
            throw XCTSkip("OpenSSL is required for certificate-chain fixtures.")
        }

        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        rootPrivateKeyURL = directory.appendingPathComponent("root-key.pem")
        rootCertificateURL = directory.appendingPathComponent("root-cert.pem")
        intermediatePrivateKeyURL = directory.appendingPathComponent("intermediate-key.pem")
        intermediateCertificateURL = directory.appendingPathComponent("intermediate-cert.pem")
        leafPrivateKeyURL = directory.appendingPathComponent("leaf-key.pem")
        leafCertificateURL = directory.appendingPathComponent("leaf-cert.pem")

        let intermediateCSRURL = directory.appendingPathComponent("intermediate.csr")
        let intermediateExtensionsURL = directory.appendingPathComponent("intermediate.ext")
        let leafCSRURL = directory.appendingPathComponent("leaf.csr")
        let leafExtensionsURL = directory.appendingPathComponent("leaf.ext")

        var rootArguments = [
            "req",
            "-x509",
            "-newkey", "rsa:2048",
            "-keyout", rootPrivateKeyURL.path,
            "-out", rootCertificateURL.path,
            "-nodes",
            "-subj", "/CN=RorkSignPathRoot/O=Rork Sign Tests",
            "-days", "1",
            "-sha256",
        ]
        for ext in rootExtensions {
            rootArguments.append(contentsOf: ["-addext", ext])
        }
        try runCommand(openssl, arguments: rootArguments)

        try runCommand(
            openssl,
            arguments: [
                "req",
                "-newkey", "rsa:2048",
                "-keyout", intermediatePrivateKeyURL.path,
                "-out", intermediateCSRURL.path,
                "-nodes",
                "-subj", "/CN=RorkSignPathIntermediate/O=Rork Sign Tests",
                "-sha256",
            ]
        )
        try Data((intermediateExtensions.joined(separator: "\n") + "\n").utf8)
            .write(to: intermediateExtensionsURL)
        try runCommand(
            openssl,
            arguments: [
                "x509",
                "-req",
                "-in", intermediateCSRURL.path,
                "-CA", rootCertificateURL.path,
                "-CAkey", rootPrivateKeyURL.path,
                "-CAcreateserial",
                "-out", intermediateCertificateURL.path,
                "-days", "1",
                "-sha256",
                "-extfile", intermediateExtensionsURL.path,
            ]
        )

        try runCommand(
            openssl,
            arguments: [
                "req",
                "-newkey", "rsa:2048",
                "-keyout", leafPrivateKeyURL.path,
                "-out", leafCSRURL.path,
                "-nodes",
                "-subj", "/CN=RorkSignPathLeaf/O=Rork Sign Tests",
                "-sha256",
            ]
        )
        try Data((leafExtensions.joined(separator: "\n") + "\n").utf8).write(to: leafExtensionsURL)
        try runCommand(
            openssl,
            arguments: [
                "x509",
                "-req",
                "-in", leafCSRURL.path,
                "-CA", intermediateCertificateURL.path,
                "-CAkey", intermediatePrivateKeyURL.path,
                "-CAcreateserial",
                "-out", leafCertificateURL.path,
                "-days", "1",
                "-sha256",
                "-extfile", leafExtensionsURL.path,
            ]
        )

        chainPEM = try String(contentsOf: leafCertificateURL, encoding: .utf8)
            + "\n"
            + String(contentsOf: intermediateCertificateURL, encoding: .utf8)
            + "\n"
            + String(contentsOf: rootCertificateURL, encoding: .utf8)
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}

struct OpenSSLECFixture {
    let directory: URL
    let identity: SigningIdentity
    let certificatePEM: String
    let privateKeyPEM: String
    let certificateURL: URL
    let privateKeyURL: URL
    let curve: OpenSSLECCurve

    init(curve: OpenSSLECCurve = .p256) throws {
        let openssl = URL(fileURLWithPath: "/usr/bin/openssl")
        guard FileManager.default.fileExists(atPath: openssl.path) else {
            throw XCTSkip("OpenSSL is required for CMS verification.")
        }

        self.curve = curve
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        privateKeyURL = directory.appendingPathComponent("ec-key.pem")
        certificateURL = directory.appendingPathComponent("ec-cert.pem")
        try runCommand(
            openssl,
            arguments: [
                "ecparam",
                "-name", curve.opensslName,
                "-genkey",
                "-noout",
                "-out", privateKeyURL.path,
            ]
        )
        try runCommand(
            openssl,
            arguments: [
                "req",
                "-x509",
                "-new",
                "-key", privateKeyURL.path,
                "-out", certificateURL.path,
                "-subj", "/CN=\(curve.commonName)/O=Rork Sign Tests",
                "-days", "1",
                "-sha256",
            ]
        )

        certificatePEM = try String(contentsOf: certificateURL, encoding: .utf8)
        privateKeyPEM = try String(contentsOf: privateKeyURL, encoding: .utf8)
        identity = try SigningIdentity(certificatePEM: certificatePEM, privateKeyPEM: privateKeyPEM)
    }

    func pkcs12(password: String) throws -> Data {
        let pkcs12URL = directory.appendingPathComponent(UUID().uuidString + ".p12")
        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: [
                "pkcs12",
                "-export",
                "-inkey", privateKeyURL.path,
                "-in", certificateURL.path,
                "-out", pkcs12URL.path,
                "-password", "pass:\(password)",
            ]
        )
        return try Data(contentsOf: pkcs12URL)
    }

    func verifyDetachedCMS(_ cms: Data, content: Data) throws {
        let cmsURL = directory.appendingPathComponent(UUID().uuidString + ".cms")
        let contentURL = directory.appendingPathComponent(UUID().uuidString + ".content")
        let outputURL = directory.appendingPathComponent(UUID().uuidString + ".out")
        try cms.write(to: cmsURL)
        try content.write(to: contentURL)

        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: [
                "cms",
                "-verify",
                "-inform", "DER",
                "-in", cmsURL.path,
                "-content", contentURL.path,
                "-noverify",
                "-binary",
                "-out", outputURL.path,
            ]
        )
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}

enum OpenSSLECCurve {
    case p256
    case p384
    case p521

    var opensslName: String {
        switch self {
        case .p256:
            return "prime256v1"
        case .p384:
            return "secp384r1"
        case .p521:
            return "secp521r1"
        }
    }

    var commonName: String {
        switch self {
        case .p256:
            return "RorkSignECTestP256"
        case .p384:
            return "RorkSignECTestP384"
        case .p521:
            return "RorkSignECTestP521"
        }
    }

    var keyAlgorithm: String {
        switch self {
        case .p256:
            return "EC P-256"
        case .p384:
            return "EC P-384"
        case .p521:
            return "EC P-521"
        }
    }
}

enum TraditionalPEMCipher {
    case aes256CBC
    case tripleDESCBC
    case desCBC

    var opensslFlag: String {
        switch self {
        case .aes256CBC:
            return "-aes256"
        case .tripleDESCBC:
            return "-des3"
        case .desCBC:
            return "-des"
        }
    }
}

struct CLIResult {
    let status: Int32
    let output: String
}

func runRorkSign(
    _ arguments: [String],
    environment: [String: String] = [:],
    currentDirectoryURL: URL? = nil
) throws -> CLIResult {
    let process = Process()
    process.executableURL = try rorkSignExecutableURL()
    process.arguments = arguments
    process.currentDirectoryURL = currentDirectoryURL
    if !environment.isEmpty {
        process.environment = ProcessInfo.processInfo.environment.merging(
            environment
        ) { _, new in new }
    }

    let output = Pipe()
    process.standardOutput = output
    process.standardError = output
    try process.run()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return CLIResult(
        status: process.terminationStatus,
        output: String(decoding: data, as: UTF8.self)
    )
}

func rorkSignExecutableURL() throws -> URL {
    if let override = ProcessInfo.processInfo.environment[
        "RORKSIGN_TEST_EXECUTABLE"
    ] {
        let overrideURL = URL(fileURLWithPath: override)
        guard isRunnableRorkSignExecutable(overrideURL) else {
            throw XCTSkip(
                "RORKSIGN_TEST_EXECUTABLE is not runnable at \(override)."
            )
        }
        return overrideURL
    }

    #if os(Windows)
    let executableName = "rorksign.exe"
    #else
    let executableName = "rorksign"
    #endif

    let currentDirectoryURL = URL(
        fileURLWithPath: FileManager.default.currentDirectoryPath,
        isDirectory: true
    )
    let buildDirectoryURL = currentDirectoryURL.appendingPathComponent(
        ".build",
        isDirectory: true
    )
    var candidates = [
        URL(fileURLWithPath: CommandLine.arguments[0])
            .deletingLastPathComponent()
            .appendingPathComponent(executableName),
        buildDirectoryURL
            .appendingPathComponent("debug", isDirectory: true)
            .appendingPathComponent(executableName),
    ]
    if let buildDirectories = try? FileManager.default.contentsOfDirectory(
        at: buildDirectoryURL,
        includingPropertiesForKeys: nil
    ) {
        candidates.append(
            contentsOf: buildDirectories.map {
                $0.appendingPathComponent("debug", isDirectory: true)
                    .appendingPathComponent(executableName)
            }
        )
    }

    for candidate in candidates {
        if isRunnableRorkSignExecutable(candidate) {
            return candidate
        }
    }

    throw XCTSkip(
        "rorksign executable was not found beside the tests or in .build."
    )
}

private func isRunnableRorkSignExecutable(_ url: URL) -> Bool {
    #if os(Windows)
    FileManager.default.fileExists(atPath: url.path)
    #else
    FileManager.default.isExecutableFile(atPath: url.path)
    #endif
}

func runCommand(_ executableURL: URL, arguments: [String]) throws {
    let process = Process()
    process.executableURL = executableURL
    process.arguments = arguments

    let output = Pipe()
    process.standardOutput = output
    process.standardError = output
    try process.run()
    process.waitUntilExit()

    guard process.terminationStatus == 0 else {
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let message = String(decoding: data, as: UTF8.self)
        XCTFail("Command failed: \(executableURL.path) \(arguments.joined(separator: " "))\n\(message)")
        throw RorkSignError.cmsSigning("External command failed.")
    }
}

enum Fixtures {
    static func machO64WithCodeSignature() -> Data {
        var data = Data(repeating: 0, count: 0x140)
        data.writeUInt32LE(0xfeedfacf, at: 0)
        data.writeUInt32LE(0x0100000c, at: 4)
        data.writeUInt32LE(0, at: 8)
        data.writeUInt32LE(2, at: 12)
        data.writeUInt32LE(1, at: 16)
        data.writeUInt32LE(16, at: 20)
        data.writeUInt32LE(0, at: 24)
        data.writeUInt32LE(0, at: 28)

        data.writeUInt32LE(0x1d, at: 32)
        data.writeUInt32LE(16, at: 36)
        data.writeUInt32LE(0x100, at: 40)
        data.writeUInt32LE(0x40, at: 44)
        return data
    }

    static func machO64DylibWithCodeSignature() -> Data {
        var data = machO64WithCodeSignature()
        data.writeUInt32LE(6, at: 12)
        return data
    }

    static func machO64WithoutCodeSignatureButWithLoadCommandSpace() -> Data {
        var data = Data(repeating: 0, count: 0x130)
        data.writeUInt32LE(0xfeedfacf, at: 0)
        data.writeUInt32LE(0x0100000c, at: 4)
        data.writeUInt32LE(0, at: 8)
        data.writeUInt32LE(2, at: 12)
        data.writeUInt32LE(1, at: 16)
        data.writeUInt32LE(152, at: 20)
        data.writeUInt32LE(0, at: 24)
        data.writeUInt32LE(0, at: 28)

        data.writeUInt32LE(0x19, at: 32)
        data.writeUInt32LE(152, at: 36)
        data.writeFixedString("__TEXT", at: 40, count: 16)
        data.writeUInt64LE(0, at: 56)
        data.writeUInt64LE(0x1000, at: 64)
        data.writeUInt64LE(0, at: 72)
        data.writeUInt64LE(0x130, at: 80)
        data.writeUInt32LE(7, at: 88)
        data.writeUInt32LE(5, at: 92)
        data.writeUInt32LE(1, at: 96)
        data.writeUInt32LE(0, at: 100)

        data.writeFixedString("__text", at: 104, count: 16)
        data.writeFixedString("__TEXT", at: 120, count: 16)
        data.writeUInt64LE(0, at: 136)
        data.writeUInt64LE(0x20, at: 144)
        data.writeUInt32LE(0x100, at: 152)
        data.writeUInt32LE(2, at: 156)
        data.writeUInt32LE(0, at: 160)
        data.writeUInt32LE(0, at: 164)
        data.writeUInt32LE(0x80000400, at: 168)
        return data
    }

    static func machO64WithEmbeddedInfoPlistSection() -> Data {
        let embeddedInfoPlist = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>CFBundleIdentifier</key><string>app.rork.embedded-info</string></dict></plist>
        """.utf8)
        let infoOffset = 0x180
        let signatureOffset = 0x400
        var data = Data(repeating: 0, count: 0x440)
        data.writeUInt32LE(0xfeedfacf, at: 0)
        data.writeUInt32LE(0x0100000c, at: 4)
        data.writeUInt32LE(0, at: 8)
        data.writeUInt32LE(2, at: 12)
        data.writeUInt32LE(2, at: 16)
        data.writeUInt32LE(168, at: 20)
        data.writeUInt32LE(0, at: 24)
        data.writeUInt32LE(0, at: 28)

        data.writeUInt32LE(0x19, at: 32)
        data.writeUInt32LE(152, at: 36)
        data.writeFixedString("__TEXT", at: 40, count: 16)
        data.writeUInt64LE(0, at: 56)
        data.writeUInt64LE(0x4000, at: 64)
        data.writeUInt64LE(0, at: 72)
        data.writeUInt64LE(UInt64(signatureOffset), at: 80)
        data.writeUInt32LE(7, at: 88)
        data.writeUInt32LE(5, at: 92)
        data.writeUInt32LE(1, at: 96)
        data.writeUInt32LE(0, at: 100)

        data.writeFixedString("__info_plist", at: 104, count: 16)
        data.writeFixedString("__TEXT", at: 120, count: 16)
        data.writeUInt64LE(0, at: 136)
        data.writeUInt64LE(UInt64(embeddedInfoPlist.count), at: 144)
        data.writeUInt32LE(UInt32(infoOffset), at: 152)
        data.writeUInt32LE(0, at: 156)
        data.writeUInt32LE(0, at: 160)
        data.writeUInt32LE(0, at: 164)
        data.writeUInt32LE(0, at: 168)

        data.writeUInt32LE(0x1d, at: 184)
        data.writeUInt32LE(16, at: 188)
        data.writeUInt32LE(UInt32(signatureOffset), at: 192)
        data.writeUInt32LE(0x40, at: 196)
        data.replaceSubrange(infoOffset..<(infoOffset + embeddedInfoPlist.count), with: embeddedInfoPlist)
        return data
    }

    static func universalMachOHeader(architectureCount: UInt32) -> Data {
        var data = Data(repeating: 0, count: 8 + Int(architectureCount) * 20)
        data.writeUInt32BE(0xcafebabe, at: 0)
        data.writeUInt32BE(architectureCount, at: 4)
        return data
    }

    static func universalMachOWithTwoThinSlices() -> Data {
        let firstSlice = machO64WithCodeSignature()
        var secondSlice = machO64WithCodeSignature()
        secondSlice.writeUInt32LE(0x01000007, at: 4)

        let firstOffset = 0x1000
        let secondOffset = 0x2000
        var data = Data(repeating: 0, count: secondOffset + secondSlice.count)
        data.writeUInt32BE(0xcafebabe, at: 0)
        data.writeUInt32BE(2, at: 4)

        data.writeUInt32BE(0x0100000c, at: 8)
        data.writeUInt32BE(0, at: 12)
        data.writeUInt32BE(UInt32(firstOffset), at: 16)
        data.writeUInt32BE(UInt32(firstSlice.count), at: 20)
        data.writeUInt32BE(12, at: 24)

        data.writeUInt32BE(0x01000007, at: 28)
        data.writeUInt32BE(3, at: 32)
        data.writeUInt32BE(UInt32(secondOffset), at: 36)
        data.writeUInt32BE(UInt32(secondSlice.count), at: 40)
        data.writeUInt32BE(12, at: 44)

        data.replaceSubrange(firstOffset..<(firstOffset + firstSlice.count), with: firstSlice)
        data.replaceSubrange(secondOffset..<(secondOffset + secondSlice.count), with: secondSlice)
        return data
    }
}

func signatureBlobs(in signed: Data) throws -> [UInt32: Data] {
    let info = try RorkSigner.inspectMachO(signed)
    let signatureOffset = Int(info.codeSignatureOffset)
    let count = Int(signed.readUInt32BE(at: signatureOffset + 8))
    var blobs: [UInt32: Data] = [:]

    for index in 0..<count {
        let indexOffset = signatureOffset + 12 + index * 8
        let slot = signed.readUInt32BE(at: indexOffset)
        let blobOffset = signatureOffset + Int(signed.readUInt32BE(at: indexOffset + 4))
        let blobLength = Int(signed.readUInt32BE(at: blobOffset + 4))
        blobs[slot] = signed.subdata(in: blobOffset..<(blobOffset + blobLength))
    }
    return blobs
}

func flipByte(in data: inout Data, at offset: Int) {
    data[offset] = data[offset] ^ 0xff
}

func flipByteInSignatureSlot(
    _ slotToMutate: UInt32,
    in signed: inout Data,
    byteOffsetInBlob: Int
) throws {
    let info = try RorkSigner.inspectMachO(signed)
    let signatureOffset = Int(info.codeSignatureOffset)
    let count = Int(signed.readUInt32BE(at: signatureOffset + 8))

    for index in 0..<count {
        let indexOffset = signatureOffset + 12 + index * 8
        let slot = signed.readUInt32BE(at: indexOffset)
        let blobOffset = signatureOffset + Int(signed.readUInt32BE(at: indexOffset + 4))
        let blobLength = Int(signed.readUInt32BE(at: blobOffset + 4))
        guard slot == slotToMutate else {
            continue
        }

        let mutationOffset = blobOffset + byteOffsetInBlob
        guard mutationOffset < blobOffset + blobLength else {
            throw RorkSignError.invalidMachO("Test mutation offset is outside the signature slot.")
        }
        flipByte(in: &signed, at: mutationOffset)
        return
    }

    throw RorkSignError.invalidMachO("Test signature slot was not found.")
}

func universalThinSlices(in data: Data) throws -> [Data] {
    guard data.count >= 8, data.readUInt32BE(at: 0) == 0xcafebabe else {
        throw RorkSignError.invalidMachO("Test fixture is not a 32-bit universal Mach-O.")
    }

    let count = data.readUInt32BE(at: 4)
    var slices: [Data] = []
    for index in 0..<Int(count) {
        let recordOffset = 8 + index * 20
        guard data.count >= recordOffset + 20 else {
            throw RorkSignError.invalidMachO("Universal test fixture architecture table is truncated.")
        }
        let sliceOffset = Int(data.readUInt32BE(at: recordOffset + 8))
        let sliceSize = Int(data.readUInt32BE(at: recordOffset + 12))
        guard sliceOffset >= 0,
              sliceSize >= 0,
              sliceOffset <= data.count,
              sliceSize <= data.count - sliceOffset else {
            throw RorkSignError.invalidMachO("Universal test fixture slice is outside the file.")
        }
        slices.append(data.subdata(in: sliceOffset..<(sliceOffset + sliceSize)))
    }
    return slices
}

func specialSlotHash(_ slot: UInt32, in codeDirectory: Data) -> Data? {
    let hashOffset = Int(codeDirectory.readUInt32BE(at: 16))
    let specialSlots = Int(codeDirectory.readUInt32BE(at: 24))
    let hashSize = Int(codeDirectory[36])
    guard slot > 0, Int(slot) <= specialSlots else {
        return nil
    }

    let slotOffset = hashOffset - specialSlots * hashSize + (specialSlots - Int(slot)) * hashSize
    return codeDirectory.subdata(in: slotOffset..<(slotOffset + hashSize))
}

func nullTerminatedString(in data: Data, offset: Int) -> String {
    guard offset >= 0, offset < data.count else {
        return ""
    }
    let end = data[offset..<data.count].firstIndex(of: 0) ?? data.count
    return String(decoding: data[offset..<end], as: UTF8.self)
}

func parseCodeResources(_ data: Data) throws -> [String: Any] {
    let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    return try XCTUnwrap(plist as? [String: Any])
}

func sha1(_ string: String) -> Data {
    Data(Insecure.SHA1.hash(data: Data(string.utf8)))
}

func sha1File(_ url: URL) throws -> Data {
    Data(Insecure.SHA1.hash(data: try Data(contentsOf: url)))
}

func sha256(_ string: String) -> Data {
    Data(SHA256.hash(data: Data(string.utf8)))
}

extension Data {
    func nonOverlappingOccurrences(of needle: Data) -> Int {
        guard !needle.isEmpty else {
            return 0
        }

        var count = 0
        var searchStart = startIndex
        while searchStart < endIndex,
              let range = self[searchStart..<endIndex].range(of: needle) {
            count += 1
            searchStart = range.upperBound
        }
        return count
    }

    mutating func writeUInt32LE(_ value: UInt32, at offset: Int) {
        withUnsafeMutableBytes { buffer in
            buffer.storeBytes(of: value.littleEndian, toByteOffset: offset, as: UInt32.self)
        }
    }

    mutating func writeUInt32BE(_ value: UInt32, at offset: Int) {
        withUnsafeMutableBytes { buffer in
            buffer.storeBytes(of: value.bigEndian, toByteOffset: offset, as: UInt32.self)
        }
    }

    mutating func writeUInt64LE(_ value: UInt64, at offset: Int) {
        withUnsafeMutableBytes { buffer in
            buffer.storeBytes(of: value.littleEndian, toByteOffset: offset, as: UInt64.self)
        }
    }

    mutating func writeFixedString(_ value: String, at offset: Int, count: Int) {
        let bytes = Array(value.utf8.prefix(count))
        replaceSubrange(offset..<(offset + bytes.count), with: bytes)
    }

    func readUInt32LE(at offset: Int) -> UInt32 {
        self[offset..<(offset + 4)].enumerated().reduce(UInt32(0)) { result, item in
            result | (UInt32(item.element) << UInt32(item.offset * 8))
        }
    }

    func readUInt32BE(at offset: Int) -> UInt32 {
        self[offset..<(offset + 4)].reduce(UInt32(0)) { result, byte in
            (result << 8) | UInt32(byte)
        }
    }

    func readUInt64BE(at offset: Int) -> UInt64 {
        self[offset..<(offset + 8)].reduce(UInt64(0)) { result, byte in
            (result << 8) | UInt64(byte)
        }
    }
}
