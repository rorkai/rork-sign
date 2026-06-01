import Foundation
import RorkSign
import RorkSignObjC
import XCTest

final class ObjCFacadeTests: XCTestCase {
    /// Verifies the Objective-C facade reports the same version as the Swift API.
    func testVersionMatchesSwiftSignerVersion() {
        XCTAssertEqual(Signer.signerVersion(), RorkSigner.version)
    }

    /// Verifies ad-hoc bundle signing returns typed Objective-C report data.
    func testSignBundleAdHocReturnsTypedReport() throws {
        let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "app.rork.objc.adhoc")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let report = try Signer().signBundleAdHoc(at: bundleURL, options: nil)

        XCTAssertEqual(report.sealedBundleURLs, [bundleURL])
        XCTAssertEqual(report.embeddedProvisioningProfileURLs, [])
        XCTAssertEqual(report.signedCodeURLs, [bundleURL.appendingPathComponent("Host")])
        XCTAssertEqual(report.cachedCodeURLs, [])
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: bundleURL.appendingPathComponent("_CodeSignature/CodeResources").path
            )
        )
    }

    /// Verifies Objective-C options can receive info-level signing logs.
    func testBundleOptionsCanReceiveLogLines() throws {
        let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "app.rork.objc.logging")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let options = BundleSigningOptionsObjC()
        var logLines: [String] = []
        options.logLevel = .info
        options.logHandler = { level, message in
            guard level == .info else {
                return
            }
            logLines.append(message)
        }

        _ = try Signer().signBundleAdHoc(at: bundleURL, options: options)

        XCTAssertTrue(logLines.contains(">>> AppName: \tHost"), logLines.joined(separator: "\n"))
        XCTAssertTrue(
            logLines.contains(">>> BundleId: \tapp.rork.objc.logging"),
            logLines.joined(separator: "\n")
        )
        XCTAssertTrue(logLines.contains(">>> ReadCache: \tNO"), logLines.joined(separator: "\n"))
    }

    /// Verifies Objective-C logging stays silent unless a level is explicitly enabled.
    func testBundleOptionsKeepLoggingSilentByDefault() throws {
        let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "app.rork.objc.logging-silent")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let options = BundleSigningOptionsObjC()
        var logLines: [String] = []
        options.logHandler = { _, message in
            logLines.append(message)
        }

        _ = try Signer().signBundleAdHoc(at: bundleURL, options: options)

        XCTAssertEqual(logLines, [])
    }

    /// Verifies Objective-C options can route logs through an object sink.
    func testBundleOptionsCanReceiveLogsThroughLoggerObject() throws {
        let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "app.rork.objc.logger")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let logger = ObjCFacadeSigningLogger()
        let options = BundleSigningOptionsObjC()
        options.logLevel = .info
        options.logger = logger

        _ = try Signer().signBundleAdHoc(at: bundleURL, options: options)

        XCTAssertTrue(logger.messages.contains(">>> AppName: \tHost"), logger.messages.joined(separator: "\n"))
        XCTAssertTrue(
            logger.messages.contains(">>> BundleId: \tapp.rork.objc.logger"),
            logger.messages.joined(separator: "\n")
        )
    }

    /// Verifies profile/credential validation succeeds through the facade.
    func testValidatedTeamIdentifierAcceptsProfileCredentialPair() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let profile = try objcFacadeProvisioningProfile(
            bundleIdentifier: "app.rork.objc.identity",
            certificateDER: fixture.identity.certificateDER
        )

        let teamIdentifier = try Signer().validatedTeamIdentifier(
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            password: nil
        )

        XCTAssertEqual(teamIdentifier, "TEAMID1234")
    }

    /// Verifies profile-backed identities expose their team identifier through Objective-C.
    func testSigningIdentityExposesProfileTeamIdentifier() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let profile = try objcFacadeProvisioningProfile(
            bundleIdentifier: "app.rork.objc.identity-team",
            certificateDER: fixture.identity.certificateDER
        )

        let identity = try SigningIdentityObjC(
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            password: nil
        )

        XCTAssertEqual(identity.teamIdentifier, "TEAMID1234")
    }

    /// Verifies credential signing maps Objective-C options into Swift options.
    func testSignBundleWithCredentialMapsOptionsAndSignsCode() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "app.rork.objc.identity")
        let profile = try objcFacadeProvisioningProfile(
            bundleIdentifier: "app.rork.objc.identity",
            certificateDER: fixture.identity.certificateDER
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let options = BundleSigningOptionsObjC()
        options.embedProvisioningProfile = true
        options.codeDirectoryHashingMode = .sha256Only

        let report = try Signer().signBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            password: nil,
            options: options
        )

        XCTAssertEqual(report.embeddedProvisioningProfileURLs, [
            bundleURL.appendingPathComponent("embedded.mobileprovision"),
        ])
        XCTAssertEqual(report.signedCodeURLs, [bundleURL.appendingPathComponent("Host")])
        let signatures = try RorkSigner.checkMachOCodeSignatures(
            at: bundleURL.appendingPathComponent("Host")
        )
        XCTAssertEqual(signatures.first?.codeDirectories.map(\.hashAlgorithm), [.sha256])
    }

    /// Verifies preserve-identifier credential signing does not re-enable strict profile ID checks.
    func testSignBundleWithCredentialPreservesDifferentBundleIdentifierWhenProfileIsNotEmbedded() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "app.rork.objc.guest")
        let profile = try objcFacadeProvisioningProfile(
            bundleIdentifier: "app.rork.objc.host",
            certificateDER: fixture.identity.certificateDER
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let options = BundleSigningOptionsObjC()
        options.embedProvisioningProfile = false
        options.codeDirectoryHashingMode = .sha256Only

        let report = try Signer().signBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            password: nil,
            options: options
        )

        XCTAssertEqual(report.embeddedProvisioningProfileURLs, [])
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: bundleURL.appendingPathComponent("embedded.mobileprovision").path
            )
        )

        let executable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let payload = try objcFacadeEntitlementsPayload(inSignedMachO: executable)
        XCTAssertTrue(payload.contains("TEAMID1234.app.rork.objc.guest"), payload)
        XCTAssertFalse(payload.contains("TEAMID1234.app.rork.objc.host"), payload)
        XCTAssertEqual(try RorkSigner.checkMachOCodeSignatures(executable).first?.codeDirectories.map(\.hashAlgorithm), [.sha256])
    }

    /// Verifies dictionary-backed option validation rejects non-data values.
    func testStandaloneOptionsRejectInvalidProfileMapValues() throws {
        let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "app.rork.objc.invalid")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let options = StandaloneBundleSigningOptionsObjC(bundleIdentifier: "app.rork.objc.invalid")
        options.provisioningProfilesByBundleIdentifier = [
            "app.rork.objc.invalid.widget": "not data",
        ]

        XCTAssertThrowsError(try Signer().signStandaloneBundleAdHoc(at: bundleURL, options: options)) { error in
            XCTAssertTrue(error.localizedDescription.contains("is not NSData"))
        }
    }
}

/// Captures Objective-C facade log messages through the logger protocol.
private final class ObjCFacadeSigningLogger: NSObject, SigningLoggerObjC {
    var messages: [String] = []

    func signingDidLogMessage(_ message: String, level: SigningDiagnosticLevelObjC) {
        messages.append(message)
    }
}

/// Creates a minimal app bundle fixture for Objective-C facade tests.
private func makeObjCFacadeBundleFixture(bundleIdentifier: String) throws -> URL {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let bundleURL = rootURL.appendingPathComponent("Host.app", isDirectory: true)
    try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)
    try objcFacadeInfoPlist(
        bundleIdentifier: bundleIdentifier,
        executableName: "Host",
        to: bundleURL.appendingPathComponent("Info.plist")
    )
    try Fixtures.machO64WithCodeSignature().write(to: bundleURL.appendingPathComponent("Host"))
    return bundleURL
}

/// Writes the `Info.plist` required for a signable test app bundle.
private func objcFacadeInfoPlist(
    bundleIdentifier: String,
    executableName: String,
    to url: URL
) throws {
    let plist: [String: Any] = [
        "CFBundleIdentifier": bundleIdentifier,
        "CFBundleExecutable": executableName,
    ]
    let data = try PropertyListSerialization.data(
        fromPropertyList: plist,
        format: .xml,
        options: 0
    )
    try data.write(to: url)
}

/// Reads the XML entitlement slot from a signed test Mach-O.
private func objcFacadeEntitlementsPayload(inSignedMachO signed: Data) throws -> String {
    let blobs = try signatureBlobs(in: signed)
    let entitlements = try XCTUnwrap(blobs[5])
    let length = Int(entitlements.readUInt32BE(at: 4))
    return String(decoding: entitlements.subdata(in: 8..<length), as: UTF8.self)
}

/// Builds a raw plist provisioning profile authorized for the fixture identity.
private func objcFacadeProvisioningProfile(
    bundleIdentifier: String,
    certificateDER: Data
) throws -> Data {
    let farFutureExpiration = Date(timeIntervalSince1970: 4_102_444_800)
    let plist: [String: Any] = [
        "TeamIdentifier": ["TEAMID1234"],
        "ExpirationDate": farFutureExpiration,
        "DeveloperCertificates": [certificateDER],
        "Entitlements": [
            "application-identifier": "TEAMID1234.\(bundleIdentifier)",
            "com.apple.developer.team-identifier": "TEAMID1234",
        ],
    ]
    return try PropertyListSerialization.data(
        fromPropertyList: plist,
        format: .xml,
        options: 0
    )
}
