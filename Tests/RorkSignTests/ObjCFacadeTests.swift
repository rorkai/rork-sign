import Foundation
import RorkSign
import RorkSignObjC
import XCTest

final class ObjCFacadeTests: XCTestCase {
    /// Verifies the Objective-C facade reports the same version as the Swift API.
    func testVersionMatchesSwiftSignerVersion() {
        XCTAssertEqual(Signer.signerVersion(), RorkSigner.version)
    }

    /// Verifies the Objective-C async bridge delivers setup failures through
    /// its completion block instead of dropping the callback.
    func testFetchOCSPResponseCompletesWhenRequestHasNoResponderURL() async throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let signer = Signer()
        let request = try signer.makeOCSPRequest(
            certificateData: fixture.identity.certificateDER,
            issuerCertificateData: fixture.identity.certificateDER
        )
        XCTAssertNil(request.responderURL)

        let completion = await withCheckedContinuation { continuation in
            signer.fetchOCSPResponse(request, options: nil) { report, error in
                continuation.resume(
                    returning: (hasReport: report != nil, hasError: error != nil)
                )
            }
        }

        XCTAssertFalse(completion.hasReport)
        XCTAssertTrue(completion.hasError)
    }

    /// Verifies ad-hoc bundle signing returns typed Objective-C report data.
    func testSignBundleAdHocReturnsTypedReport() throws {
        let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "app.rork.objc.adhoc")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let codeDirectoryIdentifier = "app.rork.objc.adhoc.host"
        let options = BundleSigningOptionsObjC()
        options.codeDirectoryIdentifier = codeDirectoryIdentifier

        let report = try Signer().signBundleAdHoc(at: bundleURL, options: options)

        XCTAssertEqual(report.sealedBundleURLs, [bundleURL])
        XCTAssertEqual(report.embeddedProvisioningProfileURLs, [])
        XCTAssertEqual(report.signedCodeURLs, [bundleURL.appendingPathComponent("Host")])
        XCTAssertEqual(report.cachedCodeURLs, [])
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: bundleURL.appendingPathComponent("_CodeSignature/CodeResources").path
            )
        )
        XCTAssertEqual(
            try RorkSigner.checkMachOCodeSignatures(
                at: bundleURL.appendingPathComponent("Host")
            ).first?.codeDirectories.map(\.identifier),
            [codeDirectoryIdentifier, codeDirectoryIdentifier]
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

    /// Verifies the Objective-C facade can read a profile team id without credentials.
    func testTeamIdentifierConvenienceReturnsDecodedProfileTeam() throws {
        let profile = try objcFacadeProvisioningProfile(
            bundleIdentifier: "app.rork.objc.profile-team",
            certificateDER: Data([0x01])
        )
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try profile.write(to: url)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
        }
        let signer = Signer()
        let decodedProfile = try signer.decodeProvisioningProfile(profile)

        XCTAssertEqual(try signer.teamIdentifierForProvisioningProfileData(profile), "TEAMID1234")
        XCTAssertEqual(try signer.teamIdentifierForProvisioningProfile(at: url), "TEAMID1234")
        XCTAssertEqual(signer.teamIdentifier(for: decodedProfile), "TEAMID1234")
        XCTAssertEqual(decodedProfile.authorizedBundleIdentifier, "app.rork.objc.profile-team")
        XCTAssertEqual(decodedProfile.explicitAuthorizedBundleIdentifier, "app.rork.objc.profile-team")
        XCTAssertFalse(decodedProfile.usesWildcardBundleIdentifier)
        XCTAssertTrue(decodedProfile.containsDeveloperCertificateDER(Data([0x01])))
        XCTAssertFalse(decodedProfile.containsDeveloperCertificateDER(Data([0x02])))
        var nullableError: NSError?
        XCTAssertEqual(
            signer.authorizedBundleIdentifierForProvisioningProfileData(profile, error: &nullableError),
            "app.rork.objc.profile-team"
        )
        XCTAssertNil(nullableError)
        XCTAssertEqual(
            signer.authorizedBundleIdentifierForProvisioningProfile(at: url, error: &nullableError),
            "app.rork.objc.profile-team"
        )
        XCTAssertNil(nullableError)
        XCTAssertEqual(
            signer.authorizedBundleIdentifier(for: decodedProfile),
            "app.rork.objc.profile-team"
        )
        XCTAssertEqual(
            signer.explicitAuthorizedBundleIdentifierForProvisioningProfileData(profile, error: &nullableError),
            "app.rork.objc.profile-team"
        )
        XCTAssertNil(nullableError)
        XCTAssertEqual(
            signer.explicitAuthorizedBundleIdentifierForProvisioningProfile(at: url, error: &nullableError),
            "app.rork.objc.profile-team"
        )
        XCTAssertNil(nullableError)
        XCTAssertEqual(
            signer.explicitAuthorizedBundleIdentifier(for: decodedProfile),
            "app.rork.objc.profile-team"
        )
    }

    /// Verifies nullable Objective-C profile helpers distinguish wildcard results from failures.
    func testNullableProfileIdentifierHelpersPreserveWildcardNilSuccess() throws {
        let profile = try objcFacadeProvisioningProfile(
            bundleIdentifier: "unused",
            certificateDER: Data([0x01]),
            applicationIdentifier: "TEAMID1234.*"
        )
        let signer = Signer()
        let decodedProfile = try signer.decodeProvisioningProfile(profile)
        var nullableError: NSError?

        XCTAssertEqual(decodedProfile.authorizedBundleIdentifier, "*")
        XCTAssertNil(decodedProfile.explicitAuthorizedBundleIdentifier)
        XCTAssertTrue(decodedProfile.usesWildcardBundleIdentifier)
        XCTAssertEqual(
            signer.authorizedBundleIdentifierForProvisioningProfileData(profile, error: &nullableError),
            "*"
        )
        XCTAssertNil(nullableError)
        XCTAssertNil(
            signer.explicitAuthorizedBundleIdentifierForProvisioningProfileData(profile, error: &nullableError)
        )
        XCTAssertNil(nullableError)
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

    /// Verifies Objective-C hosted signing restores the guest bundle after signing.
    func testSignHostedBundleWithCredentialRestoresGuestBundleShape() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeObjCFacadeBundleFixture(
            bundleIdentifier: "app.rork.objc.hosted.guest",
            executable: Fixtures.machO64DylibWithCodeSignature()
        )
        let hostExecutableURL = bundleURL.deletingLastPathComponent().appendingPathComponent("HostStubSource")
        try Fixtures.machO64WithCodeSignature().write(to: hostExecutableURL)
        let originalInfoPlist = try Data(contentsOf: bundleURL.appendingPathComponent("Info.plist"))
        let hostBundleIdentifier = "app.rork.objc.hosted.host"
        let profile = try objcFacadeProvisioningProfile(
            bundleIdentifier: hostBundleIdentifier,
            certificateDER: fixture.identity.certificateDER
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let options = HostedBundleSigningOptionsObjC(
            hostExecutableURL: hostExecutableURL,
            hostBundleIdentifier: hostBundleIdentifier
        )
        let report = try Signer().signHostedBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            password: nil,
            options: options
        )

        let stubURL = bundleURL.appendingPathComponent("HostedSigningStub")
        XCTAssertEqual(try Data(contentsOf: bundleURL.appendingPathComponent("Info.plist")), originalInfoPlist)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stubURL.path))
        XCTAssertFalse(report.signedCodeURLs.contains(stubURL))
        XCTAssertEqual(
            report.signedCodeURLs.map { $0.standardizedFileURL },
            [bundleURL.appendingPathComponent("Host").standardizedFileURL]
        )

        let codeDirectories = try XCTUnwrap(
            RorkSigner.checkMachOCodeSignatures(
                at: bundleURL.appendingPathComponent("Host")
            ).first?.codeDirectories
        )
        XCTAssertEqual(
            codeDirectories.map(\.identifier),
            [hostBundleIdentifier, hostBundleIdentifier]
        )
    }

    /// Verifies hosted ObjC signing preserves an explicitly configured root profile.
    func testSignHostedBundleWithCredentialPreservesExplicitRootProfile() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeObjCFacadeBundleFixture(
            bundleIdentifier: "app.rork.objc.hosted.override.guest",
            executable: Fixtures.machO64DylibWithCodeSignature()
        )
        let hostExecutableURL = bundleURL.deletingLastPathComponent().appendingPathComponent("HostStubSource")
        try Fixtures.machO64WithCodeSignature().write(to: hostExecutableURL)
        let credentialProfile = try objcFacadeProvisioningProfile(
            bundleIdentifier: "app.rork.objc.hosted.override.identity",
            certificateDER: fixture.identity.certificateDER
        )
        let rootProfile = try objcFacadeProvisioningProfile(
            bundleIdentifier: "app.rork.objc.hosted.override.host",
            certificateDER: fixture.identity.certificateDER
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let options = HostedBundleSigningOptionsObjC(
            hostExecutableURL: hostExecutableURL,
            hostBundleIdentifier: "app.rork.objc.hosted.override.host"
        )
        options.bundleSigningOptions.rootProvisioningProfileData = rootProfile

        let report = try Signer().signHostedBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: credentialProfile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            password: nil,
            options: options
        )

        XCTAssertEqual(
            report.signedCodeURLs.map { $0.standardizedFileURL },
            [bundleURL.appendingPathComponent("Host").standardizedFileURL]
        )
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: bundleURL.appendingPathComponent("HostedSigningStub").path
            )
        )
    }

    /// Verifies Objective-C framework signing exposes direct framework semantics.
    func testSignFrameworkWithCredentialMapsOptionsAndSignsCode() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let frameworkURL = try makeObjCFacadeFrameworkFixture(bundleIdentifier: "app.rork.objc.framework")
        let profile = try objcFacadeProvisioningProfile(
            bundleIdentifier: "app.rork.objc.host",
            certificateDER: fixture.identity.certificateDER
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: frameworkURL.deletingLastPathComponent())
        }

        let options = FrameworkSigningOptionsObjC()
        options.codeDirectoryHashingMode = .sha256Only

        let report = try Signer().signFrameworkWithCredential(
            at: frameworkURL,
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            password: nil,
            options: options
        )

        XCTAssertEqual(report.sealedBundleURLs, [frameworkURL])
        XCTAssertEqual(report.embeddedProvisioningProfileURLs, [])
        XCTAssertEqual(report.signedCodeURLs, [frameworkURL.appendingPathComponent("TestFramework")])
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: frameworkURL.appendingPathComponent("embedded.mobileprovision").path
            )
        )

        let executableURL = frameworkURL.appendingPathComponent("TestFramework")
        let executable = try Data(contentsOf: executableURL)
        let blobs = try signatureBlobs(in: executable)
        XCTAssertNil(blobs[5])
        XCTAssertNil(blobs[7])
        XCTAssertEqual(
            try RorkSigner.checkMachOCodeSignatures(at: executableURL)
                .first?
                .codeDirectories
                .map(\.hashAlgorithm),
            [.sha256]
        )
    }

    /// Verifies Objective-C callers can inspect app bundle profile requirements.
    func testInspectAppReturnsTypedObjectiveCReport() throws {
        let fixture = try makeObjCFacadeAppBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        let report = try Signer().inspectApp(
            at: fixture.bundleURL,
            replacementBundleIdentifier: "app.rork.objc.inspect"
        )

        XCTAssertEqual(report.rootBundleURL, fixture.bundleURL)
        XCTAssertEqual(report.rootBundleIdentifier, "com.original.host")
        XCTAssertEqual(report.replacementBundleIdentifier, "app.rork.objc.inspect")
        XCTAssertEqual(report.rewrittenBundleIdentifiers, [
            "app.rork.objc.inspect",
            "app.rork.objc.inspect.ShareExtension",
        ])
        XCTAssertEqual(report.watchBundleIdentifiers, [])
        XCTAssertEqual(report.appExtensionBundleIdentifiers, ["app.rork.objc.inspect.ShareExtension"])

        let root = try XCTUnwrap(report.provisioningRequirements.first)
        XCTAssertEqual(root.url, fixture.bundleURL)
        XCTAssertEqual(root.relativePath, ".")
        XCTAssertEqual(root.originalBundleIdentifier, "com.original.host")
        XCTAssertEqual(root.rewrittenBundleIdentifier, "app.rork.objc.inspect")
        XCTAssertEqual(root.kind, .rootApp)
        XCTAssertFalse(root.isWatchBundle)
        XCTAssertNil(root.associatedBundleIdentifier)
        XCTAssertEqual(root.executableName, "Host")

        let extensionRequirement = try XCTUnwrap(report.provisioningRequirements.dropFirst().first)
        XCTAssertEqual(extensionRequirement.url, fixture.extensionURL)
        XCTAssertEqual(extensionRequirement.relativePath, "PlugIns/Share.appex")
        XCTAssertEqual(extensionRequirement.originalBundleIdentifier, "com.vendor.ShareExtension")
        XCTAssertEqual(extensionRequirement.rewrittenBundleIdentifier, "app.rork.objc.inspect.ShareExtension")
        XCTAssertEqual(extensionRequirement.kind, .appExtension)
        XCTAssertFalse(extensionRequirement.isWatchBundle)
        XCTAssertEqual(extensionRequirement.associatedBundleIdentifier, "app.rork.objc.inspect")
        XCTAssertEqual(extensionRequirement.executableName, "Share")
    }

    /// Verifies dictionary-backed option validation rejects non-data values.
    func testAppSigningOptionsRejectInvalidProfileMapValues() throws {
        let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "app.rork.objc.invalid")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let options = AppSigningOptionsObjC(bundleIdentifier: "app.rork.objc.invalid")
        options.provisioningProfilesByBundleIdentifier = [
            "app.rork.objc.invalid.widget": "not data",
        ]

        XCTAssertThrowsError(try Signer().signAppBundleAdHoc(at: bundleURL, options: options)) { error in
            XCTAssertTrue(error.localizedDescription.contains("is not NSData"))
        }
    }

    /// Verifies Objective-C callers can add files that participate in sealing.
    func testAppSigningOptionsWriteAdditionalBundleFiles() throws {
        let bundleURL = try makeObjCFacadeBundleFixture(
            bundleIdentifier: "app.rork.objc.additional-files"
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let options = AppSigningOptionsObjC(
            bundleIdentifier: "app.rork.objc.additional-files"
        )
        options.additionalBundleFiles = [
            "Signing/credential.p12": Data("credential".utf8),
        ]

        _ = try Signer().signAppBundleAdHoc(at: bundleURL, options: options)

        XCTAssertEqual(
            try Data(
                contentsOf: bundleURL
                    .appendingPathComponent("Signing/credential.p12")
            ),
            Data("credential".utf8)
        )
        let codeResources = try parseCodeResources(
            Data(
                contentsOf: bundleURL
                    .appendingPathComponent("_CodeSignature/CodeResources")
            )
        )
        let sealedFiles = try XCTUnwrap(codeResources["files2"] as? [String: Any])
        XCTAssertNotNil(sealedFiles["Signing/credential.p12"])
    }
}

/// Captures Objective-C facade log messages through the logger protocol.
private final class ObjCFacadeSigningLogger: NSObject, SigningLoggerObjC {
    var messages: [String] = []

    func signingDidLogMessage(_ message: String, level: SigningDiagnosticLevelObjC) {
        messages.append(message)
    }
}

/// App and extension locations used by Objective-C inspection tests.
private struct ObjCFacadeAppBundleFixture {
    /// Root app bundle location.
    let bundleURL: URL

    /// Nested extension bundle location.
    let extensionURL: URL
}

/// Creates a minimal app bundle fixture for Objective-C facade tests.
private func makeObjCFacadeBundleFixture(
    bundleIdentifier: String,
    executable: Data = Fixtures.machO64WithCodeSignature()
) throws -> URL {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let bundleURL = rootURL.appendingPathComponent("Host.app", isDirectory: true)
    try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)
    try objcFacadeInfoPlist(
        bundleIdentifier: bundleIdentifier,
        executableName: "Host",
        to: bundleURL.appendingPathComponent("Info.plist")
    )
    try executable.write(to: bundleURL.appendingPathComponent("Host"))
    return bundleURL
}

/// Creates an app fixture with one extension for read-only inspection tests.
private func makeObjCFacadeAppBundleFixture() throws -> ObjCFacadeAppBundleFixture {
    let bundleURL = try makeObjCFacadeBundleFixture(bundleIdentifier: "com.original.host")
    let extensionURL = bundleURL.appendingPathComponent("PlugIns/Share.appex", isDirectory: true)
    try FileManager.default.createDirectory(at: extensionURL, withIntermediateDirectories: true)
    let extensionInfo: [String: Any] = [
        "CFBundleIdentifier": "com.vendor.ShareExtension",
        "CFBundleExecutable": "Share",
        "WKCompanionAppBundleIdentifier": "com.original.host",
    ]
    let extensionInfoData = try PropertyListSerialization.data(
        fromPropertyList: extensionInfo,
        format: .xml,
        options: 0
    )
    try extensionInfoData.write(to: extensionURL.appendingPathComponent("Info.plist"))
    try Fixtures.machO64WithCodeSignature().write(to: extensionURL.appendingPathComponent("Share"))
    return ObjCFacadeAppBundleFixture(bundleURL: bundleURL, extensionURL: extensionURL)
}

/// Creates a minimal framework fixture for Objective-C facade tests.
private func makeObjCFacadeFrameworkFixture(bundleIdentifier: String) throws -> URL {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let frameworkURL = rootURL.appendingPathComponent("TestFramework.framework", isDirectory: true)
    try FileManager.default.createDirectory(at: frameworkURL, withIntermediateDirectories: true)
    try objcFacadeInfoPlist(
        bundleIdentifier: bundleIdentifier,
        executableName: "TestFramework",
        to: frameworkURL.appendingPathComponent("Info.plist")
    )
    try Fixtures.machO64DylibWithCodeSignature().write(to: frameworkURL.appendingPathComponent("TestFramework"))
    return frameworkURL
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
    certificateDER: Data,
    applicationIdentifier: String? = nil
) throws -> Data {
    let farFutureExpiration = Date(timeIntervalSince1970: 4_102_444_800)
    let plist: [String: Any] = [
        "TeamIdentifier": ["TEAMID1234"],
        "ExpirationDate": farFutureExpiration,
        "DeveloperCertificates": [certificateDER],
        "Entitlements": [
            "application-identifier": applicationIdentifier ?? "TEAMID1234.\(bundleIdentifier)",
            "com.apple.developer.team-identifier": "TEAMID1234",
        ],
    ]
    return try PropertyListSerialization.data(
        fromPropertyList: plist,
        format: .xml,
        options: 0
    )
}
