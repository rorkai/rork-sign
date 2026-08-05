import Foundation
import RorkSign
#if canImport(RorkSignObjC)
import RorkSignObjC
#endif
import XCTest

/// Coverage for overriding a framework executable's CodeDirectory identifier.
final class FrameworkIdentifierOverrideTests: XCTestCase {
    /// Verifies the Swift API overrides only the root framework CodeDirectory
    /// identifier.
    func testFrameworkIdentifierOverridePreservesBundleMetadataAndNestedCodeIdentifiers() throws {
        let identityFixture = try OpenSSLFixture()
        defer {
            identityFixture.remove()
        }
        let frameworkFixture = try makeFrameworkIdentifierFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(
                at: frameworkFixture.frameworkURL.deletingLastPathComponent()
            )
        }
        let originalInfoPlist = try Data(
            contentsOf: frameworkFixture.frameworkURL.appendingPathComponent("Info.plist")
        )
        let hostIdentifier = "app.rork.free.host"
        let profile = try makeFrameworkProvisioningProfile(
            authorizing: hostIdentifier,
            certificateDER: identityFixture.identity.certificateDER
        )
        var infoMessages: [String] = []
        let options = FrameworkSigningOptions(
            codeDirectoryIdentifier: hostIdentifier,
            diagnostics: SigningDiagnostics(eventHandler: { level, message in
                guard level == .info else {
                    return
                }
                infoMessages.append(message)
            })
        )

        let report = try RorkSigner.signFrameworkWithCredential(
            at: frameworkFixture.frameworkURL,
            provisioningProfileData: profile,
            credentialData: Data(identityFixture.privateKeyPEM.utf8),
            options: options
        )

        XCTAssertEqual(
            try Data(
                contentsOf: frameworkFixture.frameworkURL.appendingPathComponent("Info.plist")
            ),
            originalInfoPlist
        )
        XCTAssertEqual(
            report.signedCode.map { $0.resolvingSymlinksInPath() },
            [
                frameworkFixture.helperURL,
                frameworkFixture.frameworkURL.appendingPathComponent("TestFramework"),
            ].map { $0.resolvingSymlinksInPath() }
        )
        XCTAssertEqual(
            infoMessages.first { $0.hasPrefix(">>> BundleId:") },
            ">>> BundleId: \t\(hostIdentifier)"
        )

        let frameworkCodeDirectories = try XCTUnwrap(
            RorkSigner.checkMachOCodeSignatures(
                at: frameworkFixture.frameworkURL.appendingPathComponent("TestFramework")
            ).first?.codeDirectories
        )
        XCTAssertEqual(
            frameworkCodeDirectories.map(\.identifier),
            [hostIdentifier, hostIdentifier]
        )
        XCTAssertEqual(frameworkCodeDirectories.map(\.hashAlgorithm), [.sha1, .sha256])

        let helperCodeDirectories = try XCTUnwrap(
            RorkSigner.checkMachOCodeSignatures(
                at: frameworkFixture.helperURL
            ).first?.codeDirectories
        )
        XCTAssertEqual(
            helperCodeDirectories.map(\.identifier),
            ["Helper.dylib", "Helper.dylib"]
        )
    }

    /// Verifies the default framework identifier remains the bundle identifier.
    func testDefaultFrameworkIdentifierUsesBundleIdentifier() throws {
        let frameworkFixture = try makeFrameworkIdentifierFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(
                at: frameworkFixture.frameworkURL.deletingLastPathComponent()
            )
        }

        _ = try RorkSigner.signFrameworkAdHoc(at: frameworkFixture.frameworkURL)

        let codeDirectories = try XCTUnwrap(
            RorkSigner.checkMachOCodeSignatures(
                at: frameworkFixture.frameworkURL.appendingPathComponent("TestFramework")
            ).first?.codeDirectories
        )
        XCTAssertEqual(
            codeDirectories.map(\.identifier),
            ["app.rork.framework.original", "app.rork.framework.original"]
        )
    }

    /// Verifies generic bundle-signing options can override only the root identity.
    func testBundleSigningOptionsOverrideRootCodeDirectoryIdentifier() throws {
        let frameworkFixture = try makeFrameworkIdentifierFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(
                at: frameworkFixture.frameworkURL.deletingLastPathComponent()
            )
        }
        let rootIdentifier = "app.rork.generic.root"

        _ = try RorkSigner.signBundleAdHoc(
            at: frameworkFixture.frameworkURL,
            options: BundleSigningOptions(codeDirectoryIdentifier: rootIdentifier)
        )

        let rootCodeDirectories = try XCTUnwrap(
            RorkSigner.checkMachOCodeSignatures(
                at: frameworkFixture.frameworkURL.appendingPathComponent("TestFramework")
            ).first?.codeDirectories
        )
        XCTAssertEqual(
            rootCodeDirectories.map(\.identifier),
            [rootIdentifier, rootIdentifier]
        )

        let helperCodeDirectories = try XCTUnwrap(
            RorkSigner.checkMachOCodeSignatures(
                at: frameworkFixture.helperURL
            ).first?.codeDirectories
        )
        XCTAssertEqual(
            helperCodeDirectories.map(\.identifier),
            ["Helper.dylib", "Helper.dylib"]
        )
    }

    /// Verifies the Objective-C option maps the override into the Swift signer.
    #if canImport(RorkSignObjC)
    func testObjectiveCFrameworkIdentifierOverrideMapsToSwiftSigner() throws {
        let identityFixture = try OpenSSLFixture()
        defer {
            identityFixture.remove()
        }
        let frameworkFixture = try makeFrameworkIdentifierFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(
                at: frameworkFixture.frameworkURL.deletingLastPathComponent()
            )
        }
        let hostIdentifier = "app.rork.free.objc-host"
        let profile = try makeFrameworkProvisioningProfile(
            authorizing: hostIdentifier,
            certificateDER: identityFixture.identity.certificateDER
        )
        let options = FrameworkSigningOptionsObjC()
        options.codeDirectoryIdentifier = hostIdentifier

        _ = try Signer().signFrameworkWithCredential(
            at: frameworkFixture.frameworkURL,
            provisioningProfileData: profile,
            credentialData: Data(identityFixture.privateKeyPEM.utf8),
            password: nil,
            options: options
        )

        let codeDirectories = try XCTUnwrap(
            RorkSigner.checkMachOCodeSignatures(
                at: frameworkFixture.frameworkURL.appendingPathComponent("TestFramework")
            ).first?.codeDirectories
        )
        XCTAssertEqual(codeDirectories.map(\.identifier), [hostIdentifier, hostIdentifier])
    }
    #endif

    /// Verifies option equality includes the CodeDirectory identifier override.
    func testFrameworkSigningOptionsEqualityIncludesIdentifierOverride() {
        let defaultOptions = FrameworkSigningOptions()
        let overriddenOptions = FrameworkSigningOptions(
            codeDirectoryIdentifier: "app.rork.free.host"
        )
        let defaultBundleOptions = BundleSigningOptions()
        let overriddenBundleOptions = BundleSigningOptions(
            codeDirectoryIdentifier: "app.rork.free.host"
        )

        XCTAssertNil(defaultOptions.codeDirectoryIdentifier)
        XCTAssertNotEqual(defaultOptions, overriddenOptions)
        XCTAssertNil(defaultBundleOptions.codeDirectoryIdentifier)
        XCTAssertNotEqual(defaultBundleOptions, overriddenBundleOptions)
    }

    /// Verifies an empty root CodeDirectory identifier fails before framework mutation.
    func testFrameworkIdentifierOverrideRejectsEmptyValue() throws {
        let frameworkFixture = try makeFrameworkIdentifierFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(
                at: frameworkFixture.frameworkURL.deletingLastPathComponent()
            )
        }
        let originalExecutable = try Data(
            contentsOf: frameworkFixture.frameworkURL.appendingPathComponent("TestFramework")
        )

        XCTAssertThrowsError(
            try RorkSigner.signFrameworkAdHoc(
                at: frameworkFixture.frameworkURL,
                options: FrameworkSigningOptions(codeDirectoryIdentifier: " \n ")
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidBundle("CodeDirectory identifier is empty.")
            )
        }
        XCTAssertEqual(
            try Data(
                contentsOf: frameworkFixture.frameworkURL.appendingPathComponent("TestFramework")
            ),
            originalExecutable
        )
    }
}

/// Creates a framework fixture with one nested loose Mach-O for scope validation.
private func makeFrameworkIdentifierFixture() throws -> (
    frameworkURL: URL,
    helperURL: URL
) {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let frameworkURL = rootURL.appendingPathComponent("TestFramework.framework", isDirectory: true)
    let helperDirectoryURL = frameworkURL.appendingPathComponent("Helpers", isDirectory: true)
    try FileManager.default.createDirectory(
        at: helperDirectoryURL,
        withIntermediateDirectories: true
    )

    let infoPlist: [String: Any] = [
        "CFBundleExecutable": "TestFramework",
        "CFBundleIdentifier": "app.rork.framework.original",
        "CFBundleName": "TestFramework",
        "CFBundlePackageType": "FMWK",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
    ]
    let infoPlistData = try PropertyListSerialization.data(
        fromPropertyList: infoPlist,
        format: .binary,
        options: 0
    )
    try infoPlistData.write(to: frameworkURL.appendingPathComponent("Info.plist"))

    let executableURL = frameworkURL.appendingPathComponent("TestFramework")
    let helperURL = helperDirectoryURL.appendingPathComponent("Helper.dylib")
    try Fixtures.machO64DylibWithCodeSignature().write(to: executableURL)
    try Fixtures.machO64DylibWithCodeSignature().write(to: helperURL)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o755],
        ofItemAtPath: executableURL.path
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o755],
        ofItemAtPath: helperURL.path
    )
    return (frameworkURL, helperURL)
}

/// Creates a profile authorizing the supplied framework CodeDirectory identifier.
private func makeFrameworkProvisioningProfile(
    authorizing bundleIdentifier: String,
    certificateDER: Data
) throws -> Data {
    let plist: [String: Any] = [
        "TeamIdentifier": ["TEAMID1234"],
        "ExpirationDate": Date(timeIntervalSince1970: 4_102_444_800),
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
