import Foundation
import RorkSign
import RorkSignObjC
import XCTest

final class ObjCFacadeTests: XCTestCase {
    func testVersionMatchesSwiftSignerVersion() {
        XCTAssertEqual(Signer.signerVersion(), RorkSigner.version)
    }

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
