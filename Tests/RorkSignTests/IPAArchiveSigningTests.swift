import Crypto
import Foundation
import RorkSign
import XCTest
import ZIPFoundation

final class IPAArchiveSigningTests: XCTestCase {
    func testAdHocSignsPayloadAppAndWritesOutputArchive() throws {
        let fixture = try makeIPAArchiveFixture(bundleIdentifier: "app.rork.archive")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }

        let outputURL = fixture.rootURL.appendingPathComponent("Signed.ipa")
        let report = try RorkSigner.signIPAAdHoc(
            at: fixture.archiveURL,
            outputURL: outputURL
        )

        XCTAssertEqual(report.outputArchiveURL, outputURL)
        XCTAssertEqual(report.appBundlePath, "Payload/Host.app")
        XCTAssertEqual(report.sealedBundlePaths, ["Payload/Host.app"])
        XCTAssertEqual(report.embeddedProvisioningProfilePaths, [])
        XCTAssertEqual(report.signedCodePaths, ["Payload/Host.app/Host"])

        let extractedURL = try unzipArchive(outputURL, under: fixture.rootURL)
        let signedExecutable = try Data(
            contentsOf: extractedURL.appendingPathComponent("Payload/Host.app/Host")
        )
        let info = try RorkSigner.inspectMachO(signedExecutable)
        XCTAssertTrue(info.hasCodeSignature)
        XCTAssertEqual(
            try resourceDirectoryHash(inSignedMachO: signedExecutable),
            Data(SHA256.hash(data: try Data(contentsOf: extractedURL.appendingPathComponent("Payload/Host.app/_CodeSignature/CodeResources"))))
        )
    }

    func testAdHocCanWriteDeflatedOutputArchive() throws {
        let fixture = try makeIPAArchiveFixture(bundleIdentifier: "app.rork.archive.compressed")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }

        let outputURL = fixture.rootURL.appendingPathComponent("Compressed.ipa")
        try RorkSigner.signIPAAdHoc(
            at: fixture.archiveURL,
            outputURL: outputURL,
            archiveCompressionMode: .deflated
        )

        let archive = try Archive(url: outputURL, accessMode: .read)
        let executableEntry = try XCTUnwrap(archive["Payload/Host.app/Host"])
        XCTAssertTrue(executableEntry.isCompressed)
    }

    func testAdHocUsesConfiguredTemporaryDirectory() throws {
        let fixture = try makeIPAArchiveFixture(bundleIdentifier: "app.rork.archive.temp")
        let tempURL = fixture.rootURL.appendingPathComponent("CustomTemp", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }
        try FileManager.default.createDirectory(at: tempURL, withIntermediateDirectories: true)

        let outputURL = fixture.rootURL.appendingPathComponent("SignedWithTemp.ipa")
        try RorkSigner.signIPAAdHoc(
            at: fixture.archiveURL,
            outputURL: outputURL,
            temporaryDirectory: tempURL
        )

        XCTAssertTrue(FileManager.default.fileExists(atPath: outputURL.path))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: tempURL.path), [])
    }

    func testAppSigningIPARewritesPayloadAppBeforeSigning() throws {
        let fixture = try makeIPAArchiveFixture(bundleIdentifier: "com.original.host")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }

        let profile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
            ]
        )
        let outputURL = fixture.rootURL.appendingPathComponent("AppSigned.ipa")
        let report = try RorkSigner.signIPA(
            at: fixture.archiveURL,
            outputURL: outputURL,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.signed.archive",
                rootProvisioningProfile: profile
            )
        )

        XCTAssertEqual(report.appBundlePath, "Payload/Host.app")
        XCTAssertEqual(report.embeddedProvisioningProfilePaths, ["Payload/Host.app/embedded.mobileprovision"])

        let extractedURL = try unzipArchive(outputURL, under: fixture.rootURL)
        let appURL = extractedURL.appendingPathComponent("Payload/Host.app")
        XCTAssertEqual(
            try infoPlist(at: appURL)["CFBundleIdentifier"] as? String,
            "app.rork.signed.archive"
        )
        XCTAssertEqual(
            try Data(contentsOf: appURL.appendingPathComponent("embedded.mobileprovision")),
            profile
        )

        let entitlements = try entitlementDictionary(inSignedMachOAt: appURL.appendingPathComponent("Host"))
        XCTAssertEqual(
            entitlements["application-identifier"] as? String,
            "TEAMID1234.app.rork.signed.archive"
        )
        XCTAssertEqual(
            entitlements["keychain-access-groups"] as? [String],
            ["TEAMID1234.app.rork.signed.archive"]
        )
    }

    func testIdentityIPASigningAcceptsAuthorizedProvisioningProfile() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeIPAArchiveFixture(bundleIdentifier: "app.rork.archive.identity")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }
        let profile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            developerCertificates: [signing.identity.certificateDER],
            entitlements: [
                "application-identifier": "TEAMID1234.app.rork.archive.identity",
                "com.apple.developer.team-identifier": "TEAMID1234",
            ]
        )
        let outputURL = fixture.rootURL.appendingPathComponent("Identity.ipa")

        let report = try RorkSigner.signIPAWithIdentity(
            at: fixture.archiveURL,
            outputURL: outputURL,
            identity: signing.identity,
            options: BundleSigningOptions(
                provisioningProfilesByBundleIdentifier: [
                    "app.rork.archive.identity": profile,
                ]
            )
        )

        XCTAssertEqual(report.embeddedProvisioningProfilePaths, ["Payload/Host.app/embedded.mobileprovision"])
        let extractedURL = try unzipArchive(outputURL, under: fixture.rootURL)
        XCTAssertEqual(
            try Data(contentsOf: extractedURL.appendingPathComponent("Payload/Host.app/embedded.mobileprovision")),
            profile
        )
    }

    func testIdentityIPASigningRejectsUnauthorizedProvisioningProfile() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeIPAArchiveFixture(bundleIdentifier: "app.rork.archive.identity")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }
        let profile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.app.rork.archive.identity",
                "com.apple.developer.team-identifier": "TEAMID1234",
            ]
        )
        let outputURL = fixture.rootURL.appendingPathComponent("Identity.ipa")

        XCTAssertThrowsError(
            try RorkSigner.signIPAWithIdentity(
                at: fixture.archiveURL,
                outputURL: outputURL,
                identity: signing.identity,
                options: BundleSigningOptions(
                    provisioningProfilesByBundleIdentifier: [
                        "app.rork.archive.identity": profile,
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidProvisioningProfile(
                    "Signing identity is not authorized by provisioning profile for app.rork.archive.identity."
                )
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))
    }

    func testIPARejectsArchiveWithoutPayloadDirectory() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let archiveRoot = rootURL.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let archiveURL = rootURL.appendingPathComponent("Broken.ipa")
        try FileManager.default.createDirectory(at: archiveRoot, withIntermediateDirectories: true)
        try Data("not an ipa".utf8).write(to: archiveRoot.appendingPathComponent("README.txt"))
        try FileManager.default.zipItem(at: archiveRoot, to: archiveURL, shouldKeepParent: false)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }

        XCTAssertThrowsError(
            try RorkSigner.signIPAAdHoc(
                at: archiveURL,
                outputURL: rootURL.appendingPathComponent("Signed.ipa")
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidArchive("IPA archive is missing a Payload directory.")
            )
        }
    }
}

private struct IPAArchiveFixture {
    let rootURL: URL
    let archiveURL: URL
}

private func makeIPAArchiveFixture(bundleIdentifier: String) throws -> IPAArchiveFixture {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let archiveRoot = rootURL.appendingPathComponent("ArchiveRoot", isDirectory: true)
    let appURL = archiveRoot.appendingPathComponent("Payload/Host.app", isDirectory: true)
    try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
    try writeInfoPlist(
        [
            "CFBundleIdentifier": bundleIdentifier,
            "CFBundleExecutable": "Host",
        ],
        to: appURL.appendingPathComponent("Info.plist")
    )
    try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
    try Data("asset".utf8).write(to: appURL.appendingPathComponent("asset.txt"))

    let archiveURL = rootURL.appendingPathComponent("Input.ipa")
    try FileManager.default.zipItem(at: archiveRoot, to: archiveURL, shouldKeepParent: false)
    return IPAArchiveFixture(rootURL: rootURL, archiveURL: archiveURL)
}

private func unzipArchive(_ archiveURL: URL, under rootURL: URL) throws -> URL {
    let outputURL = rootURL.appendingPathComponent("Extracted-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: outputURL, withIntermediateDirectories: true)
    try FileManager.default.unzipItem(at: archiveURL, to: outputURL)
    return outputURL
}

private func provisioningProfilePlist(
    teamIdentifier: String,
    developerCertificates: [Data] = [Data([0x01, 0x02, 0x03])],
    entitlements: [String: Any]
) throws -> Data {
    let plist: [String: Any] = [
        "TeamIdentifier": [teamIdentifier],
        "ExpirationDate": Date(timeIntervalSince1970: 1_900_000_000),
        "DeveloperCertificates": developerCertificates,
        "Entitlements": entitlements,
    ]
    return try PropertyListSerialization.data(
        fromPropertyList: plist,
        format: .xml,
        options: 0
    )
}

private func writeInfoPlist(_ dictionary: [String: Any], to url: URL) throws {
    let data = try PropertyListSerialization.data(
        fromPropertyList: dictionary,
        format: .xml,
        options: 0
    )
    try data.write(to: url)
}

private func infoPlist(at bundleURL: URL) throws -> [String: Any] {
    let data = try Data(contentsOf: bundleURL.appendingPathComponent("Info.plist"))
    let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    return try XCTUnwrap(plist as? [String: Any])
}

private func resourceDirectoryHash(inSignedMachO signed: Data) throws -> Data? {
    let blobs = try signatureBlobs(in: signed)
    let codeDirectory = try XCTUnwrap(blobs[0x1000])
    return specialSlotHash(3, in: codeDirectory)
}

private func entitlementDictionary(inSignedMachOAt url: URL) throws -> [String: Any] {
    let signed = try Data(contentsOf: url)
    let blobs = try signatureBlobs(in: signed)
    let entitlements = try XCTUnwrap(blobs[5])
    let length = Int(entitlements.readUInt32BE(at: 4))
    let payload = entitlements.subdata(in: 8..<length)
    let plist = try PropertyListSerialization.propertyList(from: payload, options: [], format: nil)
    return try XCTUnwrap(plist as? [String: Any])
}
