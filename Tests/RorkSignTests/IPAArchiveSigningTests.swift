#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
@testable import RorkSign
import XCTest
import ZipArchive

#if canImport(RorkSignWeb)
import RorkSignWeb
#endif

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

    /// Guards the explicit compression option now that archive serialization
    /// is provided by the shared native and WASI backend.
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

        try ZipArchiveReader<ZipFileStorage>.withFile(outputURL.path) { reader in
            let executableEntry = try XCTUnwrap(
                try reader.readDirectory().first {
                    $0.pathInArchive == "Payload/Host.app/Host"
                }
            )
            XCTAssertEqual(executableEntry.compressionMethod, .deflate)
        }
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

    /// Ensures malformed ZIP files are rejected before signing can create an
    /// output that resembles an IPA but cannot be installed.
    func testIPARejectsArchiveWithoutPayloadDirectory() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let archiveRoot = rootURL.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let archiveURL = rootURL.appendingPathComponent("Broken.ipa")
        try FileManager.default.createDirectory(at: archiveRoot, withIntermediateDirectories: true)
        try Data("not an ipa".utf8).write(to: archiveRoot.appendingPathComponent("README.txt"))
        try IPAArchive.write(
            contentsOf: archiveRoot,
            to: archiveURL,
            compressionMode: .stored
        )
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

    #if canImport(RorkSignWeb)
    /// Exercises the complete in-memory browser API while proving that signing
    /// preserves executable modes, symbolic links, and plist value types.
    func testWebSignerReturnsInstallableArchiveAndPreservesEntryTypes() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeIPAArchiveFixture(
            bundleIdentifier: "app.rork.archive.web",
            includeSymbolicLink: true,
            additionalInfoPlistValues: [
                "UIDeviceFamily": [1, 2],
            ]
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }
        let profile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            developerCertificates: [signing.identity.certificateDER],
            entitlements: [
                "application-identifier": "TEAMID1234.app.rork.archive.web",
                "com.apple.developer.team-identifier": "TEAMID1234",
            ]
        )

        let signedIPA = try RorkSigner.signIPA(
            try Data(contentsOf: fixture.archiveURL),
            using: signing.identity,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.archive.web",
                rootProvisioningProfile: profile
            )
        )

        XCTAssertEqual(signedIPA.appBundlePath, "Payload/Host.app")
        XCTAssertEqual(
            signedIPA.embeddedProvisioningProfilePaths,
            ["Payload/Host.app/embedded.mobileprovision"]
        )

        let reader = try ZipArchiveReader(buffer: [UInt8](signedIPA.data))
        let entries = try reader.readDirectory()
        let executable = try XCTUnwrap(
            entries.first { $0.pathInArchive == "Payload/Host.app/Host" }
        )
        XCTAssertTrue(
            executable.externalAttributes.unixAttributes.filePermissions
                .contains(.ownerExecute)
        )
        let symbolicLink = try XCTUnwrap(
            entries.first { $0.pathInArchive == "Payload/Host.app/asset-link" }
        )
        XCTAssertTrue(
            symbolicLink.externalAttributes.unixAttributes.contains(
                .isSymbolicLink
            )
        )
        XCTAssertEqual(
            String(decoding: try reader.readFile(symbolicLink), as: UTF8.self),
            "asset.txt"
        )
        let infoPlistEntry = try XCTUnwrap(
            entries.first { $0.pathInArchive == "Payload/Host.app/Info.plist" }
        )
        let infoPlist = try XCTUnwrap(
            PropertyListSerialization.propertyList(
                from: Data(try reader.readFile(infoPlistEntry)),
                options: [],
                format: nil
            ) as? [String: Any]
        )
        XCTAssertEqual(infoPlist["UIDeviceFamily"] as? [Int], [1, 2])
    }

    /// Proves that browser clients can consume a published app-bundle ZIP
    /// directly instead of requiring a separately published unsigned IPA.
    func testWebSignerPackagesAndSignsAppArchive() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeIPAArchiveFixture(
            bundleIdentifier: "app.rork.archive.web",
            includeSymbolicLink: true
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }
        let appArchiveURL = fixture.rootURL.appendingPathComponent(
            "Host.app.zip"
        )
        try IPAArchive.write(
            contentsOf: fixture.rootURL.appendingPathComponent(
                "ArchiveRoot/Payload",
                isDirectory: true
            ),
            to: appArchiveURL,
            compressionMode: .deflated
        )
        let profile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            developerCertificates: [signing.identity.certificateDER],
            entitlements: [
                "application-identifier": "TEAMID1234.app.rork.archive.web",
                "com.apple.developer.team-identifier": "TEAMID1234",
            ]
        )

        let signedIPA = try RorkSigner.signAppArchive(
            try Data(contentsOf: appArchiveURL),
            using: signing.identity,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.archive.web",
                rootProvisioningProfile: profile
            )
        )

        XCTAssertEqual(signedIPA.appBundlePath, "Payload/Host.app")
        let reader = try ZipArchiveReader(buffer: [UInt8](signedIPA.data))
        let entries = try reader.readDirectory()
        let executable = try XCTUnwrap(
            entries.first { $0.pathInArchive == "Payload/Host.app/Host" }
        )
        XCTAssertTrue(
            executable.externalAttributes.unixAttributes.filePermissions
                .contains(.ownerExecute)
        )
        let symbolicLink = try XCTUnwrap(
            entries.first {
                $0.pathInArchive == "Payload/Host.app/asset-link"
            }
        )
        XCTAssertTrue(
            symbolicLink.externalAttributes.unixAttributes.contains(
                .isSymbolicLink
            )
        )
        XCTAssertEqual(
            String(decoding: try reader.readFile(symbolicLink), as: UTF8.self),
            "asset.txt"
        )
    }

    /// Rejects archives that would place unrelated files beside the app in the
    /// IPA's Payload directory.
    func testAppArchiveRejectsTopLevelSiblingEntries() throws {
        let fixture = try makeIPAArchiveFixture(
            bundleIdentifier: "app.rork.archive.sibling"
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }
        let payloadURL = fixture.rootURL.appendingPathComponent(
            "ArchiveRoot/Payload",
            isDirectory: true
        )
        try Data("not part of the app bundle".utf8).write(
            to: payloadURL.appendingPathComponent("README.txt")
        )
        let appArchiveURL = fixture.rootURL.appendingPathComponent(
            "Invalid.app.zip"
        )
        try IPAArchive.write(
            contentsOf: payloadURL,
            to: appArchiveURL,
            compressionMode: .stored
        )

        XCTAssertThrowsError(
            try IPAArchive.withExtractedAppArchive(
                from: appArchiveURL,
                temporaryDirectory: nil
            ) { _ in }
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidArchive(
                    "App archive must contain exactly one top-level .app directory."
                )
            )
        }
    }

    /// Ensures explicit empty ZIP directories survive the filesystem round trip
    /// even though they contribute no file data.
    func testWebSignerPreservesEmptyDirectories() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeIPAArchiveFixture(
            bundleIdentifier: "app.rork.archive.empty-directory",
            includeEmptyDirectory: true
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }
        let profile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            developerCertificates: [signing.identity.certificateDER],
            entitlements: [
                "application-identifier":
                    "TEAMID1234.app.rork.archive.empty-directory",
                "com.apple.developer.team-identifier": "TEAMID1234",
            ]
        )

        let signedIPA = try RorkSigner.signIPA(
            try Data(contentsOf: fixture.archiveURL),
            using: signing.identity,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.archive.empty-directory",
                rootProvisioningProfile: profile
            )
        )

        let reader = try ZipArchiveReader(buffer: [UInt8](signedIPA.data))
        let entries = try reader.readDirectory()
        let directory = try XCTUnwrap(
            entries.first {
                $0.pathInArchive.trimmingCharacters(
                    in: CharacterSet(charactersIn: "/")
                ) == "Payload/Host.app/Empty"
            }
        )
        XCTAssertTrue(directory.isDirectory)
    }
    #endif

    #if !os(WASI) && !os(Windows)
    /// Verifies POSIX extraction restores the executable bit and timestamp
    /// required by downstream bundle signing.
    func testArchiveExtractionRestoresExecutableMetadataOnNativeFilesystems()
        throws
    {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let inputURL = rootURL.appendingPathComponent("Input.ipa")
        let extractedURL = rootURL.appendingPathComponent(
            "Extracted",
            isDirectory: true
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: extractedURL,
            withIntermediateDirectories: true
        )

        let modificationDate = Date(timeIntervalSince1970: 1_700_000_000)
        let writer = ZipArchiveWriter()
        try writer.writeFile(
            filename: "Payload/Host.app/Host",
            contents: Array("executable".utf8),
            metadata: Zip.EntryMetadata(
                modificationDate: modificationDate,
                externalAttributes: .unix([
                    .isRegularFile,
                    .permissions([
                        .ownerReadWriteExecute,
                        .groupReadExecute,
                        .otherReadExecute,
                    ]),
                ])
            )
        )
        try Data(try writer.finalizeBuffer()).write(to: inputURL)

        _ = try IPAArchive.extract(at: inputURL, to: extractedURL)

        let executableURL = extractedURL.appendingPathComponent(
            "Payload/Host.app/Host"
        )
        let attributes = try FileManager.default.attributesOfItem(
            atPath: executableURL.path
        )
        let permissions = try XCTUnwrap(
            attributes[.posixPermissions] as? NSNumber
        )
        let restoredDate = try XCTUnwrap(
            attributes[.modificationDate] as? Date
        )
        XCTAssertNotEqual(permissions.intValue & 0o100, 0)
        XCTAssertEqual(
            restoredDate.timeIntervalSince1970,
            modificationDate.timeIntervalSince1970,
            accuracy: 1
        )
    }
    #endif

    /// Verifies browser-style extraction can retain archive metadata separately
    /// when its workspace cannot represent that metadata reliably.
    func testArchivePreservesMetadataWithoutRestoringItToTheWorkspace()
        throws
    {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let inputURL = rootURL.appendingPathComponent("Input.ipa")
        let extractedURL = rootURL.appendingPathComponent(
            "Extracted",
            isDirectory: true
        )
        let outputURL = rootURL.appendingPathComponent("Output.ipa")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: extractedURL,
            withIntermediateDirectories: true
        )

        let modificationDate = Date(timeIntervalSince1970: 1_700_000_000)
        let writer = ZipArchiveWriter()
        try writer.writeFile(
            filename: "Payload/Host.app/Host",
            contents: Array("executable".utf8),
            metadata: Zip.EntryMetadata(
                modificationDate: modificationDate,
                externalAttributes: .unix([
                    .isRegularFile,
                    .permissions([
                        .ownerReadWriteExecute,
                        .groupReadExecute,
                        .otherReadExecute,
                    ]),
                ])
            )
        )
        try Data(try writer.finalizeBuffer()).write(to: inputURL)

        let extraction = try IPAArchive.extract(
            at: inputURL,
            to: extractedURL,
            metadataRestoration: .skip
        )
        try IPAArchive.write(
            contentsOf: extractedURL,
            to: outputURL,
            compressionMode: .stored,
            preservingMetadataFrom: extraction
        )

        let outputReader = try ZipArchiveReader(
            buffer: [UInt8](try Data(contentsOf: outputURL))
        )
        let outputEntry = try XCTUnwrap(
            try outputReader.readDirectory().first {
                $0.pathInArchive == "Payload/Host.app/Host"
            }
        )
        XCTAssertEqual(outputEntry.fileModification, modificationDate)
        XCTAssertTrue(
            outputEntry.externalAttributes.unixAttributes.filePermissions
                .contains(.ownerExecute)
        )
    }

    /// Protects source data when a caller accidentally places the output archive
    /// inside the directory being serialized.
    func testArchiveWriteRejectsOutputInsideSourceTreeWithoutDeletingIt()
        throws
    {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let sourceURL = rootURL.appendingPathComponent(
            "ArchiveRoot",
            isDirectory: true
        )
        let outputURL = sourceURL.appendingPathComponent("Output.ipa")
        let originalOutput = Data("existing archive".utf8)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: sourceURL,
            withIntermediateDirectories: true
        )
        try Data("source".utf8).write(
            to: sourceURL.appendingPathComponent("source.txt")
        )
        try originalOutput.write(to: outputURL)

        XCTAssertThrowsError(
            try IPAArchive.write(
                contentsOf: sourceURL,
                to: outputURL,
                compressionMode: .stored
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidArchive(
                    "IPA archive output must be outside its source directory: \(outputURL.path)."
                )
            )
        }
        XCTAssertEqual(try Data(contentsOf: outputURL), originalOutput)
    }

    /// Ensures destination preflight never replaces a caller-owned directory
    /// with an archive file.
    func testArchiveWriteRejectsDirectoryDestinationWithoutRemovingIt()
        throws
    {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let sourceURL = rootURL.appendingPathComponent(
            "ArchiveRoot",
            isDirectory: true
        )
        let outputURL = rootURL.appendingPathComponent(
            "Output.ipa",
            isDirectory: true
        )
        let markerURL = outputURL.appendingPathComponent("marker.txt")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: sourceURL,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: outputURL,
            withIntermediateDirectories: true
        )
        try Data("source".utf8).write(
            to: sourceURL.appendingPathComponent("source.txt")
        )
        try Data("marker".utf8).write(to: markerURL)

        XCTAssertThrowsError(
            try IPAArchive.write(
                contentsOf: sourceURL,
                to: outputURL,
                compressionMode: .stored
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidArchive(
                    "IPA archive output path is a directory: \(outputURL.path)."
                )
            )
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: markerURL.path))
    }

    /// Preserves a caller-owned archive when serialization fails before the
    /// staged replacement can be committed.
    func testArchiveWritePreservesExistingDestinationWhenStagingFails()
        throws
    {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let outputURL = rootURL.appendingPathComponent("Output.ipa")
        let originalOutput = Data("existing archive".utf8)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )
        try originalOutput.write(to: outputURL)
        let stagingError = NSError(
            domain: "RorkSignTests",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "staging failed"]
        )

        XCTAssertThrowsError(
            try IPAArchive.writeArchive(
                to: outputURL
            ) { stagedArchiveURL in
                try Data("partial archive".utf8).write(
                    to: stagedArchiveURL
                )
                throw stagingError
            }
        ) { error in
            XCTAssertEqual(
                error as NSError,
                stagingError
            )
        }
        XCTAssertEqual(try Data(contentsOf: outputURL), originalOutput)
        XCTAssertEqual(
            try FileManager.default.contentsOfDirectory(atPath: rootURL.path),
            [outputURL.lastPathComponent]
        )
    }

    /// Confirms a completed archive replaces the previous destination only
    /// after serialization succeeds.
    func testArchiveWriteReplacesExistingDestinationAfterFinalization()
        throws
    {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let sourceURL = rootURL.appendingPathComponent(
            "ArchiveRoot",
            isDirectory: true
        )
        let outputURL = rootURL.appendingPathComponent("Output.ipa")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: sourceURL,
            withIntermediateDirectories: true
        )
        try Data("source".utf8).write(
            to: sourceURL.appendingPathComponent("source.txt")
        )
        try Data("existing archive".utf8).write(to: outputURL)

        try IPAArchive.write(
            contentsOf: sourceURL,
            to: outputURL,
            compressionMode: .stored
        )

        try ZipArchiveReader<ZipFileStorage>.withFile(
            outputURL.path
        ) { reader in
            let entry = try XCTUnwrap(
                try reader.readDirectory().first {
                    $0.pathInArchive == "source.txt"
                }
            )
            XCTAssertEqual(
                try reader.readFile(entry),
                Array("source".utf8)
            )
        }
    }

    /// A failed backup restoration must remain visible alongside the archive
    /// replacement error that triggered it.
    func testBackupArchiveReplacementReportsCommitAndRestorationFailures()
        throws
    {
        let rootURL = URL(fileURLWithPath: "/archive-test")
        let archiveURL = rootURL.appendingPathComponent("Output.ipa")
        let stagedArchiveURL = rootURL.appendingPathComponent("Staged.ipa")
        let backupURL = rootURL.appendingPathComponent("Backup.ipa")
        let commitError = NSError(
            domain: "RorkSignTests",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "commit failed"]
        )
        let restorationError = NSError(
            domain: "RorkSignTests",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "restoration failed"]
        )

        XCTAssertThrowsError(
            try IPAArchive.replaceArchive(
                at: archiveURL,
                with: stagedArchiveURL,
                backingUpOriginalTo: backupURL,
                moveItem: { sourceURL, destinationURL in
                    if sourceURL == archiveURL,
                       destinationURL == backupURL
                    {
                        return
                    }
                    if sourceURL == stagedArchiveURL,
                       destinationURL == archiveURL
                    {
                        throw commitError
                    }
                    if sourceURL == backupURL,
                       destinationURL == archiveURL
                    {
                        throw restorationError
                    }
                    XCTFail(
                        "Unexpected move from \(sourceURL.path) to \(destinationURL.path)."
                    )
                },
                removeItem: { url in
                    XCTFail("Unexpected removal of \(url.path).")
                }
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidArchive(
                    "Archive replacement failed: commit failed. The previous archive could not be restored from \(backupURL.path): restoration failed"
                )
            )
        }
    }

    /// Ensures preserved metadata is reused only when an entry keeps the same
    /// filesystem kind across signing.
    func testArchiveDoesNotReuseSymlinkMetadataForReplacementFile() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let originalRootURL = rootURL.appendingPathComponent(
            "Original",
            isDirectory: true
        )
        let extractedURL = rootURL.appendingPathComponent(
            "Extracted",
            isDirectory: true
        )
        let linkURL = originalRootURL.appendingPathComponent("Current")
        let inputURL = rootURL.appendingPathComponent("Input.ipa")
        let outputURL = rootURL.appendingPathComponent("Output.ipa")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: originalRootURL,
            withIntermediateDirectories: true
        )
        try Data("asset".utf8).write(
            to: originalRootURL.appendingPathComponent("asset.txt")
        )
        try FileManager.default.createSymbolicLink(
            atPath: linkURL.path,
            withDestinationPath: "asset.txt"
        )
        try IPAArchive.write(
            contentsOf: originalRootURL,
            to: inputURL,
            compressionMode: .stored
        )

        let extraction = try IPAArchive.extract(
            at: inputURL,
            to: extractedURL,
            metadataRestoration: .skip
        )
        let extractedLinkURL = extractedURL.appendingPathComponent("Current")
        try FileManager.default.removeItem(at: extractedLinkURL)
        try Data("replacement".utf8).write(to: extractedLinkURL)
        try IPAArchive.write(
            contentsOf: extractedURL,
            to: outputURL,
            compressionMode: .stored,
            preservingMetadataFrom: extraction
        )

        let reader = try ZipArchiveReader(
            buffer: [UInt8](try Data(contentsOf: outputURL))
        )
        let entry = try XCTUnwrap(
            try reader.readDirectory().first {
                $0.pathInArchive == "Current"
            }
        )
        XCTAssertTrue(
            entry.externalAttributes.unixAttributes.contains(.isRegularFile)
        )
        XCTAssertFalse(
            entry.externalAttributes.unixAttributes.contains(.isSymbolicLink)
        )
    }

    #if !os(Windows)
    func testArchiveWritePreservesAnExplicitNonExecutableMachOMode() throws {
        let workspaceURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let rootURL = workspaceURL.appendingPathComponent(
            "ArchiveRoot",
            isDirectory: true
        )
        let appURL = rootURL.appendingPathComponent(
            "Payload/Host.app",
            isDirectory: true
        )
        let executableURL = appURL.appendingPathComponent("Host")
        let archiveURL = workspaceURL.appendingPathComponent("Output.ipa")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: workspaceURL)
        }
        try FileManager.default.createDirectory(
            at: appURL,
            withIntermediateDirectories: true
        )
        try Fixtures.machO64WithCodeSignature().write(to: executableURL)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: executableURL.path
        )

        try IPAArchive.write(
            contentsOf: rootURL,
            to: archiveURL,
            compressionMode: .stored
        )

        try ZipArchiveReader<ZipFileStorage>.withFile(archiveURL.path) {
            reader in
            let entry = try XCTUnwrap(
                try reader.readDirectory().first {
                    $0.pathInArchive == "Payload/Host.app/Host"
                }
            )
            XCTAssertFalse(
                entry.externalAttributes.unixAttributes.filePermissions
                    .contains(.ownerExecute)
            )
        }
    }
    #endif

    #if !os(WASI) && !os(Windows)
    /// Verifies read-only directory metadata is restored after children are
    /// extracted, avoiding blocked writes and timestamp drift.
    func testArchiveRestoresDirectoryMetadataAfterExtractingChildren() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let inputURL = rootURL.appendingPathComponent("Input.ipa")
        let extractedURL = rootURL.appendingPathComponent(
            "Extracted",
            isDirectory: true
        )
        let resourcesURL = extractedURL.appendingPathComponent(
            "Payload/Host.app/Resources",
            isDirectory: true
        )
        addTeardownBlock {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o755],
                ofItemAtPath: resourcesURL.path
            )
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )

        let modificationDate = Date(timeIntervalSince1970: 1_700_000_000)
        let writer = ZipArchiveWriter()
        try writer.writeFile(
            filename: "Payload/Host.app/Resources",
            contents: [],
            metadata: Zip.EntryMetadata(
                modificationDate: modificationDate,
                externalAttributes: .unix([
                    .isDirectory,
                    .permissions([
                        .ownerRead,
                        .ownerExecute,
                        .groupRead,
                        .groupExecute,
                        .otherRead,
                        .otherExecute,
                    ]),
                ])
            )
        )
        try writer.writeFile(
            filename: "Payload/Host.app/Resources/asset.txt",
            contents: Array("asset".utf8)
        )
        try Data(try writer.finalizeBuffer()).write(to: inputURL)

        _ = try IPAArchive.extract(at: inputURL, to: extractedURL)

        XCTAssertEqual(
            try Data(contentsOf: resourcesURL.appendingPathComponent("asset.txt")),
            Data("asset".utf8)
        )
        let attributes = try FileManager.default.attributesOfItem(
            atPath: resourcesURL.path
        )
        XCTAssertEqual(
            (attributes[.posixPermissions] as? NSNumber)?.intValue,
            0o555
        )
        XCTAssertEqual(
            try XCTUnwrap(attributes[.modificationDate] as? Date)
                .timeIntervalSince1970,
            modificationDate.timeIntervalSince1970,
            accuracy: 1
        )
    }
    #endif

    /// Protects UTF-8 archive names used by localized resources and user-owned
    /// bundle files.
    func testArchiveRoundTripsUnicodePaths() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let archiveRootURL = rootURL.appendingPathComponent(
            "ArchiveRoot",
            isDirectory: true
        )
        let resourceURL = archiveRootURL.appendingPathComponent(
            "Payload/Host.app/Resources/日本語😀.txt"
        )
        let archiveURL = rootURL.appendingPathComponent("Input.ipa")
        let extractedURL = rootURL.appendingPathComponent(
            "Extracted",
            isDirectory: true
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: resourceURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data("localized asset".utf8).write(to: resourceURL)

        try FileManager.default.createIPAArchive(
            contentsOf: archiveRootURL,
            at: archiveURL
        )
        try FileManager.default.extractIPAArchive(
            at: archiveURL,
            to: extractedURL
        )

        let extractedResourceURL = extractedURL.appendingPathComponent(
            "Payload/Host.app/Resources/日本語😀.txt"
        )
        XCTAssertEqual(
            try Data(contentsOf: extractedResourceURL),
            Data("localized asset".utf8)
        )
    }

    /// Ensures a malicious ZIP entry cannot write outside the extraction root.
    ///
    /// The output assertion also proves validation happens before a signed
    /// archive can be emitted.
    func testArchiveRejectsParentTraversal() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let inputURL = rootURL.appendingPathComponent("Unsafe.ipa")
        let outputURL = rootURL.appendingPathComponent("Signed.ipa")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )

        let writer = ZipArchiveWriter()
        try writer.writeFile(
            filename: "../outside",
            contents: Array("unsafe".utf8)
        )
        try Data(try writer.finalizeBuffer()).write(to: inputURL)

        XCTAssertThrowsError(
            try RorkSigner.signIPAAdHoc(
                at: inputURL,
                outputURL: outputURL
            )
        ) { error in
            guard case .invalidArchive = error as? RorkSignError else {
                return XCTFail("Expected an invalid archive error, got \(error).")
            }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))
    }

    func testArchiveRejectsBackslashEntryPaths() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let inputURL = rootURL.appendingPathComponent("Unsafe.ipa")
        let extractedURL = rootURL.appendingPathComponent(
            "Extracted",
            isDirectory: true
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )

        let writer = ZipArchiveWriter()
        try writer.writeFile(
            filename: "Payload/Sample.app/Sample",
            contents: Array("unsafe".utf8)
        )

        // The writer rejects backslashes, so equal-length filename replacement
        // creates hostile input without changing the ZIP record layout.
        var archive = Data(try writer.finalizeBuffer())
        let slashPath = Data("Payload/Sample.app/Sample".utf8)
        let backslashPath = Data(#"Payload\Sample.app\Sample"#.utf8)
        var replacementCount = 0
        while let range = archive.range(of: slashPath) {
            archive.replaceSubrange(range, with: backslashPath)
            replacementCount += 1
        }
        XCTAssertEqual(replacementCount, 2)
        try archive.write(to: inputURL)

        XCTAssertThrowsError(
            try IPAArchive.extract(at: inputURL, to: extractedURL)
        ) { error in
            guard case .invalidArchive = error as? RorkSignError else {
                return XCTFail(
                    "Expected an invalid archive error, got \(error)."
                )
            }
        }
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: extractedURL.path)
        )
    }

    /// Ensures a relative symlink is rejected when lexical resolution escapes
    /// the extracted IPA tree.
    func testArchiveRejectsEscapingSymbolicLink() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let inputURL = rootURL.appendingPathComponent("UnsafeLink.ipa")
        let outputURL = rootURL.appendingPathComponent("Signed.ipa")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )

        let writer = ZipArchiveWriter()
        try writer.writeFile(
            filename: "Payload/Host.app/link",
            contents: Array("../../../outside".utf8),
            metadata: Zip.EntryMetadata(
                externalAttributes: .unix([
                    .isSymbolicLink,
                    .permissions([
                        .ownerReadWriteExecute,
                        .groupReadExecute,
                        .otherReadExecute,
                    ]),
                ])
            )
        )
        try Data(try writer.finalizeBuffer()).write(to: inputURL)

        XCTAssertThrowsError(
            try RorkSigner.signIPAAdHoc(
                at: inputURL,
                outputURL: outputURL
            )
        ) { error in
            guard case .invalidArchive = error as? RorkSignError else {
                return XCTFail("Expected an invalid archive error, got \(error).")
            }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))
    }

    /// Ensures archive ordering cannot redirect a later entry through a
    /// previously extracted symbolic link.
    func testArchiveRejectsEntryBelowEarlierSymbolicLink() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let inputURL = rootURL.appendingPathComponent("UnsafeLinkChild.ipa")
        let extractedURL = rootURL.appendingPathComponent(
            "Extracted",
            isDirectory: true
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )

        try archiveWithSymlinkDescendant().write(to: inputURL)

        XCTAssertThrowsError(
            try IPAArchive.extract(at: inputURL, to: extractedURL)
        ) { error in
            guard case .invalidArchive = error as? RorkSignError else {
                return XCTFail("Expected an invalid archive error, got \(error).")
            }
        }
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: extractedURL
                    .appendingPathComponent(
                        "Payload/Host.app/redirected.txt"
                    )
                    .path
            )
        )
    }
}

/// Returns a malformed ZIP whose final entry is below an earlier symlink.
///
/// The production writer correctly refuses to create this hierarchy, so the
/// fixed fixture preserves the hostile entry order needed to exercise the
/// extractor's independent trust boundary.
private func archiveWithSymlinkDescendant() throws -> Data {
    let encodedArchive = [
        "UEsDBBQAAAAAAPiS2FzWMHxaBQAAAAUAAAAbAAAAUGF5bG9hZC9Ib3N0LmFwcC9JbmZvLnBsaXN0cGxpc3RQSwME",
        "FAAAAAAAAAAhAI1yghUIAAAACAAAAAwAAABQYXlsb2FkL0xpbmtIb3N0LmFwcFBLAwQUAAAAAAD4kthceqhLcgoA",
        "AAAKAAAAGwAAAFBheWxvYWQvTGluay9yZWRpcmVjdGVkLnR4dHJlZGlyZWN0ZWRQSwECFAMUAAAAAAD4kthc1jB8",
        "WgUAAAAFAAAAGwAAAAAAAAAAAAAAgAEAAAAAUGF5bG9hZC9Ib3N0LmFwcC9JbmZvLnBsaXN0UEsBAhQDFAAAAAAA",
        "AAAhAI1yghUIAAAACAAAAAwAAAAAAAAAAAAAAP+hPgAAAFBheWxvYWQvTGlua1BLAQIUAxQAAAAAAPiS2Fx6qEty",
        "CgAAAAoAAAAbAAAAAAAAAAAAAACAAXAAAABQYXlsb2FkL0xpbmsvcmVkaXJlY3RlZC50eHRQSwUGAAAAAAMAAwDM",
        "AAAAswAAAAAA",
    ].joined()
    guard let data = Data(base64Encoded: encodedArchive) else {
        throw RorkSignError.invalidArchive(
            "The symbolic-link traversal fixture is invalid."
        )
    }
    return data
}

private struct IPAArchiveFixture {
    let rootURL: URL
    let archiveURL: URL
}

/// Creates a minimal signable IPA through the production archive boundary.
///
/// Optional entry shapes let individual tests cover metadata that is otherwise
/// easy for archive rewrites to drop.
private func makeIPAArchiveFixture(
    bundleIdentifier: String,
    includeSymbolicLink: Bool = false,
    includeEmptyDirectory: Bool = false,
    additionalInfoPlistValues: [String: Any] = [:]
) throws -> IPAArchiveFixture {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let archiveRoot = rootURL.appendingPathComponent("ArchiveRoot", isDirectory: true)
    let appURL = archiveRoot.appendingPathComponent("Payload/Host.app", isDirectory: true)
    try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
    let infoPlist: [String: Any] = [
        "CFBundleIdentifier": bundleIdentifier,
        "CFBundleExecutable": "Host",
    ].merging(additionalInfoPlistValues) { _, additionalValue in
        additionalValue
    }
    try writeInfoPlist(
        infoPlist,
        to: appURL.appendingPathComponent("Info.plist")
    )
    let executableURL = appURL.appendingPathComponent("Host")
    try Fixtures.machO64WithCodeSignature().write(to: executableURL)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o755],
        ofItemAtPath: executableURL.path
    )
    try Data("asset".utf8).write(to: appURL.appendingPathComponent("asset.txt"))
    if includeSymbolicLink {
        try FileManager.default.createSymbolicLink(
            atPath: appURL.appendingPathComponent("asset-link").path,
            withDestinationPath: "asset.txt"
        )
    }
    if includeEmptyDirectory {
        try FileManager.default.createDirectory(
            at: appURL.appendingPathComponent("Empty", isDirectory: true),
            withIntermediateDirectories: true
        )
    }

    let archiveURL = rootURL.appendingPathComponent("Input.ipa")
    try IPAArchive.write(
        contentsOf: archiveRoot,
        to: archiveURL,
        compressionMode: .stored
    )
    return IPAArchiveFixture(rootURL: rootURL, archiveURL: archiveURL)
}

private func unzipArchive(_ archiveURL: URL, under rootURL: URL) throws -> URL {
    let outputURL = rootURL.appendingPathComponent("Extracted-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: outputURL, withIntermediateDirectories: true)
    _ = try IPAArchive.extract(at: archiveURL, to: outputURL)
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
