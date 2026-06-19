#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
import RorkSign
import XCTest

final class BundleSigningTests: XCTestCase {
    func testSignFrameworkAdHocSignsFrameworkDirectly() throws {
        let frameworkURL = try makeFrameworkFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: frameworkURL.deletingLastPathComponent())
        }

        let report = try RorkSigner.signFrameworkAdHoc(at: frameworkURL)

        XCTAssertEqual(report.sealedBundles, [frameworkURL])
        XCTAssertEqual(report.embeddedProvisioningProfiles, [])
        XCTAssertEqual(report.signedCode, [frameworkURL.appendingPathComponent("TestFramework")])

        let codeResourcesURL = frameworkURL.appendingPathComponent("_CodeSignature/CodeResources")
        let codeResources = try Data(contentsOf: codeResourcesURL)
        let executable = try Data(contentsOf: frameworkURL.appendingPathComponent("TestFramework"))
        XCTAssertEqual(try resourceDirectoryHash(inSignedMachO: executable), Data(SHA256.hash(data: codeResources)))
        XCTAssertEqual(
            try infoPlistHash(inSignedMachO: executable),
            Data(SHA256.hash(data: try Data(contentsOf: frameworkURL.appendingPathComponent("Info.plist"))))
        )
    }

    func testSignFrameworkWithCredentialDoesNotEmbedProfileOrDeriveEntitlements() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let frameworkURL = try makeFrameworkFixture(bundleIdentifier: "app.rork.framework.identity")
        let profile = try rawProvisioningProfile(
            bundleIdentifier: "app.rork.host",
            developerCertificates: [fixture.identity.certificateDER]
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: frameworkURL.deletingLastPathComponent())
        }

        let report = try RorkSigner.signFrameworkWithCredential(
            at: frameworkURL,
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            options: FrameworkSigningOptions(codeDirectoryHashingMode: .sha256Only)
        )

        XCTAssertEqual(report.sealedBundles, [frameworkURL])
        XCTAssertEqual(report.embeddedProvisioningProfiles, [])
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

    func testSignFrameworkRejectsNonFrameworkBundle() throws {
        let bundleURL = try makeNestedBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        XCTAssertThrowsError(try RorkSigner.signFrameworkAdHoc(at: bundleURL)) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidBundle("Expected a .framework bundle: \(bundleURL.path).")
            )
        }
    }

    func testSignFrameworkAcceptsCaseVariantFrameworkExtension() throws {
        let frameworkURL = try makeFrameworkFixture(extensionName: "Framework")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: frameworkURL.deletingLastPathComponent())
        }

        let report = try RorkSigner.signFrameworkAdHoc(at: frameworkURL)

        XCTAssertEqual(report.sealedBundles, [frameworkURL])
        XCTAssertEqual(report.signedCode, [frameworkURL.appendingPathComponent("TestFramework")])
    }

    func testSignHostedBundleRestoresInfoPlistAndRemovesTemporaryStub() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeNestedBundleFixture(hostExecutable: Fixtures.machO64DylibWithCodeSignature())
        let hostExecutableURL = bundleURL.deletingLastPathComponent().appendingPathComponent("HostStubSource")
        try Fixtures.machO64WithCodeSignature().write(to: hostExecutableURL)
        let originalInfoPlist = try Data(contentsOf: bundleURL.appendingPathComponent("Info.plist"))
        let hostBundleIdentifier = "app.rork.hosted.host"
        let profile = try rawProvisioningProfile(
            bundleIdentifier: hostBundleIdentifier,
            developerCertificates: [fixture.identity.certificateDER]
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let report = try RorkSigner.signHostedBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            options: HostedBundleSigningOptions(
                hostExecutableURL: hostExecutableURL,
                hostBundleIdentifier: hostBundleIdentifier,
                bundleSigningOptions: BundleSigningOptions(
                    embedProvisioningProfiles: false,
                    codeDirectoryIdentifier: "app.rork.hosted.ignored"
                )
            )
        )

        let stubURL = bundleURL.appendingPathComponent("HostedSigningStub")
        XCTAssertEqual(try Data(contentsOf: bundleURL.appendingPathComponent("Info.plist")), originalInfoPlist)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stubURL.path))
        XCTAssertFalse(report.signedCode.contains(stubURL))
        XCTAssertEqual(
            try report.signedCode.map { try relativePath($0, under: bundleURL) },
            [
                "Frameworks/Nested.framework/Nested",
                "Host",
            ]
        )

        let hostCodeResources = try parseCodeResources(
            Data(contentsOf: bundleURL.appendingPathComponent("_CodeSignature/CodeResources"))
        )
        let files2 = try XCTUnwrap(hostCodeResources["files2"] as? [String: Any])
        XCTAssertNotNil(files2["Host"])
        XCTAssertNil(files2["HostedSigningStub"])

        let originalExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let originalExecutableBlobs = try signatureBlobs(in: originalExecutable)
        XCTAssertNil(originalExecutableBlobs[5])
        XCTAssertNil(originalExecutableBlobs[7])

        let originalCodeDirectories = try XCTUnwrap(
            RorkSigner.checkMachOCodeSignatures(
                at: bundleURL.appendingPathComponent("Host")
            ).first?.codeDirectories
        )
        XCTAssertEqual(
            originalCodeDirectories.map(\.identifier),
            [hostBundleIdentifier, hostBundleIdentifier]
        )

        let nestedCodeDirectories = try XCTUnwrap(
            RorkSigner.checkMachOCodeSignatures(
                at: bundleURL.appendingPathComponent("Frameworks/Nested.framework/Nested")
            ).first?.codeDirectories
        )
        XCTAssertEqual(
            nestedCodeDirectories.map(\.identifier),
            ["app.rork.host.nested", "app.rork.host.nested"]
        )
    }

    func testSignHostedBundleRestoresTemporaryFilesAfterSigningFailure() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeNestedBundleFixture(hostExecutable: Fixtures.machO64DylibWithCodeSignature())
        let hostExecutableURL = bundleURL.deletingLastPathComponent().appendingPathComponent("HostStubSource")
        try Fixtures.machO64WithCodeSignature().write(to: hostExecutableURL)
        let originalInfoPlist = try Data(contentsOf: bundleURL.appendingPathComponent("Info.plist"))
        let profile = try rawProvisioningProfile(
            bundleIdentifier: "app.rork.hosted.other",
            developerCertificates: [fixture.identity.certificateDER]
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        XCTAssertThrowsError(
            try RorkSigner.signHostedBundleWithCredential(
                at: bundleURL,
                provisioningProfileData: profile,
                credentialData: Data(fixture.privateKeyPEM.utf8),
                options: HostedBundleSigningOptions(
                    hostExecutableURL: hostExecutableURL,
                    hostBundleIdentifier: "app.rork.hosted.host"
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidProvisioningProfile(
                    "Provisioning profile does not authorize bundle identifier app.rork.hosted.host."
                )
            )
        }

        XCTAssertEqual(try Data(contentsOf: bundleURL.appendingPathComponent("Info.plist")), originalInfoPlist)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: bundleURL.appendingPathComponent("HostedSigningStub").path
            )
        )
    }

    func testSignBundleAdHocSignsNestedBundlesBeforeParentExecutable() throws {
        let bundleURL = try makeNestedBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let report = try RorkSigner.signBundleAdHoc(at: bundleURL)

        XCTAssertEqual(
            try report.sealedBundles.map { try relativePath($0, under: bundleURL.deletingLastPathComponent()) },
            [
                "Host.app/Frameworks/Nested.framework",
                "Host.app",
            ]
        )
        XCTAssertEqual(
            try report.signedCode.map { try relativePath($0, under: bundleURL) },
            [
                "Frameworks/Nested.framework/Nested",
                "Host",
            ]
        )

        let nestedCodeResourcesURL = bundleURL
            .appendingPathComponent("Frameworks/Nested.framework/_CodeSignature/CodeResources")
        let hostCodeResourcesURL = bundleURL
            .appendingPathComponent("_CodeSignature/CodeResources")
        let nestedCodeResources = try Data(contentsOf: nestedCodeResourcesURL)
        let hostCodeResources = try Data(contentsOf: hostCodeResourcesURL)

        let nestedExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Frameworks/Nested.framework/Nested"))
        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        XCTAssertEqual(try resourceDirectoryHash(inSignedMachO: nestedExecutable), Data(SHA256.hash(data: nestedCodeResources)))
        XCTAssertEqual(try resourceDirectoryHash(inSignedMachO: hostExecutable), Data(SHA256.hash(data: hostCodeResources)))
        XCTAssertEqual(
            try infoPlistHash(inSignedMachO: nestedExecutable),
            Data(SHA256.hash(data: try Data(contentsOf: bundleURL.appendingPathComponent("Frameworks/Nested.framework/Info.plist"))))
        )
        XCTAssertEqual(
            try infoPlistHash(inSignedMachO: hostExecutable),
            Data(SHA256.hash(data: try Data(contentsOf: bundleURL.appendingPathComponent("Info.plist"))))
        )

        let hostCodeResourcesPlist = try parseCodeResources(hostCodeResources)
        let files2 = try XCTUnwrap(hostCodeResourcesPlist["files2"] as? [String: Any])
        XCTAssertNotNil(files2["Frameworks/Nested.framework/Nested"])
        XCTAssertNotNil(files2["Frameworks/Nested.framework/_CodeSignature/CodeResources"])
        XCTAssertNil(files2["Host"])
    }

    func testSignBundleAdHocReusesSignatureCacheForUnchangedCode() throws {
        let bundleURL = try makeNestedBundleFixture()
        let cacheURL = bundleURL.deletingLastPathComponent().appendingPathComponent(".zsign_cache", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let options = BundleSigningOptions(
            signingCache: SigningCacheOptions(directoryURL: cacheURL)
        )

        let firstReport = try RorkSigner.signBundleAdHoc(at: bundleURL, options: options)
        let secondReport = try RorkSigner.signBundleAdHoc(at: bundleURL, options: options)

        XCTAssertEqual(firstReport.cachedCode, [])
        XCTAssertEqual(
            try secondReport.cachedCode.map { try relativePath($0, under: bundleURL) },
            [
                "Frameworks/Nested.framework/Nested",
                "Host",
            ]
        )
        XCTAssertGreaterThanOrEqual(
            try FileManager.default.contentsOfDirectory(atPath: cacheURL.path).count,
            2
        )
    }

    func testSignBundleAdHocCacheInvalidatesWhenResourceSealChanges() throws {
        let bundleURL = try makeNestedBundleFixture()
        let cacheURL = bundleURL.deletingLastPathComponent().appendingPathComponent(".zsign_cache", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let options = BundleSigningOptions(
            signingCache: SigningCacheOptions(directoryURL: cacheURL)
        )

        _ = try RorkSigner.signBundleAdHoc(at: bundleURL, options: options)
        try Data("new root resource".utf8).write(to: bundleURL.appendingPathComponent("added.txt"))
        let report = try RorkSigner.signBundleAdHoc(at: bundleURL, options: options)

        XCTAssertEqual(
            try report.cachedCode.map { try relativePath($0, under: bundleURL) },
            ["Frameworks/Nested.framework/Nested"]
        )
    }

    func testSignBundleAdHocForceCacheRefreshSkipsExistingEntries() throws {
        let bundleURL = try makeNestedBundleFixture()
        let cacheURL = bundleURL.deletingLastPathComponent().appendingPathComponent(".zsign_cache", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        _ = try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(signingCache: SigningCacheOptions(directoryURL: cacheURL))
        )
        let report = try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(
                signingCache: SigningCacheOptions(directoryURL: cacheURL, readExistingEntries: false)
            )
        )

        XCTAssertEqual(report.cachedCode, [])
    }

    func testSignBundleAdHocSignsNestedXCTestBundlesBeforeParentExecutable() throws {
        let bundleURL = try makeNestedBundleFixture()
        let testBundleURL = bundleURL.appendingPathComponent("PlugIns/Tests.xctest", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        try FileManager.default.createDirectory(at: testBundleURL, withIntermediateDirectories: true)
        try writeInfoPlist(
            bundleIdentifier: "app.rork.host.tests",
            executableName: "Tests",
            to: testBundleURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: testBundleURL.appendingPathComponent("Tests"))

        let report = try RorkSigner.signBundleAdHoc(at: bundleURL)

        XCTAssertEqual(
            try report.sealedBundles.map { try relativePath($0, under: bundleURL.deletingLastPathComponent()) },
            [
                "Host.app/Frameworks/Nested.framework",
                "Host.app/PlugIns/Tests.xctest",
                "Host.app",
            ]
        )
        XCTAssertEqual(
            try report.signedCode.map { try relativePath($0, under: bundleURL) },
            [
                "Frameworks/Nested.framework/Nested",
                "PlugIns/Tests.xctest/Tests",
                "Host",
            ]
        )
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: testBundleURL.appendingPathComponent("_CodeSignature/CodeResources").path
            )
        )
    }

    func testSignBundleAdHocSkipsDSYMsAndWatchKitStubsWhenScanningCode() throws {
        let bundleURL = try makeNestedBundleFixture()
        let debugMachOURL = bundleURL.appendingPathComponent(
            "Host.app.dSYM/Contents/Resources/DWARF/Host"
        )
        let watchStubURL = bundleURL.appendingPathComponent("_WatchKitStub/Stub")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        try FileManager.default.createDirectory(
            at: debugMachOURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: watchStubURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace().write(to: debugMachOURL)
        try Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace().write(to: watchStubURL)

        let report = try RorkSigner.signBundleAdHoc(at: bundleURL)

        XCTAssertFalse(try RorkSigner.inspectMachO(Data(contentsOf: debugMachOURL)).hasCodeSignature)
        XCTAssertFalse(try RorkSigner.inspectMachO(Data(contentsOf: watchStubURL)).hasCodeSignature)
        XCTAssertFalse(report.signedCode.contains(debugMachOURL))
        XCTAssertFalse(report.signedCode.contains(watchStubURL))
    }

    func testSignBundleAdHocUsesPerBundleEntitlementsAndProvisioningProfiles() throws {
        let bundleURL = try makeNestedBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let options = BundleSigningOptions(
            defaultEntitlementsXML: entitlementsXML(applicationIdentifier: "TEAMID1234.app.rork.host"),
            entitlementsByBundleIdentifier: [
                "app.rork.host.nested": entitlementsXML(
                    applicationIdentifier: "TEAMID1234.app.rork.host.nested"
                ),
            ],
            provisioningProfilesByBundleIdentifier: [
                "app.rork.host": Data("root profile".utf8),
                "app.rork.host.nested": Data("nested profile".utf8),
            ]
        )

        let report = try RorkSigner.signBundleAdHoc(at: bundleURL, options: options)

        XCTAssertEqual(
            try report.embeddedProvisioningProfiles.map { try relativePath($0, under: bundleURL) },
            [
                "Frameworks/Nested.framework/embedded.mobileprovision",
                "embedded.mobileprovision",
            ]
        )
        XCTAssertEqual(
            try Data(contentsOf: bundleURL.appendingPathComponent("embedded.mobileprovision")),
            Data("root profile".utf8)
        )
        XCTAssertEqual(
            try Data(contentsOf: bundleURL.appendingPathComponent("Frameworks/Nested.framework/embedded.mobileprovision")),
            Data("nested profile".utf8)
        )

        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let nestedExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Frameworks/Nested.framework/Nested"))
        XCTAssertTrue(try entitlementsPayload(inSignedMachO: hostExecutable).contains("TEAMID1234.app.rork.host"))
        XCTAssertTrue(try entitlementsPayload(inSignedMachO: nestedExecutable).contains("TEAMID1234.app.rork.host.nested"))

        let hostResources = try parseCodeResources(
            Data(contentsOf: bundleURL.appendingPathComponent("_CodeSignature/CodeResources"))
        )
        let nestedResources = try parseCodeResources(
            Data(contentsOf: bundleURL.appendingPathComponent("Frameworks/Nested.framework/_CodeSignature/CodeResources"))
        )
        XCTAssertEqual(
            try hash2(for: "embedded.mobileprovision", in: hostResources),
            Data(SHA256.hash(data: Data("root profile".utf8)))
        )
        XCTAssertEqual(
            try hash2(for: "embedded.mobileprovision", in: nestedResources),
            Data(SHA256.hash(data: Data("nested profile".utf8)))
        )
    }

    func testSignBundleAdHocDerivesEntitlementsFromProvisioningProfileWhenNotExplicit() throws {
        let bundleURL = try makeNestedBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let profile = try rawProvisioningProfile(bundleIdentifier: "app.rork.host")

        try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(
                provisioningProfilesByBundleIdentifier: [
                    "app.rork.host": profile,
                ]
            )
        )

        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let entitlements = try entitlementsDictionary(inSignedMachO: hostExecutable)
        XCTAssertEqual(entitlements["application-identifier"] as? String, "TEAMID1234.app.rork.host")
        XCTAssertEqual(entitlements["com.apple.developer.team-identifier"] as? String, "TEAMID1234")
        XCTAssertEqual(entitlements["keychain-access-groups"] as? [String], ["TEAMID1234.app.rork.host"])
    }

    func testSignBundleAdHocOmitsEntitlementsForNonExecuteRootMachO() throws {
        let bundleURL = try makeNestedBundleFixture(
            hostExecutable: Fixtures.machO64DylibWithCodeSignature()
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let profile = try rawProvisioningProfile(bundleIdentifier: "app.rork.host")

        try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(
                provisioningProfilesByBundleIdentifier: [
                    "app.rork.host": profile,
                ]
            )
        )

        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let blobs = try signatureBlobs(in: hostExecutable)
        let codeDirectory = try XCTUnwrap(blobs[0])

        XCTAssertNil(blobs[5])
        XCTAssertNil(blobs[7])
        XCTAssertEqual(codeDirectory.readUInt32BE(at: 24), 3)
        XCTAssertEqual(codeDirectory.readUInt64BE(at: 80), 0)
        XCTAssertEqual(
            nullTerminatedString(in: codeDirectory, offset: Int(codeDirectory.readUInt32BE(at: 48))),
            "TEAMID1234"
        )
    }

    func testSignBundleAdHocUsesRootProvisioningProfileFallback() throws {
        let bundleURL = try makeNestedBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let profile = try rawProvisioningProfile(
            bundleIdentifier: "app.rork.host",
            applicationIdentifier: "TEAMID1234.app.rork.*"
        )

        let report = try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(rootProvisioningProfile: profile)
        )

        XCTAssertEqual(report.embeddedProvisioningProfiles, [bundleURL.appendingPathComponent("embedded.mobileprovision")])
        XCTAssertEqual(try Data(contentsOf: bundleURL.appendingPathComponent("embedded.mobileprovision")), profile)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: bundleURL
                    .appendingPathComponent("Frameworks/Nested.framework/embedded.mobileprovision")
                    .path
            )
        )

        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let nestedExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Frameworks/Nested.framework/Nested"))
        XCTAssertTrue(try entitlementsPayload(inSignedMachO: hostExecutable).contains("TEAMID1234.app.rork.host"))
        if let nestedEntitlements = try signatureBlobs(in: nestedExecutable)[5] {
            let length = Int(nestedEntitlements.readUInt32BE(at: 4))
            let payload = String(decoding: nestedEntitlements.subdata(in: 8..<length), as: UTF8.self)
            XCTAssertFalse(payload.contains("TEAMID1234.app.rork.*"))
        }
    }

    func testSignBundleAdHocRemovesEmbeddedProfilesWhenEmbeddingIsDisabled() throws {
        let bundleURL = try makeNestedBundleFixture()
        let nestedBundleURL = bundleURL.appendingPathComponent("Frameworks/Nested.framework", isDirectory: true)
        let rootProfileURL = bundleURL.appendingPathComponent("embedded.mobileprovision")
        let nestedProfileURL = nestedBundleURL.appendingPathComponent("embedded.mobileprovision")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        try Data("old root profile".utf8).write(to: rootProfileURL)
        try Data("old nested profile".utf8).write(to: nestedProfileURL)

        let report = try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(
                provisioningProfilesByBundleIdentifier: [
                    "app.rork.host": try rawProvisioningProfile(bundleIdentifier: "app.rork.host"),
                    "app.rork.host.nested": try rawProvisioningProfile(bundleIdentifier: "app.rork.host.nested"),
                ],
                embedProvisioningProfiles: false
            )
        )

        XCTAssertEqual(report.embeddedProvisioningProfiles, [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: rootProfileURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: nestedProfileURL.path))

        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let nestedExecutable = try Data(contentsOf: nestedBundleURL.appendingPathComponent("Nested"))
        XCTAssertTrue(try entitlementsPayload(inSignedMachO: hostExecutable).contains("TEAMID1234.app.rork.host"))
        XCTAssertTrue(try entitlementsPayload(inSignedMachO: nestedExecutable).contains("TEAMID1234.app.rork.host.nested"))

        let hostResources = try parseCodeResources(
            Data(contentsOf: bundleURL.appendingPathComponent("_CodeSignature/CodeResources"))
        )
        let nestedResources = try parseCodeResources(
            Data(contentsOf: nestedBundleURL.appendingPathComponent("_CodeSignature/CodeResources"))
        )
        XCTAssertNil((try XCTUnwrap(hostResources["files2"] as? [String: Any]))["embedded.mobileprovision"])
        XCTAssertNil((try XCTUnwrap(nestedResources["files2"] as? [String: Any]))["embedded.mobileprovision"])
    }

    func testSignBundleAdHocCopiesInjectedDylibSealsItAndLoadsItFromRootExecutable() throws {
        let bundleURL = try makeNestedBundleFixture(
            hostExecutable: Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace()
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let dylibURL = bundleURL.deletingLastPathComponent().appendingPathComponent("Hook.dylib")
        try Fixtures.machO64WithCodeSignature().write(to: dylibURL)

        let report = try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(
                dylibInjections: [
                    BundleDylibInjection(sourceURL: dylibURL),
                ]
            )
        )

        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: Data(contentsOf: bundleURL.appendingPathComponent("Host"))),
            [
                MachODylibLoadCommand(path: "@executable_path/Hook.dylib"),
            ]
        )
        XCTAssertEqual(
            try report.signedCode.map { try relativePath($0, under: bundleURL) },
            [
                "Frameworks/Nested.framework/Nested",
                "Hook.dylib",
                "Host",
            ]
        )

        let copiedDylibURL = bundleURL.appendingPathComponent("Hook.dylib")
        let copiedDylib = try Data(contentsOf: copiedDylibURL)
        XCTAssertTrue(try RorkSigner.inspectMachO(copiedDylib).hasCodeSignature)

        let hostResources = try parseCodeResources(
            Data(contentsOf: bundleURL.appendingPathComponent("_CodeSignature/CodeResources"))
        )
        XCTAssertEqual(
            try hash2(for: "Hook.dylib", in: hostResources),
            Data(SHA256.hash(data: copiedDylib))
        )
    }

    func testSignBundleAdHocCopiesInjectedDylibToExecutablePathInstallName() throws {
        let bundleURL = try makeNestedBundleFixture(
            hostExecutable: machO64WithExtraLoadCommandSpace()
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let dylibURL = bundleURL.deletingLastPathComponent().appendingPathComponent("Hook.dylib")
        try Fixtures.machO64WithCodeSignature().write(to: dylibURL)

        let report = try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(
                dylibInjections: [
                    BundleDylibInjection(
                        sourceURL: dylibURL,
                        installName: "@executable_path/Frameworks/Hook.dylib",
                        weak: true
                    ),
                ]
            )
        )

        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: Data(contentsOf: bundleURL.appendingPathComponent("Host"))),
            [
                MachODylibLoadCommand(
                    path: "@executable_path/Frameworks/Hook.dylib",
                    weak: true
                ),
            ]
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: bundleURL.appendingPathComponent("Hook.dylib").path))

        let copiedDylibURL = bundleURL.appendingPathComponent("Frameworks/Hook.dylib")
        let copiedDylib = try Data(contentsOf: copiedDylibURL)
        XCTAssertTrue(try RorkSigner.inspectMachO(copiedDylib).hasCodeSignature)
        XCTAssertTrue(
            try report.signedCode.map { try relativePath($0, under: bundleURL) }
                .contains("Frameworks/Hook.dylib")
        )

        let hostResources = try parseCodeResources(
            Data(contentsOf: bundleURL.appendingPathComponent("_CodeSignature/CodeResources"))
        )
        XCTAssertEqual(
            try hash2(for: "Frameworks/Hook.dylib", in: hostResources),
            Data(SHA256.hash(data: copiedDylib))
        )
    }

    func testSignBundleAdHocRejectsNonMachODylibInjection() throws {
        let bundleURL = try makeNestedBundleFixture(
            hostExecutable: Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace()
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let dylibURL = bundleURL.deletingLastPathComponent().appendingPathComponent("NotADylib.dylib")
        try Data("not a mach-o".utf8).write(to: dylibURL)

        XCTAssertThrowsError(
            try RorkSigner.signBundleAdHoc(
                at: bundleURL,
                options: BundleSigningOptions(
                    dylibInjections: [
                        BundleDylibInjection(sourceURL: dylibURL),
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidBundle("Dylib file is not a supported Mach-O: \(dylibURL.path).")
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: bundleURL.appendingPathComponent("NotADylib.dylib").path))
        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: Data(contentsOf: bundleURL.appendingPathComponent("Host"))),
            []
        )
    }

    func testSignBundleAdHocRejectsMalformedStandaloneCodeWithSwappedMachOMagic() throws {
        let bundleURL = try makeNestedBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try Data([0xfe, 0xed, 0xfa, 0xcf, 0x00, 0x00, 0x00, 0x00])
            .write(to: bundleURL.appendingPathComponent("Helper"))

        XCTAssertThrowsError(try RorkSigner.signBundleAdHoc(at: bundleURL)) { error in
            XCTAssertEqual(error as? RorkSignError, .invalidMachO("Input is not a supported Mach-O file."))
        }
    }

    func testSignBundleAdHocRejectsUnsafeExecutablePathDylibDestination() throws {
        let bundleURL = try makeNestedBundleFixture(
            hostExecutable: Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace()
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let dylibURL = bundleURL.deletingLastPathComponent().appendingPathComponent("Hook.dylib")
        try Fixtures.machO64WithCodeSignature().write(to: dylibURL)

        XCTAssertThrowsError(
            try RorkSigner.signBundleAdHoc(
                at: bundleURL,
                options: BundleSigningOptions(
                    dylibInjections: [
                        BundleDylibInjection(
                            sourceURL: dylibURL,
                            installName: "@executable_path/../Hook.dylib"
                        ),
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidBundle("Dylib bundle-relative path is not safe: ../Hook.dylib.")
            )
        }
    }

    func testSignBundleAdHocRemovesRootExecutableDylibLoadCommandBeforeSigning() throws {
        let host = try RorkSigner.injectDylibLoadCommand(
            into: Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace(),
            path: "@executable_path/OldHook.dylib"
        )
        let bundleURL = try makeNestedBundleFixture(hostExecutable: host)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try Fixtures.machO64WithCodeSignature()
            .write(to: bundleURL.appendingPathComponent("OldHook.dylib"))

        let report = try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(
                dylibLoadCommandsToRemove: ["OldHook.dylib"]
            )
        )

        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: Data(contentsOf: bundleURL.appendingPathComponent("Host"))),
            []
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: bundleURL.appendingPathComponent("OldHook.dylib").path))
        XCTAssertFalse(
            try report.signedCode.map { try relativePath($0, under: bundleURL) }
                .contains("OldHook.dylib")
        )

        let hostResources = try parseCodeResources(
            Data(contentsOf: bundleURL.appendingPathComponent("_CodeSignature/CodeResources"))
        )
        let files2 = try XCTUnwrap(hostResources["files2"] as? [String: Any])
        XCTAssertNil(files2["OldHook.dylib"])
    }

    func testSignBundleAdHocRemovesNestedExecutablePathDylibFileBeforeSigning() throws {
        let host = try RorkSigner.injectDylibLoadCommand(
            into: Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace(),
            path: "@executable_path/Frameworks/OldHook.dylib"
        )
        let bundleURL = try makeNestedBundleFixture(hostExecutable: host)
        let oldDylibURL = bundleURL.appendingPathComponent("Frameworks/OldHook.dylib")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try Fixtures.machO64WithCodeSignature().write(to: oldDylibURL)

        let report = try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(
                dylibLoadCommandsToRemove: ["@executable_path/Frameworks/OldHook.dylib"]
            )
        )

        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: Data(contentsOf: bundleURL.appendingPathComponent("Host"))),
            []
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: oldDylibURL.path))
        XCTAssertFalse(
            try report.signedCode.map { try relativePath($0, under: bundleURL) }
                .contains("Frameworks/OldHook.dylib")
        )

        let hostResources = try parseCodeResources(
            Data(contentsOf: bundleURL.appendingPathComponent("_CodeSignature/CodeResources"))
        )
        let files2 = try XCTUnwrap(hostResources["files2"] as? [String: Any])
        XCTAssertNil(files2["Frameworks/OldHook.dylib"])
    }
}

/// Creates a root app fixture with one nested framework.
private func makeNestedBundleFixture(
    hostExecutable: Data = Fixtures.machO64WithCodeSignature(),
    nestedExecutable: Data = Fixtures.machO64WithCodeSignature()
) throws -> URL {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let bundleURL = rootURL.appendingPathComponent("Host.app", isDirectory: true)
    let frameworkURL = bundleURL.appendingPathComponent("Frameworks/Nested.framework", isDirectory: true)
    try FileManager.default.createDirectory(at: frameworkURL, withIntermediateDirectories: true)

    try writeInfoPlist(
        bundleIdentifier: "app.rork.host",
        executableName: "Host",
        to: bundleURL.appendingPathComponent("Info.plist")
    )
    try writeInfoPlist(
        bundleIdentifier: "app.rork.host.nested",
        executableName: "Nested",
        to: frameworkURL.appendingPathComponent("Info.plist")
    )
    try hostExecutable.write(to: bundleURL.appendingPathComponent("Host"))
    try nestedExecutable.write(to: frameworkURL.appendingPathComponent("Nested"))
    try Data("nested asset".utf8).write(to: frameworkURL.appendingPathComponent("asset.txt"))

    return bundleURL
}

/// Creates a standalone framework fixture.
private func makeFrameworkFixture(
    bundleIdentifier: String = "app.rork.framework",
    executable: Data = Fixtures.machO64DylibWithCodeSignature(),
    extensionName: String = "framework"
) throws -> URL {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let frameworkURL = rootURL.appendingPathComponent("TestFramework.\(extensionName)", isDirectory: true)
    try FileManager.default.createDirectory(at: frameworkURL, withIntermediateDirectories: true)
    try writeInfoPlist(
        bundleIdentifier: bundleIdentifier,
        executableName: "TestFramework",
        to: frameworkURL.appendingPathComponent("Info.plist")
    )
    try executable.write(to: frameworkURL.appendingPathComponent("TestFramework"))
    try Data("framework asset".utf8).write(to: frameworkURL.appendingPathComponent("asset.txt"))
    return frameworkURL
}

/// Writes the minimal bundle metadata required by signing tests.
private func writeInfoPlist(bundleIdentifier: String, executableName: String, to url: URL) throws {
    let plist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict><key>CFBundleIdentifier</key><string>\(bundleIdentifier)</string><key>CFBundleExecutable</key><string>\(executableName)</string></dict></plist>
    """
    try Data(plist.utf8).write(to: url)
}

/// Creates a Mach-O fixture with extra capacity for injected load commands.
private func machO64WithExtraLoadCommandSpace() -> Data {
    var data = Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace()
    data.append(Data(repeating: 0, count: 0x80))
    data.writeUInt64LE(0x1b0, at: 80)
    data.writeUInt32LE(0x180, at: 152)
    return data
}

/// Reads the resource-directory special-slot hash from a signed Mach-O.
private func resourceDirectoryHash(inSignedMachO signed: Data) throws -> Data? {
    let blobs = try signatureBlobs(in: signed)
    let codeDirectory = try XCTUnwrap(blobs[0x1000])
    return specialSlotHash(3, in: codeDirectory)
}

/// Reads the Info.plist special-slot hash from a signed Mach-O.
private func infoPlistHash(inSignedMachO signed: Data) throws -> Data? {
    let blobs = try signatureBlobs(in: signed)
    let codeDirectory = try XCTUnwrap(blobs[0x1000])
    return specialSlotHash(1, in: codeDirectory)
}

/// Reads the XML entitlement payload from a signed Mach-O.
private func entitlementsPayload(inSignedMachO signed: Data) throws -> String {
    let blobs = try signatureBlobs(in: signed)
    let entitlements = try XCTUnwrap(blobs[5])
    let length = Int(entitlements.readUInt32BE(at: 4))
    let payload = entitlements.subdata(in: 8..<length)
    return String(decoding: payload, as: UTF8.self)
}

/// Parses the entitlement payload from a signed Mach-O.
private func entitlementsDictionary(inSignedMachO signed: Data) throws -> [String: Any] {
    let payload = try Data(entitlementsPayload(inSignedMachO: signed).utf8)
    let plist = try PropertyListSerialization.propertyList(from: payload, options: [], format: nil)
    return try XCTUnwrap(plist as? [String: Any])
}

/// Reads a SHA-256 resource hash from a CodeResources dictionary.
private func hash2(for relativePath: String, in codeResources: [String: Any]) throws -> Data {
    let files2 = try XCTUnwrap(codeResources["files2"] as? [String: [String: Any]])
    let entry = try XCTUnwrap(files2[relativePath])
    return try XCTUnwrap(entry["hash2"] as? Data)
}

/// Creates the entitlement plist used by bundle-signing tests.
private func entitlementsXML(applicationIdentifier: String) -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict><key>application-identifier</key><string>\(applicationIdentifier)</string></dict></plist>
    """
}

/// Creates a raw plist provisioning profile for bundle-signing tests.
private func rawProvisioningProfile(
    bundleIdentifier: String,
    applicationIdentifier: String? = nil,
    developerCertificates: [Data] = [Data([0x01])]
) throws -> Data {
    let plist: [String: Any] = [
        "TeamIdentifier": ["TEAMID1234"],
        "ExpirationDate": Date(timeIntervalSince1970: 1_900_000_000),
        "DeveloperCertificates": developerCertificates,
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

/// Returns a validated path relative to a test fixture root.
private func relativePath(_ url: URL, under rootURL: URL) throws -> String {
    let rootPath = rootURL.standardizedFileURL.path
    let path = url.standardizedFileURL.path
    guard path.hasPrefix(rootPath + "/") else {
        throw RorkSignError.invalidBundle("Path escaped root: \(path).")
    }
    return String(path.dropFirst(rootPath.count + 1))
}
