#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
import RorkSign
import XCTest
import ZipArchive

final class PortableCLITests: XCTestCase {
    func testFocusedSignCommandSignsCompleteSyntheticArchive() throws {
        let signing = try SyntheticSigningFixture()
        defer {
            signing.remove()
        }
        let directory = try makePortableDirectory()
        defer {
            try? FileManager.default.removeItem(at: directory)
        }

        let archiveRootURL = directory.appendingPathComponent(
            "ArchiveRoot",
            isDirectory: true
        )
        let appURL = archiveRootURL.appendingPathComponent(
            "Payload/Sample.app",
            isDirectory: true
        )
        let nested = try makePortableApp(
            at: appURL,
            includeNestedBundles: true
        )
        let inputURL = directory.appendingPathComponent("Input.ipa")
        let outputURL = directory.appendingPathComponent("Output.ipa")
        let rootProfileURL = directory.appendingPathComponent(
            "Root.mobileprovision"
        )
        let extensionProfileURL = directory.appendingPathComponent(
            "Extension.mobileprovision"
        )
        let profileMapURL = directory.appendingPathComponent("profiles.json")
        let extractedURL = directory.appendingPathComponent(
            "Extracted",
            isDirectory: true
        )
        let rootIdentifier = "com.example.signed"
        let extensionIdentifier = "\(rootIdentifier).Widget"
        let appGroupIdentifier = "group.example.shared"
        let entitlementsResourceName = "RequestedEntitlements.plist"

        try writePortablePlist(
            [
                "com.apple.developer.networking.networkextension": [
                    "packet-tunnel-provider"
                ]
            ],
            to: appURL.appendingPathComponent(entitlementsResourceName)
        )
        try writePortablePlist(
            [
                "com.apple.developer.networking.networkextension": [
                    "packet-tunnel-provider"
                ]
            ],
            to: nested.extensionURL.appendingPathComponent(
                entitlementsResourceName
            )
        )

        let rootProfile = try portableProvisioningProfile(
            bundleIdentifier: rootIdentifier,
            certificateDER: signing.identity.certificateDER,
            appGroupIdentifier: appGroupIdentifier
        )
        let extensionProfile = try portableProvisioningProfile(
            bundleIdentifier: extensionIdentifier,
            certificateDER: signing.identity.certificateDER,
            appGroupIdentifier: appGroupIdentifier
        )
        try rootProfile.write(to: rootProfileURL)
        try extensionProfile.write(to: extensionProfileURL)
        try JSONSerialization.data(
            withJSONObject: [
                rootIdentifier: rootProfileURL.path,
                extensionIdentifier: extensionProfileURL.lastPathComponent,
            ],
            options: [.sortedKeys]
        ).write(to: profileMapURL)
        try FileManager.default.createIPAArchive(
            contentsOf: archiveRootURL,
            at: inputURL
        )
        try Data("previous output".utf8).write(to: outputURL)

        let result = try runRorkSign([
            "sign", "ipa",
            "--input", inputURL.path,
            "--output", outputURL.path,
            "--bundle-id", rootIdentifier,
            "--profile-map", profileMapURL.path,
            "--certificate", signing.certificateURL.path,
            "--key", signing.privateKeyURL.path,
            "--app-groups", appGroupIdentifier,
            "--bundle-name", "Portable Sample",
            "--entitlements-resource", entitlementsResourceName,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        guard result.status == 0 else {
            return
        }

        try FileManager.default.createDirectory(
            at: extractedURL,
            withIntermediateDirectories: true
        )
        try FileManager.default.extractIPAArchive(
            at: outputURL,
            to: extractedURL
        )
        let signedAppURL = extractedURL.appendingPathComponent(
            "Payload/Sample.app",
            isDirectory: true
        )
        let signedExtensionURL = signedAppURL.appendingPathComponent(
            "PlugIns/Widget.appex",
            isDirectory: true
        )
        let signedFrameworkURL = signedAppURL.appendingPathComponent(
            "Frameworks/Library.framework",
            isDirectory: true
        )
        let rootInfo = try portablePlist(
            at: signedAppURL.appendingPathComponent(
                "Info.plist"
            ))
        let extensionInfo = try portablePlist(
            at: signedExtensionURL.appendingPathComponent("Info.plist")
        )

        XCTAssertEqual(
            rootInfo["CFBundleIdentifier"] as? String,
            rootIdentifier
        )
        XCTAssertEqual(
            extensionInfo["CFBundleIdentifier"] as? String,
            extensionIdentifier
        )
        XCTAssertEqual(
            rootInfo["CFBundleName"] as? String,
            "Portable Sample"
        )
        XCTAssertEqual(
            rootInfo["CFBundleDisplayName"] as? String,
            "Portable Sample"
        )
        XCTAssertEqual(
            try Data(
                contentsOf: signedAppURL.appendingPathComponent(
                    "embedded.mobileprovision"
                )
            ),
            rootProfile
        )
        XCTAssertEqual(
            try Data(
                contentsOf: signedExtensionURL.appendingPathComponent(
                    "embedded.mobileprovision"
                )
            ),
            extensionProfile
        )

        let rootEntitlements = try portableEntitlements(
            in: signedAppURL.appendingPathComponent("Sample")
        )
        let extensionEntitlements = try portableEntitlements(
            in: signedExtensionURL.appendingPathComponent("Widget")
        )
        XCTAssertEqual(
            rootEntitlements["application-identifier"] as? String,
            "TEAMID1234.\(rootIdentifier)"
        )
        XCTAssertEqual(
            extensionEntitlements["application-identifier"] as? String,
            "TEAMID1234.\(extensionIdentifier)"
        )
        XCTAssertEqual(
            rootEntitlements[
                "com.apple.developer.networking.networkextension"
            ] as? [String],
            ["packet-tunnel-provider"]
        )
        XCTAssertEqual(
            extensionEntitlements[
                "com.apple.developer.networking.networkextension"
            ] as? [String],
            ["packet-tunnel-provider"]
        )
        XCTAssertEqual(
            rootEntitlements[
                "com.apple.security.application-groups"
            ] as? [String],
            [appGroupIdentifier]
        )

        XCTAssertTrue(
            try RorkSigner.verifyCodeResources(
                forBundleAt: signedAppURL
            ).isValid
        )
        XCTAssertTrue(
            try RorkSigner.verifyCodeResources(
                forBundleAt: signedExtensionURL
            ).isValid
        )
        XCTAssertTrue(
            try RorkSigner.verifyCodeResources(
                forBundleAt: signedFrameworkURL
            ).isValid
        )
        XCTAssertTrue(
            try RorkSigner.inspectMachO(
                Data(
                    contentsOf: signedFrameworkURL.appendingPathComponent(
                        "Library"
                    )
                )
            ).hasCodeSignature
        )

        try ZipArchiveReader<ZipFileStorage>.withFile(outputURL.path) {
            reader in
            let entries = try reader.readDirectory()
            XCTAssertFalse(
                entries.contains { $0.filename.string.contains("\\") }
            )
            for path in [
                "Payload/Sample.app/Sample",
                "Payload/Sample.app/PlugIns/Widget.appex/Widget",
                "Payload/Sample.app/Frameworks/Library.framework/Library",
            ] {
                let entry = try XCTUnwrap(
                    entries.first { $0.filename.string == path }
                )
                XCTAssertTrue(
                    entry.externalAttributes.unixAttributes.filePermissions
                        .contains(.ownerExecute),
                    path
                )
            }
        }
    }

    func testFocusedSignCommandAcceptsDirectoryInputs() throws {
        let signing = try SyntheticSigningFixture()
        defer {
            signing.remove()
        }
        let directory = try makePortableDirectory()
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let rootIdentifier = "com.example.directory"
        let profileURL = directory.appendingPathComponent(
            "Root.mobileprovision"
        )
        let profileMapURL = directory.appendingPathComponent("profiles.json")
        try portableProvisioningProfile(
            bundleIdentifier: rootIdentifier,
            certificateDER: signing.identity.certificateDER
        ).write(to: profileURL)
        try JSONSerialization.data(
            withJSONObject: [
                rootIdentifier: profileURL.path
            ],
            options: [.sortedKeys]
        ).write(to: profileMapURL)

        let appInputURL = directory.appendingPathComponent(
            "Direct.app",
            isDirectory: true
        )
        try makePortableApp(at: appInputURL)
        let extractedInputURL = directory.appendingPathComponent(
            "ExtractedArchive",
            isDirectory: true
        )
        let extractedAppURL = extractedInputURL.appendingPathComponent(
            "Payload/Extracted.app",
            isDirectory: true
        )
        try makePortableApp(at: extractedAppURL)

        for (inputURL, outputName, expectedAppName) in [
            (appInputURL, "Direct.ipa", "Direct.app"),
            (extractedInputURL, "Extracted.ipa", "Extracted.app"),
        ] {
            let outputURL = directory.appendingPathComponent(outputName)
            let temporaryURL = directory.appendingPathComponent(
                "tmp-\(outputName)",
                isDirectory: true
            )
            try FileManager.default.createDirectory(
                at: temporaryURL,
                withIntermediateDirectories: true
            )
            let result = try runRorkSign([
                "sign", "ipa",
                "--input", inputURL.path,
                "--output", outputURL.path,
                "--bundle-id", rootIdentifier,
                "--profile-map", profileMapURL.path,
                "--certificate", signing.certificateURL.path,
                "--key", signing.privateKeyURL.path,
            ], environment: [
                "TMPDIR": temporaryURL.path,
                "TMP": temporaryURL.path,
                "TEMP": temporaryURL.path,
            ])

            XCTAssertEqual(result.status, 0, result.output)
            guard result.status == 0 else {
                continue
            }
            let remainingWorkspaces = try FileManager.default
                .contentsOfDirectory(atPath: temporaryURL.path)
                .filter { $0.hasPrefix("rorksign-input-") }
            XCTAssertEqual(remainingWorkspaces, [])
            try ZipArchiveReader<ZipFileStorage>.withFile(outputURL.path) {
                reader in
                let entries = try reader.readDirectory()
                let executablePath = "Payload/\(expectedAppName)/Sample"
                let executable = try XCTUnwrap(
                    entries.first { $0.filename.string == executablePath }
                )
                XCTAssertTrue(
                    executable.externalAttributes.unixAttributes
                        .filePermissions.contains(.ownerExecute)
                )
                XCTAssertNotNil(
                    entries.first {
                        $0.filename.string
                            == "Payload/\(expectedAppName)/_CodeSignature/CodeResources"
                    }
                )
            }
        }
    }

    func testExportPKCS12ReencryptsIdentityWithoutExternalTools() throws {
        let signing = try SyntheticSigningFixture()
        defer {
            signing.remove()
        }
        let inputURL = signing.directory.appendingPathComponent("Input.p12")
        let outputURL = signing.directory.appendingPathComponent("Output.p12")
        try signing.identity.pkcs12Representation(password: "input-secret")
            .write(to: inputURL)
        try Data("previous output".utf8).write(to: outputURL)

        let result = try runRorkSign([
            "export-pkcs12",
            "--certificate", signing.certificateURL.path,
            "--key", inputURL.path,
            "--input-password", "input-secret",
            "--output", outputURL.path,
            "--output-password", "output-secret",
        ])

        XCTAssertEqual(result.status, 0, result.output)
        guard result.status == 0 else {
            return
        }
        let exportedData = try Data(contentsOf: outputURL)
        #if !os(Windows)
        let permissions = try XCTUnwrap(
            FileManager.default.attributesOfItem(
                atPath: outputURL.path
            )[.posixPermissions] as? NSNumber
        )
        XCTAssertEqual(permissions.intValue & 0o777, 0o600)
        #endif
        let stagedFiles = try FileManager.default.contentsOfDirectory(
            atPath: outputURL.deletingLastPathComponent().path
        ).filter {
            $0.hasPrefix(".\(outputURL.lastPathComponent).")
        }
        XCTAssertEqual(stagedFiles, [])
        let imported = try SigningIdentity(
            pkcs12Data: exportedData,
            password: "output-secret"
        )
        XCTAssertEqual(
            imported.certificateDER,
            signing.identity.certificateDER
        )
        XCTAssertThrowsError(
            try SigningIdentity(
                pkcs12Data: exportedData,
                password: "input-secret"
            )
        )
    }

    func testExportPKCS12LeavesExistingOutputAfterInputFailure() throws {
        let signing = try SyntheticSigningFixture()
        defer {
            signing.remove()
        }
        let inputURL = signing.directory.appendingPathComponent("Input.p12")
        let outputURL = signing.directory.appendingPathComponent("Output.p12")
        let previousOutput = Data("previous output".utf8)
        try signing.identity.pkcs12Representation(password: "input-secret")
            .write(to: inputURL)
        try previousOutput.write(to: outputURL)

        let result = try runRorkSign([
            "export-pkcs12",
            "--certificate", signing.certificateURL.path,
            "--key", inputURL.path,
            "--input-password", "wrong-secret",
            "--output", outputURL.path,
            "--output-password", "output-secret",
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertEqual(try Data(contentsOf: outputURL), previousOutput)
    }

    func testExportPKCS12RejectsAnEmptyOutputPassword() throws {
        let signing = try SyntheticSigningFixture()
        defer {
            signing.remove()
        }
        let outputURL = signing.directory.appendingPathComponent("Output.p12")

        let result = try runRorkSign([
            "export-pkcs12",
            "--certificate", signing.certificateURL.path,
            "--key", signing.privateKeyURL.path,
            "--output", outputURL.path,
            "--output-password", "",
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.contains("Output password must not be empty."))
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))
    }
}

private struct PortableNestedBundles {
    let extensionURL: URL
    let frameworkURL: URL
}

@discardableResult
private func makePortableApp(
    at appURL: URL,
    includeNestedBundles: Bool = false
) throws -> PortableNestedBundles {
    let extensionURL = appURL.appendingPathComponent(
        "PlugIns/Widget.appex",
        isDirectory: true
    )
    let frameworkURL = appURL.appendingPathComponent(
        "Frameworks/Library.framework",
        isDirectory: true
    )
    try FileManager.default.createDirectory(
        at: includeNestedBundles ? extensionURL : appURL,
        withIntermediateDirectories: true
    )
    try writePortablePlist(
        [
            "CFBundleIdentifier": "com.example.original",
            "CFBundleExecutable": "Sample",
            "CFBundleName": "Original",
            "CFBundleDisplayName": "Original",
        ],
        to: appURL.appendingPathComponent("Info.plist")
    )
    let appExecutableURL = appURL.appendingPathComponent("Sample")
    try Fixtures.machO64WithCodeSignature().write(
        to: appExecutableURL
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o755],
        ofItemAtPath: appExecutableURL.path
    )
    try Data("asset".utf8).write(
        to: appURL.appendingPathComponent("asset.txt")
    )

    if includeNestedBundles {
        try FileManager.default.createDirectory(
            at: frameworkURL,
            withIntermediateDirectories: true
        )
        try writePortablePlist(
            [
                "CFBundleIdentifier": "com.example.original.Widget",
                "CFBundleExecutable": "Widget",
                "NSExtension": [
                    "NSExtensionPointIdentifier":
                        "com.apple.widgetkit-extension"
                ],
            ],
            to: extensionURL.appendingPathComponent("Info.plist")
        )
        let extensionExecutableURL = extensionURL
            .appendingPathComponent("Widget")
        try Fixtures.machO64WithCodeSignature().write(
            to: extensionExecutableURL
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: extensionExecutableURL.path
        )
        try writePortablePlist(
            [
                "CFBundleIdentifier": "com.example.original.Library",
                "CFBundleExecutable": "Library",
            ],
            to: frameworkURL.appendingPathComponent("Info.plist")
        )
        let frameworkExecutableURL = frameworkURL
            .appendingPathComponent("Library")
        try Fixtures.machO64DylibWithCodeSignature().write(
            to: frameworkExecutableURL
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: frameworkExecutableURL.path
        )
    }

    return PortableNestedBundles(
        extensionURL: extensionURL,
        frameworkURL: frameworkURL
    )
}

private func portableProvisioningProfile(
    bundleIdentifier: String,
    certificateDER: Data,
    appGroupIdentifier: String? = nil
) throws -> Data {
    var entitlements: [String: Any] = [
        "application-identifier": "TEAMID1234.\(bundleIdentifier)",
        "com.apple.developer.team-identifier": "TEAMID1234",
        "com.apple.developer.networking.networkextension": [
            "app-proxy-provider",
            "packet-tunnel-provider",
        ],
    ]
    if let appGroupIdentifier {
        entitlements["com.apple.security.application-groups"] = [
            appGroupIdentifier
        ]
    }
    return try PropertyListSerialization.data(
        fromPropertyList: [
            "TeamIdentifier": ["TEAMID1234"],
            "ExpirationDate": Date(timeIntervalSince1970: 2_400_000_000),
            "DeveloperCertificates": [certificateDER],
            "Entitlements": entitlements,
        ],
        format: .xml,
        options: 0
    )
}

private func makePortableDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true
    )
    return directory
}

private func writePortablePlist(
    _ dictionary: [String: Any],
    to url: URL
) throws {
    let data = try PropertyListSerialization.data(
        fromPropertyList: dictionary,
        format: .xml,
        options: 0
    )
    try data.write(to: url)
}

private func portablePlist(at url: URL) throws -> [String: Any] {
    let value = try PropertyListSerialization.propertyList(
        from: Data(contentsOf: url),
        options: [],
        format: nil
    )
    return try XCTUnwrap(value as? [String: Any])
}

private func portableEntitlements(in url: URL) throws -> [String: Any] {
    let signed = try Data(contentsOf: url)
    let entitlements = try XCTUnwrap(signatureBlobs(in: signed)[5])
    guard entitlements.count >= 8 else {
        XCTFail("The entitlements blob is missing its header.")
        throw CocoaError(.fileReadCorruptFile)
    }
    let length = Int(entitlements.readUInt32BE(at: 4))
    guard length >= 8, length <= entitlements.count else {
        XCTFail("The entitlements blob has an invalid length.")
        throw CocoaError(.fileReadCorruptFile)
    }
    let value = try PropertyListSerialization.propertyList(
        from: entitlements.subdata(in: 8..<length),
        options: [],
        format: nil
    )
    return try XCTUnwrap(value as? [String: Any])
}
