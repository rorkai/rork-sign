import Foundation
import RorkSign
import XCTest

final class CLITests: XCTestCase {
    func testDefaultCommandAcceptsZSignStyleAdHocMachOFlags() throws {
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        let outputURL = fixture.directory.appendingPathComponent("Output")
        try Fixtures.machO64WithCodeSignature().write(to: inputURL)

        let result = try runRorkSign([
            "-a",
            "-b", "com.example.cli",
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("signed=\(outputURL.path)"))
        XCTAssertTrue(try RorkSigner.inspectMachO(Data(contentsOf: outputURL)).hasCodeSignature)
    }

    func testDefaultCommandInjectsSingleMachODylibInstallName() throws {
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        let outputURL = fixture.directory.appendingPathComponent("Output")
        try Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace().write(to: inputURL)

        let result = try runRorkSign([
            "-l", "@executable_path/Hook.dylib",
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("signed=\(outputURL.path)"))
        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: Data(contentsOf: outputURL)),
            [
                MachODylibLoadCommand(path: "@executable_path/Hook.dylib"),
            ]
        )
        XCTAssertFalse(try RorkSigner.inspectMachO(Data(contentsOf: outputURL)).hasCodeSignature)
    }

    func testDefaultCommandInjectsWeakSingleMachODylibInstallName() throws {
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        let outputURL = fixture.directory.appendingPathComponent("Output")
        try Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace().write(to: inputURL)

        let result = try runRorkSign([
            "-w",
            "-l", "@rpath/Optional.framework/Optional",
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: Data(contentsOf: outputURL)),
            [
                MachODylibLoadCommand(path: "@rpath/Optional.framework/Optional", weak: true),
            ]
        )
    }

    func testDefaultCommandInfersBundleIdentifierForAppExecutableSigning() throws {
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let appURL = fixture.directory.appendingPathComponent("Fixture.app", isDirectory: true)
        let executableURL = appURL.appendingPathComponent("Fixture")
        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.inferred",
                "CFBundleExecutable": "Fixture",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace().write(to: executableURL)

        let result = try runRorkSign([
            "-a",
            "-l", "@executable_path/Hook.dylib",
            executableURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        let signedData = try Data(contentsOf: executableURL)
        XCTAssertTrue(try RorkSigner.inspectMachO(signedData).hasCodeSignature)
        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: signedData),
            [
                MachODylibLoadCommand(path: "@executable_path/Hook.dylib"),
            ]
        )
    }

    func testDefaultCommandInfersBundleIdentifierForExtensionExecutableSigning() throws {
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let extensionURL = fixture.directory.appendingPathComponent("Share.appex", isDirectory: true)
        let executableURL = extensionURL.appendingPathComponent("Share")
        try FileManager.default.createDirectory(at: extensionURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.share",
                "CFBundleExecutable": "Share",
            ],
            to: extensionURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace().write(to: executableURL)

        let result = try runRorkSign([
            "-a",
            "-l", "@executable_path/Hook.dylib",
            executableURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        let signedData = try Data(contentsOf: executableURL)
        XCTAssertTrue(try RorkSigner.inspectMachO(signedData).hasCodeSignature)
        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: signedData),
            [
                MachODylibLoadCommand(path: "@executable_path/Hook.dylib"),
            ]
        )
    }

    func testDefaultCommandSignsMachOWithEncryptedPrivateKeyPEM() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        let outputURL = fixture.directory.appendingPathComponent("Output")
        let encryptedKeyURL = fixture.directory.appendingPathComponent("EncryptedKey.pem")
        try Fixtures.machO64WithCodeSignature().write(to: inputURL)
        try signing.encryptedPrivateKeyPEM(password: "secret").write(to: encryptedKeyURL, atomically: true, encoding: .utf8)

        let result = try runRorkSign([
            "-c", signing.certificateURL.path,
            "-k", encryptedKeyURL.path,
            "-p", "secret",
            "-b", "com.example.cli.encrypted-key",
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        let blobs = try signatureBlobs(in: Data(contentsOf: outputURL))
        let codeDirectory = try XCTUnwrap(blobs[0])
        let cmsBlob = try XCTUnwrap(blobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
        try signing.verifyDetachedCMS(
            cmsBlob.subdata(in: 8..<cmsLength),
            content: codeDirectory
        )
    }

    func testDefaultCommandSignsMachOWithPEMCertificateAndEncryptedDERPrivateKey() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        let outputURL = fixture.directory.appendingPathComponent("Output")
        let encryptedKeyURL = fixture.directory.appendingPathComponent("EncryptedKey.der")
        try Fixtures.machO64WithCodeSignature().write(to: inputURL)
        try signing.encryptedPrivateKeyDER(password: "secret").write(to: encryptedKeyURL)

        let result = try runRorkSign([
            "-c", signing.certificateURL.path,
            "-k", encryptedKeyURL.path,
            "-p", "secret",
            "-b", "com.example.cli.mixed-key",
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        let blobs = try signatureBlobs(in: Data(contentsOf: outputURL))
        let codeDirectory = try XCTUnwrap(blobs[0])
        let cmsBlob = try XCTUnwrap(blobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
        try signing.verifyDetachedCMS(
            cmsBlob.subdata(in: 8..<cmsLength),
            content: codeDirectory
        )
    }

    func testDefaultCommandSignsMachOWithPEMCertificateAndPKCS12Credential() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        let outputURL = fixture.directory.appendingPathComponent("Output")
        let pkcs12URL = fixture.directory.appendingPathComponent("Identity.p12")
        try Fixtures.machO64WithCodeSignature().write(to: inputURL)
        try signing.pkcs12(password: "secret", useAES: true).write(to: pkcs12URL)

        let result = try runRorkSign([
            "-c", signing.certificateURL.path,
            "-k", pkcs12URL.path,
            "-p", "secret",
            "-b", "com.example.cli.cert-p12",
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        let blobs = try signatureBlobs(in: Data(contentsOf: outputURL))
        let codeDirectory = try XCTUnwrap(blobs[0])
        let cmsBlob = try XCTUnwrap(blobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
        try signing.verifyDetachedCMS(
            cmsBlob.subdata(in: 8..<cmsLength),
            content: codeDirectory
        )
    }

    func testDefaultCommandSignsMachOWithTraditionalEncryptedPrivateKeyPEM() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        let outputURL = fixture.directory.appendingPathComponent("Output")
        let encryptedKeyURL = fixture.directory.appendingPathComponent("TraditionalEncryptedKey.pem")
        try Fixtures.machO64WithCodeSignature().write(to: inputURL)
        try signing.traditionalEncryptedPrivateKeyPEM(password: "secret", cipher: .aes256CBC)
            .write(to: encryptedKeyURL, atomically: true, encoding: .utf8)

        let result = try runRorkSign([
            "-c", signing.certificateURL.path,
            "-k", encryptedKeyURL.path,
            "-p", "secret",
            "-b", "com.example.cli.traditional-encrypted-key",
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        let blobs = try signatureBlobs(in: Data(contentsOf: outputURL))
        let codeDirectory = try XCTUnwrap(blobs[0])
        let cmsBlob = try XCTUnwrap(blobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
        try signing.verifyDetachedCMS(
            cmsBlob.subdata(in: 8..<cmsLength),
            content: codeDirectory
        )
    }

    func testDefaultCommandWritesDebugSignatureArtifacts() throws {
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        let outputURL = fixture.directory.appendingPathComponent("Output")
        let entitlementsURL = fixture.directory.appendingPathComponent("Entitlements.plist")
        let debugDirectoryURL = fixture.directory.appendingPathComponent(".zsign_debug", isDirectory: true)
        try Fixtures.machO64WithCodeSignature().write(to: inputURL)
        try Data(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>
            """.utf8
        ).write(to: entitlementsURL)

        let result = try runRorkSign(
            [
                "-a",
                "-d",
                "-b", "com.example.cli.debug",
                "-e", entitlementsURL.path,
                "-o", outputURL.path,
                inputURL.path,
            ],
            currentDirectoryURL: fixture.directory
        )

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains(".zsign_debug"), result.output)
        XCTAssertTrue(FileManager.default.fileExists(atPath: debugDirectoryURL.appendingPathComponent("CodeSignature.blob.new").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: debugDirectoryURL.appendingPathComponent("CodeDirectory_SHA1.slot.new").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: debugDirectoryURL.appendingPathComponent("CodeDirectory_SHA256.slot.new").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: debugDirectoryURL.appendingPathComponent("Requirements.slot.new").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: debugDirectoryURL.appendingPathComponent("Entitlements.slot.new").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: debugDirectoryURL.appendingPathComponent("Entitlements.der.slot.new").path))

        let entitlements = try String(
            contentsOf: debugDirectoryURL.appendingPathComponent("Entitlements.plist.new"),
            encoding: .utf8
        )
        XCTAssertTrue(entitlements.contains("get-task-allow"), entitlements)
    }

    func testNamedInspectSubcommandKeepsItsPositionalArgument() throws {
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        try Fixtures.machO64WithCodeSignature().write(to: inputURL)

        let result = try runRorkSign([
            "inspect",
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("kind=machO64"))
        XCTAssertTrue(result.output.contains("codeSignature=true"))
    }

    func testDefaultCommandCanExtractMetadataWithoutSigning() throws {
        let fixture = try makeCLIFixture()
        let appURL = fixture.directory.appendingPathComponent("Host.app", isDirectory: true)
        let metadataURL = fixture.directory.appendingPathComponent("Metadata", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.metadata",
                "CFBundleName": "CLI Fixture",
                "CFBundleVersion": "1",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )

        let result = try runRorkSign([
            "-x", metadataURL.path,
            appURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("metadata=\(metadataURL.appendingPathComponent("metadata.json").path)"))
        let metadata = try JSONDecoder().decode(
            AppMetadataReport.self,
            from: Data(contentsOf: metadataURL.appendingPathComponent("metadata.json"))
        )
        XCTAssertEqual(metadata.appBundleIdentifier, "com.example.cli.metadata")
        XCTAssertEqual(metadata.appName, "CLI Fixture")
    }

    func testDefaultCommandExtractsMetadataFromWrapperDirectory() throws {
        let fixture = try makeCLIFixture()
        let wrapperURL = fixture.directory.appendingPathComponent("Wrapper", isDirectory: true)
        let appURL = wrapperURL.appendingPathComponent("Products/Host.app", isDirectory: true)
        let metadataURL = fixture.directory.appendingPathComponent("Metadata", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.metadata.wrapper",
                "CFBundleName": "Wrapped Fixture",
                "CFBundleVersion": "1",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )

        let result = try runRorkSign([
            "-x", metadataURL.path,
            wrapperURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        let metadata = try JSONDecoder().decode(
            AppMetadataReport.self,
            from: Data(contentsOf: metadataURL.appendingPathComponent("metadata.json"))
        )
        XCTAssertEqual(metadata.appBundleIdentifier, "com.example.cli.metadata.wrapper")
        XCTAssertEqual(metadata.appName, "Wrapped Fixture")
    }

    /// Confirms archive structure, rather than the filename extension,
    /// determines whether metadata extraction follows the IPA path.
    func testMetadataSubcommandTreatsZipLikeIPAArchive() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.zip")
        let metadataURL = fixture.directory.appendingPathComponent("Metadata", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.metadata.zip",
                "CFBundleName": "ZIP Fixture",
                "CFBundleVersion": "1",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "metadata",
            inputURL.path,
            metadataURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        let metadata = try JSONDecoder().decode(
            AppMetadataReport.self,
            from: Data(contentsOf: metadataURL.appendingPathComponent("metadata.json"))
        )
        XCTAssertEqual(metadata.appBundleIdentifier, "com.example.cli.metadata.zip")
        XCTAssertEqual(metadata.appName, "ZIP Fixture")
    }

    /// Protects the CLI path that accepts an already extracted IPA tree and
    /// still emits a sealed, compressed, installable archive.
    func testDefaultCommandSignsExtractedIPAFolderAndWritesOutputArchive() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.extracted",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))

        let result = try runRorkSign([
            "-a",
            "-z", "9",
            "-o", outputURL.path,
            archiveRootURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(FileManager.default.fileExists(atPath: outputURL.path))

        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let signedExecutableURL = extractedURL.appendingPathComponent("Payload/Host.app/Host")
        XCTAssertTrue(try RorkSigner.inspectMachO(Data(contentsOf: signedExecutableURL)).hasCodeSignature)
        XCTAssertTrue(try isArchiveEntryCompressed("Payload/Host.app/Host", in: outputURL))
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: extractedURL.appendingPathComponent("Payload/Host.app/_CodeSignature/CodeResources").path
            )
        )
    }

    /// Verifies that requesting archive output for a bare app bundle adds the
    /// required IPA container without changing the bundle-signing behavior.
    func testDefaultCommandSignsAppBundleAndWritesOutputArchive() throws {
        let fixture = try makeCLIFixture()
        let appURL = fixture.directory.appendingPathComponent("Host.app", isDirectory: true)
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.app-output",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))

        let result = try runRorkSign([
            "-a",
            "-o", outputURL.path,
            appURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(FileManager.default.fileExists(atPath: outputURL.path))
        XCTAssertTrue(try RorkSigner.inspectMachO(Data(contentsOf: appURL.appendingPathComponent("Host"))).hasCodeSignature)
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: appURL.appendingPathComponent("_CodeSignature/CodeResources").path
            )
        )

        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let archivedAppURL = extractedURL.appendingPathComponent("Payload/Host.app")
        XCTAssertTrue(try RorkSigner.inspectMachO(Data(contentsOf: archivedAppURL.appendingPathComponent("Host"))).hasCodeSignature)
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: archivedAppURL.appendingPathComponent("_CodeSignature/CodeResources").path
            )
        )
    }

    func testDefaultCommandDiscoversAppInsideWrapperDirectory() throws {
        let fixture = try makeCLIFixture()
        let wrapperURL = fixture.directory.appendingPathComponent("Wrapper", isDirectory: true)
        let ignoredURL = wrapperURL.appendingPathComponent("__MACOSX/Ignored.app", isDirectory: true)
        let appURL = wrapperURL.appendingPathComponent("Products/Host.app", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: ignoredURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.wrapper",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))

        let result = try runRorkSign([
            "-a",
            wrapperURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("sealed=1 signed=1"), result.output)
        XCTAssertTrue(try RorkSigner.inspectMachO(Data(contentsOf: appURL.appendingPathComponent("Host"))).hasCodeSignature)
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: appURL.appendingPathComponent("_CodeSignature/CodeResources").path
            )
        )
    }

    func testDefaultCommandSignsTopLevelAppExtensionBundle() throws {
        let fixture = try makeCLIFixture()
        let extensionURL = fixture.directory.appendingPathComponent("Widget.appex", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: extensionURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.widget",
                "CFBundleExecutable": "Widget",
            ],
            to: extensionURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: extensionURL.appendingPathComponent("Widget"))

        let result = try runRorkSign([
            "-a",
            extensionURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("sealed=1 signed=1"), result.output)
        XCTAssertTrue(try RorkSigner.inspectMachO(Data(contentsOf: extensionURL.appendingPathComponent("Widget"))).hasCodeSignature)
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: extensionURL.appendingPathComponent("_CodeSignature/CodeResources").path
            )
        )
    }

    func testDefaultCommandUsesSigningCacheUnlessForced() throws {
        let fixture = try makeCLIFixture()
        let appURL = fixture.directory.appendingPathComponent("Host.app", isDirectory: true)
        let executableURL = appURL.appendingPathComponent("Host")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.cache",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: executableURL)

        let first = try runRorkSign(
            ["-a", "-V", appURL.path],
            currentDirectoryURL: fixture.directory
        )
        let second = try runRorkSign(
            ["-a", "-V", appURL.path],
            currentDirectoryURL: fixture.directory
        )
        let forced = try runRorkSign(
            ["-a", "-f", "-V", appURL.path],
            currentDirectoryURL: fixture.directory
        )

        XCTAssertEqual(first.status, 0, first.output)
        XCTAssertFalse(first.output.contains("cachedCode="), first.output)
        XCTAssertEqual(second.status, 0, second.output)
        XCTAssertTrue(second.output.contains("cachedCode=\(executableURL.path)"), second.output)
        XCTAssertEqual(forced.status, 0, forced.output)
        XCTAssertFalse(forced.output.contains("cachedCode="), forced.output)
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(
                atPath: fixture.directory.appendingPathComponent(".zsign_cache").path
            )
            .isEmpty
        )
    }

    func testDefaultCommandAppliesAppSigningMetadataRewriteFlags() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let profileURL = fixture.directory.appendingPathComponent("Wildcard.mobileprovision")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.original",
                "CFBundleExecutable": "Host",
                "CFBundleName": "Original",
                "CFBundleDisplayName": "Original",
                "CFBundleVersion": "1",
                "CFBundleShortVersionString": "1.0",
                "MinimumOSVersion": "13.0",
                "UISupportedDevices": ["iPhone10,1"],
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        let profile = try cliProvisioningProfile(
            bundleIdentifier: "com.example.rewritten",
            certificateDER: Data([0x01]),
            applicationIdentifier: "TEAMID1234.*"
        )
        try profile.write(to: profileURL)
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-a",
            "-b", "com.example.rewritten",
            "-n", "Rewritten App",
            "-r", "2.3.4",
            "-M", "15.0",
            "-S",
            "-U",
            "-m", profileURL.path,
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let signedAppURL = extractedURL.appendingPathComponent("Payload/Host.app")
        let info = try cliPlistDictionary(at: signedAppURL.appendingPathComponent("Info.plist"))

        XCTAssertEqual(info["CFBundleIdentifier"] as? String, "com.example.rewritten")
        XCTAssertEqual(info["CFBundleName"] as? String, "Rewritten App")
        XCTAssertEqual(info["CFBundleDisplayName"] as? String, "Rewritten App")
        XCTAssertEqual(info["CFBundleVersion"] as? String, "2.3.4")
        XCTAssertEqual(info["CFBundleShortVersionString"] as? String, "2.3.4")
        XCTAssertEqual(info["MinimumOSVersion"] as? String, "15.0")
        XCTAssertEqual(info["UISupportsDocumentBrowser"] as? Bool, true)
        XCTAssertEqual(info["UIFileSharingEnabled"] as? Bool, true)
        XCTAssertNil(info["UISupportedDevices"])
        XCTAssertEqual(
            try Data(contentsOf: signedAppURL.appendingPathComponent("embedded.mobileprovision")),
            profile
        )
        XCTAssertTrue(try RorkSigner.inspectMachO(Data(contentsOf: signedAppURL.appendingPathComponent("Host"))).hasCodeSignature)
    }

    func testSignIPACommandSignsNestedProfilesFromJSONMap() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let extensionURL = appURL.appendingPathComponent("PlugIns/Widget.appex", isDirectory: true)
        let frameworkURL = appURL.appendingPathComponent("Frameworks/Nested.framework", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let rootProfileURL = fixture.directory.appendingPathComponent("Root.mobileprovision")
        let extensionProfileURL = fixture.directory.appendingPathComponent("Widget.mobileprovision")
        let profileMapURL = fixture.directory.appendingPathComponent("profiles.json")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: extensionURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: frameworkURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.original",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.original.Widget",
                "CFBundleExecutable": "Widget",
                "NSExtension": [
                    "NSExtensionPointIdentifier": "com.apple.widgetkit-extension",
                ],
            ],
            to: extensionURL.appendingPathComponent("Info.plist")
        )
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.original.Nested",
                "CFBundleExecutable": "Nested",
            ],
            to: frameworkURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        try Fixtures.machO64WithCodeSignature().write(to: extensionURL.appendingPathComponent("Widget"))
        try Fixtures.machO64DylibWithCodeSignature().write(to: frameworkURL.appendingPathComponent("Nested"))
        let entitlementsResourceName = "FixtureEntitlements.plist"
        try writeCLIInfoPlist(
            [
                "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
            ],
            to: appURL.appendingPathComponent(entitlementsResourceName)
        )
        try writeCLIInfoPlist(
            [
                "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
            ],
            to: extensionURL.appendingPathComponent(entitlementsResourceName)
        )

        let rootProfile = try cliProvisioningProfile(
            bundleIdentifier: "com.example.rewritten",
            certificateDER: signing.identity.certificateDER,
            entitlements: [
                "com.apple.developer.networking.networkextension": [
                    "app-proxy-provider",
                    "packet-tunnel-provider",
                ],
            ]
        )
        let extensionProfile = try cliProvisioningProfile(
            bundleIdentifier: "com.example.rewritten.Widget",
            certificateDER: signing.identity.certificateDER,
            entitlements: [
                "com.apple.developer.networking.networkextension": [
                    "app-proxy-provider",
                    "packet-tunnel-provider",
                ],
            ]
        )
        try rootProfile.write(to: rootProfileURL)
        try extensionProfile.write(to: extensionProfileURL)
        try JSONSerialization.data(
            withJSONObject: [
                "com.example.rewritten": rootProfileURL.lastPathComponent,
                "com.example.rewritten.Widget": extensionProfileURL.lastPathComponent,
            ],
            options: [.sortedKeys]
        )
        .write(to: profileMapURL)
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "sign", "ipa",
            "--input", inputURL.path,
            "--output", outputURL.path,
            "--bundle-id", "com.example.rewritten",
            "--profile-map", profileMapURL.path,
            "--certificate", signing.certificateURL.path,
            "--key", signing.privateKeyURL.path,
            "--entitlements-resource", entitlementsResourceName,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        guard result.status == 0 else {
            return
        }
        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let signedAppURL = extractedURL.appendingPathComponent("Payload/Host.app")
        let signedExtensionURL = signedAppURL.appendingPathComponent("PlugIns/Widget.appex")
        let signedFrameworkExecutableURL = signedAppURL.appendingPathComponent("Frameworks/Nested.framework/Nested")
        XCTAssertEqual(
            try cliPlistDictionary(at: signedAppURL.appendingPathComponent("Info.plist"))["CFBundleIdentifier"] as? String,
            "com.example.rewritten"
        )
        XCTAssertEqual(
            try cliPlistDictionary(at: signedExtensionURL.appendingPathComponent("Info.plist"))["CFBundleIdentifier"] as? String,
            "com.example.rewritten.Widget"
        )
        XCTAssertEqual(
            try Data(contentsOf: signedAppURL.appendingPathComponent("embedded.mobileprovision")),
            rootProfile
        )
        XCTAssertEqual(
            try Data(contentsOf: signedExtensionURL.appendingPathComponent("embedded.mobileprovision")),
            extensionProfile
        )
        XCTAssertEqual(
            try cliEntitlementDictionary(inSignedMachOAt: signedAppURL.appendingPathComponent("Host"))["application-identifier"] as? String,
            "TEAMID1234.com.example.rewritten"
        )
        XCTAssertEqual(
            try cliEntitlementDictionary(inSignedMachOAt: signedAppURL.appendingPathComponent("Host"))[
                "com.apple.developer.networking.networkextension"
            ] as? [String],
            ["packet-tunnel-provider"]
        )
        XCTAssertEqual(
            try cliEntitlementDictionary(inSignedMachOAt: signedExtensionURL.appendingPathComponent("Widget"))["application-identifier"] as? String,
            "TEAMID1234.com.example.rewritten.Widget"
        )
        XCTAssertEqual(
            try cliEntitlementDictionary(inSignedMachOAt: signedExtensionURL.appendingPathComponent("Widget"))[
                "com.apple.developer.networking.networkextension"
            ] as? [String],
            ["packet-tunnel-provider"]
        )
        let frameworkCodeDirectory = try XCTUnwrap(
            signatureBlobs(in: try Data(contentsOf: signedFrameworkExecutableURL))[0]
        )
        let frameworkTeamOffset = Int(frameworkCodeDirectory.readUInt32BE(at: 48))
        XCTAssertGreaterThan(frameworkTeamOffset, 0)
        XCTAssertEqual(
            nullTerminatedString(in: frameworkCodeDirectory, offset: frameworkTeamOffset),
            "TEAMID1234"
        )
    }

    func testDefaultCommandEntitlementsResourceUsesAppSigning() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let profileURL = fixture.directory.appendingPathComponent("Root.mobileprovision")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        let entitlementsResourceName = "FixtureEntitlements.plist"
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.resource",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try writeCLIInfoPlist(
            [
                "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
            ],
            to: appURL.appendingPathComponent(entitlementsResourceName)
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))

        let profile = try cliProvisioningProfile(
            bundleIdentifier: "com.example.resource",
            certificateDER: signing.identity.certificateDER,
            entitlements: [
                "com.apple.developer.networking.networkextension": [
                    "app-proxy-provider",
                    "packet-tunnel-provider",
                ],
            ]
        )
        try profile.write(to: profileURL)
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-m", profileURL.path,
            "-o", outputURL.path,
            "--entitlements-resource", entitlementsResourceName,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        guard result.status == 0 else {
            return
        }
        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let entitlements = try cliEntitlementDictionary(
            inSignedMachOAt: extractedURL.appendingPathComponent("Payload/Host.app/Host")
        )
        XCTAssertEqual(
            entitlements["com.apple.developer.networking.networkextension"] as? [String],
            ["packet-tunnel-provider"]
        )
    }

    func testSignIPACommandRejectsMissingRootBundleIdentifier() throws {
        let fixture = try makeCLIFixture()
        let profileURL = fixture.directory.appendingPathComponent("Other.mobileprovision")
        let profileMapURL = fixture.directory.appendingPathComponent("profiles.json")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try Data("profile".utf8).write(to: profileURL)
        try JSONSerialization.data(
            withJSONObject: [
                "com.example.other": profileURL.lastPathComponent,
            ],
            options: [.sortedKeys]
        )
        .write(to: profileMapURL)

        let result = try runRorkSign([
            "sign", "ipa",
            "--input", fixture.directory.appendingPathComponent("Input.ipa").path,
            "--output", fixture.directory.appendingPathComponent("Signed.ipa").path,
            "--bundle-id", "com.example.rewritten",
            "--profile-map", profileMapURL.path,
            "--certificate", fixture.directory.appendingPathComponent("cert.der").path,
            "--key", fixture.directory.appendingPathComponent("key.pem").path,
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(
            result.output.contains(
                "Provisioning profile map must include a profile for root bundle identifier com.example.rewritten."
            ),
            result.output
        )
    }

    func testSignIPACommandAppliesBundleName() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let profileURL = fixture.directory.appendingPathComponent("Root.mobileprovision")
        let profileMapURL = fixture.directory.appendingPathComponent("profiles.json")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.original",
                "CFBundleExecutable": "Host",
                "CFBundleName": "Original",
                "CFBundleDisplayName": "Original",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))

        let profile = try cliProvisioningProfile(
            bundleIdentifier: "com.example.rewritten",
            certificateDER: signing.identity.certificateDER
        )
        try profile.write(to: profileURL)
        try JSONSerialization.data(
            withJSONObject: [
                "com.example.rewritten": profileURL.lastPathComponent,
            ],
            options: [.sortedKeys]
        )
        .write(to: profileMapURL)
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "sign", "ipa",
            "--input", inputURL.path,
            "--output", outputURL.path,
            "--bundle-id", "com.example.rewritten",
            "--profile-map", profileMapURL.path,
            "--certificate", signing.certificateURL.path,
            "--key", signing.privateKeyURL.path,
            "--bundle-name", "Renamed App",
        ])

        XCTAssertEqual(result.status, 0, result.output)
        guard result.status == 0 else {
            return
        }
        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let info = try cliPlistDictionary(
            at: extractedURL.appendingPathComponent("Payload/Host.app/Info.plist")
        )
        XCTAssertEqual(info["CFBundleName"] as? String, "Renamed App")
        XCTAssertEqual(info["CFBundleDisplayName"] as? String, "Renamed App")
    }

    func testDefaultCommandAppliesAppSigningRootEntitlementsFile() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let profileURL = fixture.directory.appendingPathComponent("Wildcard.mobileprovision")
        let entitlementsURL = fixture.directory.appendingPathComponent("Entitlements.plist")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.original",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        let profile = try cliProvisioningProfile(
            bundleIdentifier: "com.example.rewritten",
            certificateDER: Data([0x01]),
            applicationIdentifier: "TEAMID1234.*"
        )
        try profile.write(to: profileURL)
        try writeCLIInfoPlist(
            [
                "application-identifier": "TEAMID1234.com.example.explicit",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": false,
            ],
            to: entitlementsURL
        )
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-a",
            "-b", "com.example.rewritten",
            "-m", profileURL.path,
            "-e", entitlementsURL.path,
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let signedAppURL = extractedURL.appendingPathComponent("Payload/Host.app")
        let entitlements = try cliEntitlementDictionary(
            inSignedMachOAt: signedAppURL.appendingPathComponent("Host")
        )
        XCTAssertEqual(entitlements["application-identifier"] as? String, "TEAMID1234.com.example.explicit")
        XCTAssertEqual(entitlements["com.apple.developer.team-identifier"] as? String, "TEAMID1234")
        XCTAssertEqual(entitlements["get-task-allow"] as? Bool, false)
    }

    func testDefaultCommandPreservesIPAIdentifierForAppSigningWithoutBundleID() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let profileURL = fixture.directory.appendingPathComponent("Wildcard.mobileprovision")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.preserved",
                "CFBundleExecutable": "Host",
                "CFBundleName": "Original",
                "CFBundleDisplayName": "Original",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        let profile = try cliProvisioningProfile(
            bundleIdentifier: "com.example.preserved",
            certificateDER: Data([0x01]),
            applicationIdentifier: "TEAMID1234.com.example.*"
        )
        try profile.write(to: profileURL)
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-a",
            "-n", "Renamed App",
            "-m", profileURL.path,
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let signedAppURL = extractedURL.appendingPathComponent("Payload/Host.app")
        let info = try cliPlistDictionary(at: signedAppURL.appendingPathComponent("Info.plist"))
        XCTAssertEqual(info["CFBundleIdentifier"] as? String, "com.example.preserved")
        XCTAssertEqual(info["CFBundleName"] as? String, "Renamed App")
        XCTAssertEqual(info["CFBundleDisplayName"] as? String, "Renamed App")
        XCTAssertTrue(try RorkSigner.inspectMachO(Data(contentsOf: signedAppURL.appendingPathComponent("Host"))).hasCodeSignature)
    }

    /// Ensures caller-selected temporary storage is honored for archive work
    /// instead of silently falling back to a system directory.
    func testDefaultCommandUsesConfiguredTempFolderForIPAInput() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let tempURL = fixture.directory.appendingPathComponent("CustomTemp", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: tempURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.temp",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-a",
            "-t", tempURL.path,
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(FileManager.default.fileExists(atPath: outputURL.path))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: tempURL.path), [])
    }

    func testDefaultCommandRemoveProvisionRemovesExistingEmbeddedProfile() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let profileURL = fixture.directory.appendingPathComponent("profile.mobileprovision")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.remove-profile",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        let profile = try cliProvisioningProfile(
            bundleIdentifier: "com.example.remove-profile",
            certificateDER: Data([0x01])
        )
        try Data("old embedded profile".utf8).write(to: appURL.appendingPathComponent("embedded.mobileprovision"))
        try profile.write(to: profileURL)
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-a",
            "-R",
            "-m", profileURL.path,
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let signedAppURL = extractedURL.appendingPathComponent("Payload/Host.app")
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: signedAppURL.appendingPathComponent("embedded.mobileprovision").path
            )
        )

        let codeResources = try parseCodeResources(
            Data(contentsOf: signedAppURL.appendingPathComponent("_CodeSignature/CodeResources"))
        )
        XCTAssertNil((try XCTUnwrap(codeResources["files2"] as? [String: Any]))["embedded.mobileprovision"])

        let signedExecutable = try Data(contentsOf: signedAppURL.appendingPathComponent("Host"))
        let entitlements = try XCTUnwrap(signatureBlobs(in: signedExecutable)[5])
        let length = Int(entitlements.readUInt32BE(at: 4))
        let payload = String(decoding: entitlements.subdata(in: 8..<length), as: UTF8.self)
        XCTAssertTrue(payload.contains("TEAMID1234.com.example.remove-profile"), payload)
    }

    func testDefaultCommandUsesRootWildcardProvisioningProfile() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let profileURL = fixture.directory.appendingPathComponent("Wildcard.mobileprovision")
        let extractedURL = fixture.directory.appendingPathComponent("Extracted", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.wildcard",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        let profile = try cliProvisioningProfile(
            bundleIdentifier: "com.example.wildcard",
            certificateDER: Data([0x01]),
            applicationIdentifier: "TEAMID1234.com.example.*"
        )
        try profile.write(to: profileURL)
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-a",
            "-m", profileURL.path,
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        try FileManager.default.createDirectory(at: extractedURL, withIntermediateDirectories: true)
        try FileManager.default.extractIPAArchive(at: outputURL, to: extractedURL)
        let signedAppURL = extractedURL.appendingPathComponent("Payload/Host.app")
        XCTAssertEqual(
            try Data(contentsOf: signedAppURL.appendingPathComponent("embedded.mobileprovision")),
            profile
        )

        let signedExecutable = try Data(contentsOf: signedAppURL.appendingPathComponent("Host"))
        let entitlements = try XCTUnwrap(signatureBlobs(in: signedExecutable)[5])
        let length = Int(entitlements.readUInt32BE(at: 4))
        let payload = String(decoding: entitlements.subdata(in: 8..<length), as: UTF8.self)
        XCTAssertTrue(payload.contains("TEAMID1234.com.example.wildcard"), payload)
    }

    func testDefaultCommandVerbosePrintsArchiveSigningPaths() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.verbose",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-a",
            "-V",
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains(">>> Signing: \t"), result.output)
        XCTAssertTrue(result.output.contains(">>> AppName: \tHost"), result.output)
        XCTAssertTrue(result.output.contains(">>> BundleId: \tcom.example.verbose"), result.output)
        XCTAssertTrue(result.output.contains(">>> Version: \t-"), result.output)
        XCTAssertTrue(result.output.contains(">>> TeamId: \tAdHoc"), result.output)
        XCTAssertTrue(result.output.contains(">>> SubjectCN: \tAdHoc"), result.output)
        XCTAssertTrue(result.output.contains(">>> ReadCache: \tYES"), result.output)
        XCTAssertTrue(result.output.contains("outputArchive=\(outputURL.path)"), result.output)
        XCTAssertTrue(result.output.contains("appBundle=Payload/Host.app"), result.output)
        XCTAssertTrue(result.output.contains("sealedBundle=Payload/Host.app"), result.output)
        XCTAssertTrue(result.output.contains("signedCode=Payload/Host.app/Host"), result.output)
    }

    func testDefaultCommandInstallsSignedIPAWithTemporaryOutput() throws {
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let tempURL = fixture.directory.appendingPathComponent("CustomTemp", isDirectory: true)
        let installerDirectory = fixture.directory.appendingPathComponent("Tools", isDirectory: true)
        let installerLogURL = fixture.directory.appendingPathComponent("installer.log")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: tempURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: installerDirectory, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.install",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)
        try writeFakeInstaller(
            in: installerDirectory,
            logURL: installerLogURL
        )

        let result = try runRorkSign(
            [
                "-a",
                "-i",
                "-t", tempURL.path,
                inputURL.path,
            ],
            environment: [
                "PATH": testPath(prepending: installerDirectory),
                "INSTALL_LOG": installerLogURL.path,
            ]
        )

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("installed="), result.output)
        let installArguments = try String(contentsOf: installerLogURL, encoding: .utf8)
            .split(whereSeparator: \.isNewline)
            .map(String.init)
        XCTAssertEqual(installArguments.first, "install")
        let installedArchivePath = try XCTUnwrap(installArguments.dropFirst().first)
        XCTAssertTrue(installedArchivePath.hasPrefix(tempURL.path), installedArchivePath)
        XCTAssertFalse(FileManager.default.fileExists(atPath: installedArchivePath))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: tempURL.path), [])
    }

    func testDefaultCommandInstallsAppBundleWithTemporaryOutput() throws {
        let fixture = try makeCLIFixture()
        let appURL = fixture.directory.appendingPathComponent("Host.app", isDirectory: true)
        let tempURL = fixture.directory.appendingPathComponent("CustomTemp", isDirectory: true)
        let installerDirectory = fixture.directory.appendingPathComponent("Tools", isDirectory: true)
        let installerLogURL = fixture.directory.appendingPathComponent("installer.log")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: tempURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: installerDirectory, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.install-app",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        try writeFakeInstaller(
            in: installerDirectory,
            logURL: installerLogURL
        )

        let result = try runRorkSign(
            [
                "-a",
                "-i",
                "-t", tempURL.path,
                appURL.path,
            ],
            environment: [
                "PATH": testPath(prepending: installerDirectory),
                "INSTALL_LOG": installerLogURL.path,
            ]
        )

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("installed="), result.output)
        let installArguments = try String(contentsOf: installerLogURL, encoding: .utf8)
            .split(whereSeparator: \.isNewline)
            .map(String.init)
        XCTAssertEqual(installArguments.first, "install")
        let installedArchivePath = try XCTUnwrap(installArguments.dropFirst().first)
        XCTAssertTrue(installedArchivePath.hasPrefix(tempURL.path), installedArchivePath)
        XCTAssertFalse(FileManager.default.fileExists(atPath: installedArchivePath))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: tempURL.path), [])
    }

    func testDefaultCommandChecksPKCS12Credential() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let pkcs12URL = fixture.directory.appendingPathComponent("Identity.p12")
        try signing.pkcs12(password: "secret", useAES: true).write(to: pkcs12URL)

        let result = try runRorkSign([
            "-C",
            "-p", "secret",
            pkcs12URL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("certificateCN=RorkSignTest"), result.output)
        XCTAssertTrue(result.output.contains("certificateOrg=Rork Sign Tests"), result.output)
        XCTAssertTrue(result.output.contains("certificateIssuer=RorkSignTest"), result.output)
        XCTAssertTrue(result.output.contains("certificateAlgorithm=RSA 2048-bit"), result.output)
        XCTAssertTrue(result.output.contains("certificateExpired=false"), result.output)
    }

    func testDefaultCommandChecksPEMCertificateChain() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let additionalCertificate = try signing.selfSignedCertificate(commonName: "RorkSignCLIIntermediate")
        let chainURL = fixture.directory.appendingPathComponent("chain.pem")
        let chainPEM = signing.certificatePEM
            + "\n"
            + (try String(contentsOf: additionalCertificate.url, encoding: .utf8))
        try chainPEM.write(to: chainURL, atomically: true, encoding: .utf8)

        let result = try runRorkSign([
            "-C",
            chainURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("certificateIndex=0"), result.output)
        XCTAssertTrue(result.output.contains("certificateIndex=1"), result.output)
        XCTAssertTrue(result.output.contains("certificateCN=RorkSignTest"), result.output)
        XCTAssertTrue(result.output.contains("certificateCN=RorkSignCLIIntermediate"), result.output)
    }

    func testDefaultCommandChecksCertificateChainValidation() throws {
        let signing = try OpenSSLCertificateChainFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let chainURL = fixture.directory.appendingPathComponent("valid-chain.pem")
        try signing.chainPEM.write(to: chainURL, atomically: true, encoding: .utf8)

        let result = try runRorkSign([
            "-C",
            chainURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("chainValid=true"), result.output)
        XCTAssertTrue(result.output.contains("chainLinksValid=true"), result.output)
        XCTAssertTrue(result.output.contains("chainCertificates=2"), result.output)
        XCTAssertTrue(result.output.contains("chainLinks=1"), result.output)
        XCTAssertTrue(result.output.contains("chainRootSelfSigned=true"), result.output)
        XCTAssertTrue(result.output.contains("chainRootCanSign=true"), result.output)
    }

    func testDefaultCommandChecksCertificateOCSPResponderURL() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let certificate = try signing.selfSignedCertificate(
            commonName: "RorkSignCLIOCSP",
            ocspResponderURL: "http://ocsp.example.test"
        )

        let result = try runRorkSign([
            "-C",
            certificate.url.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("certificateCN=RorkSignCLIOCSP"), result.output)
        XCTAssertTrue(result.output.contains("certificateOCSP=http://ocsp.example.test"), result.output)
    }

    func testDefaultCommandChecksCertificateCRLDistributionPointURL() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let certificate = try signing.selfSignedCertificate(
            commonName: "RorkSignCLICRL",
            ocspResponderURL: nil,
            crlDistributionPointURL: "http://crl.example.test/root.crl"
        )

        let result = try runRorkSign([
            "-C",
            certificate.url.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("certificateCN=RorkSignCLICRL"), result.output)
        XCTAssertTrue(result.output.contains("certificateCRL=http://crl.example.test/root.crl"), result.output)
    }

    func testDefaultCommandChecksMachOSigningCertificate() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("SignedMachO")
        let signed = try RorkSigner.signMachOWithIdentity(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "com.example.cli.signed-check",
            identity: signing.identity
        )
        try signed.write(to: inputURL)

        let result = try runRorkSign([
            "-C",
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("codeSignatureArchitecture=0"), result.output)
        XCTAssertTrue(result.output.contains("codeDirectoryHashes=true"), result.output)
        XCTAssertTrue(result.output.contains("codeDirectories=2"), result.output)
        XCTAssertTrue(result.output.contains("cms=true"), result.output)
        XCTAssertTrue(result.output.contains("cmsVerified=true"), result.output)
        XCTAssertTrue(result.output.contains("certificateCN=RorkSignTest"), result.output)
        XCTAssertTrue(result.output.contains("certificateAlgorithm=RSA 2048-bit"), result.output)
        XCTAssertTrue(result.output.contains("certificateExpired=false"), result.output)
    }

    func testDefaultCommandChecksProfileCredentialBeforeSigning() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        let inputURL = fixture.directory.appendingPathComponent("Input")
        let outputURL = fixture.directory.appendingPathComponent("Output")
        let profileURL = fixture.directory.appendingPathComponent("Profile.mobileprovision")
        try Fixtures.machO64WithCodeSignature().write(to: inputURL)
        try cliProvisioningProfile(
            bundleIdentifier: "com.example.cli.check",
            certificateDER: signing.identity.certificateDER
        )
        .write(to: profileURL)

        let result = try runRorkSign([
            "-C",
            "-k", signing.privateKeyURL.path,
            "-m", profileURL.path,
            "-b", "com.example.cli.check",
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("profileTeam=TEAMID1234"), result.output)
        XCTAssertTrue(result.output.contains("certificateCN=RorkSignTest"), result.output)
        XCTAssertTrue(result.output.contains("credentialAuthorized=true"), result.output)
        XCTAssertTrue(result.output.contains("signed=\(outputURL.path)"), result.output)
        XCTAssertTrue(try RorkSigner.inspectMachO(Data(contentsOf: outputURL)).hasCodeSignature)
    }

    func testDefaultCommandChecksEmbeddedProfileInIPAUsingTempFolder() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let tempURL = fixture.directory.appendingPathComponent("CustomTemp", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: tempURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.profile",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try cliProvisioningProfile(
            bundleIdentifier: "com.example.cli.profile",
            certificateDER: signing.identity.certificateDER
        )
        .write(to: appURL.appendingPathComponent("embedded.mobileprovision"))
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-C",
            "-t", tempURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("profileTeam=TEAMID1234"), result.output)
        XCTAssertTrue(result.output.contains("developerCertificates=1"), result.output)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: tempURL.path), [])
    }

    func testDefaultCommandChecksBundleCodeResources() throws {
        let fixture = try makeCLIFixture()
        let appURL = fixture.directory.appendingPathComponent("Host.app", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.resources-check",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        try Data("asset".utf8).write(to: appURL.appendingPathComponent("asset.txt"))
        try RorkSigner.signBundleAdHoc(at: appURL)

        let result = try runRorkSign([
            "-C",
            appURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("resourcesVerified=true"), result.output)
        XCTAssertTrue(result.output.contains("sealed=1"), result.output)
        XCTAssertTrue(result.output.contains("checked=1"), result.output)
        XCTAssertTrue(result.output.contains("mismatched=0"), result.output)
        XCTAssertTrue(result.output.contains("codeSignatureArchitecture=0"), result.output)
    }

    func testDefaultCommandReportsTamperedBundleCodeResources() throws {
        let fixture = try makeCLIFixture()
        let appURL = fixture.directory.appendingPathComponent("Host.app", isDirectory: true)
        let assetURL = appURL.appendingPathComponent("asset.txt")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.resources-tampered",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        try Data("asset".utf8).write(to: assetURL)
        try RorkSigner.signBundleAdHoc(at: appURL)
        try Data("tampered".utf8).write(to: assetURL)

        let result = try runRorkSign([
            "-C",
            appURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("resourcesVerified=false"), result.output)
        XCTAssertTrue(result.output.contains("mismatched=1"), result.output)
        XCTAssertTrue(result.output.contains("codeSignatureArchitecture=0"), result.output)
    }

    func testDefaultCommandReportsNestedBundleCodeResources() throws {
        let fixture = try makeCLIFixture()
        let appURL = fixture.directory.appendingPathComponent("Host.app", isDirectory: true)
        let nestedURL = appURL.appendingPathComponent("Frameworks/Nested.framework", isDirectory: true)
        let nestedAssetURL = nestedURL.appendingPathComponent("asset.txt")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: nestedURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.resources-nested",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.resources-nested.framework",
                "CFBundleExecutable": "Nested",
            ],
            to: nestedURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        try Fixtures.machO64WithCodeSignature().write(to: nestedURL.appendingPathComponent("Nested"))
        try Data("nested asset".utf8).write(to: nestedAssetURL)
        try RorkSigner.signBundleAdHoc(at: appURL)
        try Data("changed".utf8).write(to: nestedAssetURL)

        let result = try runRorkSign([
            "-C",
            appURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("resourceBundle=."), result.output)
        XCTAssertTrue(
            result.output.contains("resourceBundle=Frameworks/Nested.framework resourcesVerified=false"),
            result.output
        )
        XCTAssertTrue(result.output.contains("codeSignatureArchitecture=0"), result.output)
    }

    func testDefaultCommandChecksSignedIPAAfterIdentitySigning() throws {
        let signing = try OpenSSLFixture()
        defer {
            signing.remove()
        }
        let fixture = try makeCLIFixture()
        let archiveRootURL = fixture.directory.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let appURL = archiveRootURL.appendingPathComponent("Payload/Host.app", isDirectory: true)
        let inputURL = fixture.directory.appendingPathComponent("Input.ipa")
        let outputURL = fixture.directory.appendingPathComponent("Signed.ipa")
        let profileURL = fixture.directory.appendingPathComponent("Profile.mobileprovision")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.identity-check",
                "CFBundleExecutable": "Host",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Fixtures.machO64WithCodeSignature().write(to: appURL.appendingPathComponent("Host"))
        try cliProvisioningProfile(
            bundleIdentifier: "com.example.cli.identity-check",
            certificateDER: signing.identity.certificateDER
        )
        .write(to: profileURL)
        try FileManager.default.createIPAArchive(contentsOf: archiveRootURL, at: inputURL)

        let result = try runRorkSign([
            "-C",
            "-k", signing.privateKeyURL.path,
            "-m", profileURL.path,
            "-o", outputURL.path,
            inputURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("credentialAuthorized=true"), result.output)
        XCTAssertTrue(result.output.contains("app=Payload/Host.app"), result.output)
        XCTAssertTrue(result.output.contains("resourcesVerified=true"), result.output)
        XCTAssertTrue(result.output.contains("codeSignatureArchitecture=0"), result.output)
        XCTAssertTrue(result.output.contains("cms=true"), result.output)
        XCTAssertTrue(result.output.contains("cmsVerified=true"), result.output)
        XCTAssertTrue(result.output.contains("certificateCN=RorkSignTest"), result.output)
    }

    func testDefaultCommandRejectsInvalidTempFolder() throws {
        let result = try runRorkSign([
            "-t", "/definitely/missing/rorksign-temp",
            "Input.ipa",
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.contains("Invalid temp folder"), result.output)
    }

    func testDefaultCommandRejectsInvalidZipLevel() throws {
        let result = try runRorkSign([
            "-z", "10",
            "Input.ipa",
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.contains("Invalid zip level"), result.output)
    }

    func testDefaultCommandRejectsOnlineOCSPWithoutCheckMode() throws {
        let result = try runRorkSign([
            "--online-ocsp",
            "Input.ipa",
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.contains("--online-ocsp requires -C/--check"), result.output)
    }

    func testZSignCompatibleVersionFlags() throws {
        let shortResult = try runRorkSign([
            "-v",
        ])
        let longRootResult = try runRorkSign([
            "--version",
        ])
        let longResult = try runRorkSign([
            "zsign",
            "--version",
        ])

        XCTAssertEqual(shortResult.status, 0, shortResult.output)
        XCTAssertEqual(longRootResult.status, 0, longRootResult.output)
        XCTAssertEqual(longResult.status, 0, longResult.output)
        let expectedVersion = "version: \(RorkSigner.version)"
        XCTAssertEqual(
            shortResult.output.trimmingCharacters(in: .newlines),
            expectedVersion
        )
        XCTAssertEqual(
            longRootResult.output.trimmingCharacters(in: .newlines),
            expectedVersion
        )
        XCTAssertEqual(
            longResult.output.trimmingCharacters(in: .newlines),
            expectedVersion
        )
    }

    func testRootHelpIsGeneratedByArgumentParser() throws {
        let result = try runRorkSign([
            "--help",
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("USAGE: rorksign <subcommand>"), result.output)
        XCTAssertTrue(result.output.contains("zsign (default)"), result.output)
        XCTAssertTrue(result.output.contains("inspect"), result.output)
        XCTAssertTrue(result.output.contains("-h, --help"), result.output)
    }

    func testZSignHelpIsExposedThroughArgumentParserSubcommand() throws {
        let result = try runRorkSign([
            "zsign",
            "--help",
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("-k, --pkey"))
        XCTAssertTrue(result.output.contains("-m, --prov"))
        XCTAssertTrue(result.output.contains("-x, --metadata"))
        XCTAssertTrue(result.output.contains("-f, --force"))
        XCTAssertTrue(result.output.contains("-V, --verbose"))
        XCTAssertTrue(result.output.contains("-v, --version"))
        XCTAssertTrue(result.output.contains("--online-ocsp"))
        XCTAssertFalse(result.output.contains("Show the version"))
        XCTAssertTrue(result.output.contains("Rebuild signatures"))
        XCTAssertTrue(result.output.contains("Print detailed signing paths"))
    }

    func testVerifyResourcesSubcommandReportsValidSeal() throws {
        let fixture = try makeCLIFixture()
        let bundleURL = fixture.directory.appendingPathComponent("Fixture.app", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)
        try writeCLIInfoPlist(
            [
                "CFBundleIdentifier": "com.example.cli.resources",
                "CFBundleExecutable": "Fixture",
            ],
            to: bundleURL.appendingPathComponent("Info.plist")
        )
        try Data("executable".utf8).write(to: bundleURL.appendingPathComponent("Fixture"))
        try Data("asset".utf8).write(to: bundleURL.appendingPathComponent("asset.txt"))
        try RorkSigner.sealBundleResources(at: bundleURL)

        let result = try runRorkSign([
            "verify-resources",
            bundleURL.path,
        ])

        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("resourcesVerified=true"), result.output)
        XCTAssertTrue(result.output.contains("sealed=1"), result.output)
        XCTAssertTrue(result.output.contains("unsealed=0"), result.output)
    }
}

private struct CLIFixture {
    let directory: URL
}

private func makeCLIFixture() throws -> CLIFixture {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return CLIFixture(directory: directory)
}

private func writeCLIInfoPlist(_ dictionary: [String: Any], to url: URL) throws {
    let data = try PropertyListSerialization.data(
        fromPropertyList: dictionary,
        format: .xml,
        options: 0
    )
    try data.write(to: url)
}

private func cliPlistDictionary(at url: URL) throws -> [String: Any] {
    let plist = try PropertyListSerialization.propertyList(
        from: Data(contentsOf: url),
        options: [],
        format: nil
    )
    return try XCTUnwrap(plist as? [String: Any])
}

private func cliEntitlementDictionary(inSignedMachOAt url: URL) throws -> [String: Any] {
    let signed = try Data(contentsOf: url)
    let blobs = try signatureBlobs(in: signed)
    let entitlements = try XCTUnwrap(blobs[5])
    let length = Int(entitlements.readUInt32BE(at: 4))
    let payload = entitlements.subdata(in: 8..<length)
    let plist = try PropertyListSerialization.propertyList(from: payload, options: [], format: nil)
    return try XCTUnwrap(plist as? [String: Any])
}

/// Writes a platform-native installer fixture that records each argument.
private func writeFakeInstaller(in directoryURL: URL, logURL: URL) throws {
    #if os(Windows)
    let url = directoryURL.appendingPathComponent("ideviceinstaller.exe")
    let sourceURL = directoryURL.appendingPathComponent(
        "fake-ideviceinstaller.c"
    )
    let source = #"""
    #include <stdio.h>
    #include <stdlib.h>

    int main(int argc, char **argv) {
        const char *log_path = getenv("INSTALL_LOG");
        if (log_path == NULL) {
            return 2;
        }
        FILE *log = fopen(log_path, "wb");
        if (log == NULL) {
            return 3;
        }
        for (int index = 1; index < argc; index++) {
            fprintf(log, "%s\n", argv[index]);
        }
        return fclose(log) == 0 ? 0 : 4;
    }
    """#
    try Data(source.utf8).write(to: sourceURL)
    let compilerURL = try XCTUnwrap(
        testExecutableURL(named: "clang-cl.exe"),
        "The Windows toolchain compiler was not found in PATH."
    )
    try runCommand(
        compilerURL,
        arguments: [
            sourceURL.path,
            "/nologo",
            "/MT",
            "/O2",
            "/Fe\(url.path)",
        ]
    )
    #else
    let url = directoryURL.appendingPathComponent("ideviceinstaller")
    let script = """
    #!/bin/sh
    printf '%s\\n' "$@" > "\(logURL.path)"
    exit 0
    """
    try Data(script.utf8).write(to: url)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o755],
        ofItemAtPath: url.path
    )
    #endif
}

/// Prepends one directory using the platform's executable search separator.
private func testPath(prepending directoryURL: URL) -> String {
    #if os(Windows)
    let separator = ";"
    #else
    let separator = ":"
    #endif
    return [
        directoryURL.path,
        ProcessInfo.processInfo.environment["SWIFT_RUNTIME_PATH"] ?? "",
        ProcessInfo.processInfo.environment["PATH"] ?? "",
    ]
    .filter { !$0.isEmpty }
    .joined(separator: separator)
}

/// Resolves one test tool through the configured toolchain or search path.
private func testExecutableURL(named name: String) -> URL? {
    if let swiftBin = ProcessInfo.processInfo.environment["SWIFT_BIN"] {
        let url = URL(fileURLWithPath: swiftBin)
            .appendingPathComponent(name)
        if isRunnableTestExecutable(url) {
            return url
        }
    }

    #if os(Windows)
    let separator: Character = ";"
    #else
    let separator: Character = ":"
    #endif
    let pathValue = ProcessInfo.processInfo.environment["PATH"] ?? ""
    for directory in pathValue.split(separator: separator) {
        let url = URL(fileURLWithPath: String(directory))
            .appendingPathComponent(name)
        if isRunnableTestExecutable(url) {
            return url
        }
    }
    return nil
}

/// Applies the platform's executable discovery rule to one test tool.
private func isRunnableTestExecutable(_ url: URL) -> Bool {
    #if os(Windows)
    var isDirectory = ObjCBool(false)
    return FileManager.default.fileExists(
        atPath: url.path,
        isDirectory: &isDirectory
    ) && !isDirectory.boolValue
    #else
    return FileManager.default.isExecutableFile(atPath: url.path)
    #endif
}

private func cliProvisioningProfile(
    bundleIdentifier: String,
    certificateDER: Data,
    applicationIdentifier: String? = nil,
    entitlements additionalEntitlements: [String: Any] = [:]
) throws -> Data {
    let entitlements = [
        "application-identifier": applicationIdentifier ?? "TEAMID1234.\(bundleIdentifier)",
        "com.apple.developer.team-identifier": "TEAMID1234",
    ].merging(additionalEntitlements) { _, additional in additional }
    let plist: [String: Any] = [
        "TeamIdentifier": ["TEAMID1234"],
        "ExpirationDate": Date(timeIntervalSince1970: 1_900_000_000),
        "DeveloperCertificates": [certificateDER],
        "Entitlements": entitlements,
    ]
    return try PropertyListSerialization.data(
        fromPropertyList: plist,
        format: .xml,
        options: 0
    )
}
