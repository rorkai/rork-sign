#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
import RorkSign
import XCTest

final class MachOSigningTests: XCTestCase {
    func testReadsThin64MachOCodeSignatureCommand() throws {
        let data = Fixtures.machO64WithCodeSignature()

        let info = try RorkSigner.inspectMachO(data)

        XCTAssertEqual(info.kind, .machO64)
        XCTAssertEqual(info.magic, 0xfeedfacf)
        XCTAssertEqual(info.fileType, 2)
        XCTAssertEqual(info.architectureCount, 1)
        XCTAssertTrue(info.hasCodeSignature)
        XCTAssertEqual(info.codeSignatureOffset, 0x100)
        XCTAssertEqual(info.codeSignatureSize, 0x40)
    }

    func testRejectsMalformedLoadCommandSize() {
        var data = Fixtures.machO64WithCodeSignature()
        data.writeUInt32LE(0, at: 36)

        XCTAssertThrowsError(try RorkSigner.inspectMachO(data)) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidMachO("Mach-O load command has an invalid size.")
            )
        }
    }

    func testReadsUniversalMachOHeader() throws {
        let data = Fixtures.universalMachOHeader(architectureCount: 2)

        let info = try RorkSigner.inspectMachO(data)

        XCTAssertEqual(info.kind, .universal)
        XCTAssertEqual(info.magic, 0xcafebabe)
        XCTAssertEqual(info.architectureCount, 2)
    }

    func testInjectsStrongDylibLoadCommand() throws {
        let injected = try RorkSigner.injectDylibLoadCommand(
            into: Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace(),
            path: "@executable_path/Hook.dylib"
        )

        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: injected),
            [
                MachODylibLoadCommand(path: "@executable_path/Hook.dylib"),
            ]
        )
        XCTAssertEqual(injected.readUInt32LE(at: 16), 2)
        XCTAssertEqual(injected.readUInt32LE(at: 20), 208)
    }

    func testInjectsWeakDylibLoadCommand() throws {
        let injected = try RorkSigner.injectDylibLoadCommand(
            into: Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace(),
            path: "@rpath/Optional.framework/Optional",
            weak: true
        )

        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: injected),
            [
                MachODylibLoadCommand(path: "@rpath/Optional.framework/Optional", weak: true),
            ]
        )
    }

    func testDylibInjectionIsIdempotentForExistingPath() throws {
        let input = Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace()
        let once = try RorkSigner.injectDylibLoadCommand(
            into: input,
            path: "@executable_path/Hook.dylib"
        )
        let twice = try RorkSigner.injectDylibLoadCommand(
            into: once,
            path: "@executable_path/Hook.dylib"
        )

        XCTAssertEqual(twice, once)
        XCTAssertEqual(try RorkSigner.dylibLoadCommands(in: twice).count, 1)
    }

    func testRemovesDylibLoadCommandByExactPathAndExecutablePathName() throws {
        let injected = try RorkSigner.injectDylibLoadCommand(
            into: Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace(),
            path: "@executable_path/Hook.dylib"
        )

        let removed = try RorkSigner.removeDylibLoadCommands(
            from: injected,
            matching: ["Hook.dylib"]
        )

        XCTAssertEqual(try RorkSigner.dylibLoadCommands(in: removed), [])
        XCTAssertEqual(removed.readUInt32LE(at: 16), 1)
        XCTAssertEqual(removed.readUInt32LE(at: 20), 152)
    }

    func testSignsMachOAfterDylibInjection() throws {
        let injected = try RorkSigner.injectDylibLoadCommand(
            into: Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace(),
            path: "@executable_path/Hook.dylib"
        )

        let signed = try RorkSigner.signMachOAdHoc(
            injected,
            bundleIdentifier: "app.rork.sign.injected"
        )
        let info = try RorkSigner.inspectMachO(signed)

        XCTAssertTrue(info.hasCodeSignature)
        XCTAssertEqual(
            try RorkSigner.dylibLoadCommands(in: signed),
            [
                MachODylibLoadCommand(path: "@executable_path/Hook.dylib"),
            ]
        )
        XCTAssertEqual(signed.count, Int(info.codeSignatureOffset + info.codeSignatureSize))
    }

    func testAdHocSignsExistingThin64MachO() throws {
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.fixture"
        )

        let info = try RorkSigner.inspectMachO(signed)

        XCTAssertTrue(info.hasCodeSignature)
        XCTAssertEqual(info.codeSignatureOffset, 0x100)
        XCTAssertEqual(
            info.codeSignatureSize,
            compatibleCodeSignatureReservationSize(codeLimit: UInt64(info.codeSignatureOffset))
        )
        XCTAssertEqual(signed.count, Int(info.codeSignatureOffset + info.codeSignatureSize))
        XCTAssertEqual(signed.readUInt32BE(at: Int(info.codeSignatureOffset)), 0xfade0cc0)
        XCTAssertLessThanOrEqual(signed.readUInt32BE(at: Int(info.codeSignatureOffset) + 4), info.codeSignatureSize)
        XCTAssertEqual(signed.readUInt32BE(at: Int(info.codeSignatureOffset) + 8), 3)

        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let alternateCodeDirectory = try XCTUnwrap(blobs[0x1000])
        let requirements = try XCTUnwrap(blobs[2])
        XCTAssertEqual(codeDirectory.readUInt32BE(at: 0), 0xfade0c02)
        XCTAssertEqual(codeDirectory.readUInt32BE(at: 12), 0x2)
        XCTAssertEqual(codeDirectory.readUInt32BE(at: 24), 2)
        XCTAssertEqual(codeDirectory[36], 20)
        XCTAssertEqual(codeDirectory[37], 1)
        XCTAssertEqual(alternateCodeDirectory.readUInt32BE(at: 0), 0xfade0c02)
        XCTAssertEqual(alternateCodeDirectory.readUInt32BE(at: 12), 0x2)
        XCTAssertEqual(alternateCodeDirectory.readUInt32BE(at: 24), 2)
        XCTAssertEqual(alternateCodeDirectory[36], 32)
        XCTAssertEqual(alternateCodeDirectory[37], 2)
        XCTAssertEqual(requirements.readUInt32BE(at: 0), 0xfade0c01)
        XCTAssertEqual(requirements.readUInt32BE(at: 8), 0)
    }

    func testReadsEmbeddedCodeSignatureSlots() throws {
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.inspect"
        )

        let signatures = try RorkSigner.readEmbeddedCodeSignatures(in: signed)

        XCTAssertEqual(signatures.count, 1)
        XCTAssertEqual(signatures[0].architectureIndex, 0)
        XCTAssertEqual(signatures[0].superBlob.readUInt32BE(at: 0), 0xfade0cc0)
        XCTAssertNotNil(signatures[0].firstSlot(0))
        XCTAssertNotNil(signatures[0].firstSlot(2))
        XCTAssertNotNil(signatures[0].firstSlot(0x1000))
        XCTAssertNil(signatures[0].firstSlot(0x10000))
    }

    func testMachOCodeSignatureCheckValidatesCodeDirectoryHashes() throws {
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.validate-code-directory"
        )

        let reports = try RorkSigner.checkMachOCodeSignatures(signed)

        XCTAssertEqual(reports.count, 1)
        XCTAssertFalse(reports[0].hasCMS)
        XCTAssertFalse(reports[0].cmsSignatureValid)
        XCTAssertTrue(reports[0].codeDirectoryHashesValid)
        XCTAssertEqual(reports[0].codeDirectories.count, 2)
        XCTAssertEqual(reports[0].codeDirectories.map(\.hashAlgorithm), [.sha1, .sha256])
        XCTAssertEqual(
            reports[0].codeDirectories.map(\.identifier),
            [
                "app.rork.sign.validate-code-directory",
                "app.rork.sign.validate-code-directory",
            ]
        )
        XCTAssertTrue(reports[0].codeDirectories.allSatisfy(\.codeSlotsValid))
        XCTAssertTrue(reports[0].codeDirectories.allSatisfy(\.specialSlotsValid))
    }

    func testMachOCodeSignatureCheckDetectsTamperedCodeBytes() throws {
        var signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.tampered-code"
        )
        let info = try RorkSigner.inspectMachO(signed)
        flipByte(in: &signed, at: Int(info.codeSignatureOffset) - 1)

        let reports = try RorkSigner.checkMachOCodeSignatures(signed)

        XCTAssertEqual(reports.count, 1)
        XCTAssertFalse(reports[0].codeDirectoryHashesValid)
        XCTAssertFalse(reports[0].codeDirectories[0].codeSlotsValid)
        XCTAssertFalse(reports[0].codeDirectories[1].codeSlotsValid)
        XCTAssertTrue(reports[0].codeDirectories[0].specialSlotsValid)
        XCTAssertTrue(reports[0].codeDirectories[1].specialSlotsValid)
    }

    func testMachOCodeSignatureCheckDetectsTamperedSpecialSlot() throws {
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>
        """
        var signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.tampered-entitlements",
            entitlementsXML: entitlements
        )
        try flipByteInSignatureSlot(5, in: &signed, byteOffsetInBlob: 8)

        let reports = try RorkSigner.checkMachOCodeSignatures(signed)

        XCTAssertEqual(reports.count, 1)
        XCTAssertFalse(reports[0].codeDirectoryHashesValid)
        XCTAssertTrue(reports[0].codeDirectories[0].codeSlotsValid)
        XCTAssertTrue(reports[0].codeDirectories[1].codeSlotsValid)
        XCTAssertFalse(reports[0].codeDirectories[0].specialSlotsValid)
        XCTAssertFalse(reports[0].codeDirectories[1].specialSlotsValid)
    }

    func testAdHocCanEmitSHA256OnlyCodeDirectory() throws {
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.fixture",
            codeDirectoryHashingMode: .sha256Only
        )

        let info = try RorkSigner.inspectMachO(signed)
        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])

        XCTAssertEqual(signed.readUInt32BE(at: Int(info.codeSignatureOffset) + 8), 2)
        XCTAssertNil(blobs[0x1000])
        XCTAssertEqual(codeDirectory.readUInt32BE(at: 0), 0xfade0c02)
        XCTAssertEqual(codeDirectory[36], 32)
        XCTAssertEqual(codeDirectory[37], 2)
    }

    func testAdHocSigningRecordsExecutableSegmentMetadata() throws {
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>
        """

        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace(),
            bundleIdentifier: "app.rork.sign.fixture",
            entitlementsXML: entitlements
        )

        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        XCTAssertEqual(codeDirectory.readUInt64BE(at: 72), 0x1000)
        XCTAssertEqual(codeDirectory.readUInt64BE(at: 80), 0x11)
    }

    func testAdHocSigningUsesEmbeddedInfoPlistWhenNoExternalInfoPlistIsProvided() throws {
        let embeddedInfoPlist = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>CFBundleIdentifier</key><string>app.rork.embedded-info</string></dict></plist>
        """.utf8)

        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithEmbeddedInfoPlistSection(),
            bundleIdentifier: "app.rork.sign.embedded-info"
        )

        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let alternateCodeDirectory = try XCTUnwrap(blobs[0x1000])
        XCTAssertEqual(specialSlotHash(1, in: codeDirectory), Data(Insecure.SHA1.hash(data: embeddedInfoPlist)))
        XCTAssertEqual(specialSlotHash(1, in: alternateCodeDirectory), Data(SHA256.hash(data: embeddedInfoPlist)))
    }

    func testExternalInfoPlistOverridesEmbeddedInfoPlistSection() throws {
        let externalInfoPlist = Data("<plist><dict><key>CFBundleIdentifier</key><string>app.rork.external-info</string></dict></plist>".utf8)

        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithEmbeddedInfoPlistSection(),
            bundleIdentifier: "app.rork.sign.embedded-info",
            infoPlist: externalInfoPlist
        )

        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let alternateCodeDirectory = try XCTUnwrap(blobs[0x1000])
        XCTAssertEqual(specialSlotHash(1, in: codeDirectory), Data(Insecure.SHA1.hash(data: externalInfoPlist)))
        XCTAssertEqual(specialSlotHash(1, in: alternateCodeDirectory), Data(SHA256.hash(data: externalInfoPlist)))
    }

    func testAdHocAddsCodeSignatureCommandWhenLoadCommandSpaceExists() throws {
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithoutCodeSignatureButWithLoadCommandSpace(),
            bundleIdentifier: "app.rork.sign.fixture"
        )

        let info = try RorkSigner.inspectMachO(signed)

        XCTAssertTrue(info.hasCodeSignature)
        XCTAssertEqual(info.codeSignatureOffset, 0x130)
        XCTAssertEqual(signed.readUInt32LE(at: 16), 2)
        XCTAssertEqual(signed.readUInt32LE(at: 20), 168)
        XCTAssertEqual(signed.readUInt32LE(at: 184), 0x1d)
        XCTAssertEqual(signed.readUInt32LE(at: 192), 0x130)
        XCTAssertEqual(
            info.codeSignatureSize,
            compatibleCodeSignatureReservationSize(codeLimit: UInt64(info.codeSignatureOffset))
        )
        XCTAssertEqual(signed.count, Int(info.codeSignatureOffset + info.codeSignatureSize))
    }

    func testAdHocSigningEmbedsEntitlementsBlobAndDEREntitlementsBlob() throws {
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>get-task-allow</key><true/><key>application-identifier</key><string>ABCDE12345.app.rork.sign.fixture</string></dict></plist>
        """
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.fixture",
            entitlementsXML: entitlements
        )
        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let entitlementsBlob = try XCTUnwrap(blobs[5])
        let derEntitlementsBlob = try XCTUnwrap(blobs[7])

        XCTAssertEqual(codeDirectory.readUInt32BE(at: 24), 7)
        XCTAssertEqual(entitlementsBlob.readUInt32BE(at: 0), 0xfade7171)
        XCTAssertEqual(derEntitlementsBlob.readUInt32BE(at: 0), 0xfade7172)

        let entitlementsLength = Int(entitlementsBlob.readUInt32BE(at: 4))
        let payload = entitlementsBlob.subdata(in: 8..<entitlementsLength)
        XCTAssertTrue(String(decoding: payload, as: UTF8.self).contains("get-task-allow"))

        let derEntitlementsLength = Int(derEntitlementsBlob.readUInt32BE(at: 4))
        let derPayload = derEntitlementsBlob.subdata(in: 8..<derEntitlementsLength)
        XCTAssertEqual(derPayload, Data([
            0x70, 0x56, 0x02, 0x01, 0x01, 0xb0, 0x51, 0x30,
            0x3a, 0x0c, 0x16, 0x61, 0x70, 0x70, 0x6c, 0x69,
            0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x69,
            0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65,
            0x72, 0x0c, 0x20, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x2e, 0x61, 0x70,
            0x70, 0x2e, 0x72, 0x6f, 0x72, 0x6b, 0x2e, 0x73,
            0x69, 0x67, 0x6e, 0x2e, 0x66, 0x69, 0x78, 0x74,
            0x75, 0x72, 0x65, 0x30, 0x13, 0x0c, 0x0e, 0x67,
            0x65, 0x74, 0x2d, 0x74, 0x61, 0x73, 0x6b, 0x2d,
            0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x01, 0x01, 0xff,
        ]))
    }

    func testCodeDirectoryRecordsTeamIdentifierFromEntitlements() throws {
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>application-identifier</key><string>TEAMID1234.app.rork.sign.fixture</string><key>com.apple.developer.team-identifier</key><string>TEAMID1234</string></dict></plist>
        """
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.fixture",
            entitlementsXML: entitlements
        )

        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let identifierOffset = Int(codeDirectory.readUInt32BE(at: 20))
        let teamOffset = Int(codeDirectory.readUInt32BE(at: 48))

        XCTAssertGreaterThan(teamOffset, identifierOffset)
        XCTAssertEqual(nullTerminatedString(in: codeDirectory, offset: teamOffset), "TEAMID1234")
    }

    func testCodeDirectoryFallsBackToApplicationIdentifierTeamPrefix() throws {
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>application-identifier</key><string>ABCDE12345.app.rork.sign.fixture</string></dict></plist>
        """
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.fixture",
            entitlementsXML: entitlements
        )

        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])

        XCTAssertEqual(nullTerminatedString(in: codeDirectory, offset: Int(codeDirectory.readUInt32BE(at: 48))), "ABCDE12345")
    }

    func testDEREntitlementsKeepIntegerOneDistinctFromBooleanTrue() throws {
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>integer</key><integer>1</integer><key>boolean</key><true/></dict></plist>
        """
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.fixture",
            entitlementsXML: entitlements
        )

        let blobs = try signatureBlobs(in: signed)
        let derEntitlementsBlob = try XCTUnwrap(blobs[7])
        let derEntitlementsLength = Int(derEntitlementsBlob.readUInt32BE(at: 4))
        let derPayload = derEntitlementsBlob.subdata(in: 8..<derEntitlementsLength)

        XCTAssertEqual(derPayload, Data([
            0x70, 0x21, 0x02, 0x01, 0x01, 0xb0, 0x1c,
            0x30, 0x0c, 0x0c, 0x07, 0x62, 0x6f, 0x6f, 0x6c,
            0x65, 0x61, 0x6e, 0x01, 0x01, 0xff,
            0x30, 0x0c, 0x0c, 0x07, 0x69, 0x6e, 0x74, 0x65,
            0x67, 0x65, 0x72, 0x02, 0x01, 0x01,
        ]))
    }

    func testAdHocSigningEmbedsResourceDirectoryHash() throws {
        let resourceDirectory = Data("sealed resources".utf8)
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.fixture",
            resourceDirectory: resourceDirectory
        )
        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let alternateCodeDirectory = try XCTUnwrap(blobs[0x1000])

        XCTAssertEqual(codeDirectory.readUInt32BE(at: 24), 3)
        XCTAssertEqual(
            specialSlotHash(3, in: codeDirectory),
            Data(Insecure.SHA1.hash(data: resourceDirectory))
        )
        XCTAssertEqual(alternateCodeDirectory.readUInt32BE(at: 24), 3)
        XCTAssertEqual(
            specialSlotHash(3, in: alternateCodeDirectory),
            Data(SHA256.hash(data: resourceDirectory))
        )
    }

    func testPreparesCodeDirectoryAndEmbedsCMSBlob() throws {
        let input = Fixtures.machO64WithCodeSignature()
        let prepared = try RorkSigner.prepareMachOCMSCodeDirectories(
            input,
            bundleIdentifier: "app.rork.sign.cms",
            cmsSignatureLengthHints: [4]
        )

        XCTAssertEqual(prepared.count, 1)
        XCTAssertEqual(prepared[0].architectureIndex, 0)
        XCTAssertEqual(prepared[0].codeDirectory.readUInt32BE(at: 0), 0xfade0c02)
        XCTAssertEqual(prepared[0].codeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(prepared[0].codeDirectory[37], 1)
        XCTAssertEqual(prepared[0].alternateCodeDirectory.readUInt32BE(at: 0), 0xfade0c02)
        XCTAssertEqual(prepared[0].alternateCodeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(prepared[0].alternateCodeDirectory[37], 2)

        let signed = try RorkSigner.signMachOWithCMSBlob(
            input,
            bundleIdentifier: "app.rork.sign.cms",
            cmsSignature: Data([0xde, 0xad, 0xbe, 0xef])
        )
        let blobs = try signatureBlobs(in: signed)
        let codeDirectoryBlob = try XCTUnwrap(blobs[0])
        let alternateCodeDirectoryBlob = try XCTUnwrap(blobs[0x1000])
        let cmsBlob = try XCTUnwrap(blobs[0x10000])

        XCTAssertEqual(codeDirectoryBlob.readUInt32BE(at: 12), 0)
        XCTAssertEqual(alternateCodeDirectoryBlob.readUInt32BE(at: 12), 0)
        XCTAssertEqual(alternateCodeDirectoryBlob[37], 2)
        XCTAssertEqual(cmsBlob.readUInt32BE(at: 0), 0xfade0b01)
        XCTAssertEqual(cmsBlob.readUInt32BE(at: 4), 12)
        XCTAssertEqual(cmsBlob.subdata(in: 8..<12), Data([0xde, 0xad, 0xbe, 0xef]))
    }

    func testCMSPreparationAndEmbeddingIncludeResourceDirectoryHash() throws {
        let resourceDirectory = Data("sealed resources".utf8)
        let input = Fixtures.machO64WithCodeSignature()
        let prepared = try RorkSigner.prepareMachOCMSCodeDirectories(
            input,
            bundleIdentifier: "app.rork.sign.cms.resources",
            resourceDirectory: resourceDirectory,
            cmsSignatureLengthHints: [4]
        )

        XCTAssertEqual(
            specialSlotHash(3, in: prepared[0].codeDirectory),
            Data(Insecure.SHA1.hash(data: resourceDirectory))
        )
        XCTAssertEqual(
            specialSlotHash(3, in: prepared[0].alternateCodeDirectory),
            Data(SHA256.hash(data: resourceDirectory))
        )

        let signed = try RorkSigner.signMachOWithCMSBlob(
            input,
            bundleIdentifier: "app.rork.sign.cms.resources",
            cmsSignature: Data([0xde, 0xad, 0xbe, 0xef]),
            resourceDirectory: resourceDirectory
        )
        let blobs = try signatureBlobs(in: signed)
        let signedCodeDirectory = try XCTUnwrap(blobs[0])
        let signedAlternateCodeDirectory = try XCTUnwrap(blobs[0x1000])
        XCTAssertEqual(
            specialSlotHash(3, in: signedCodeDirectory),
            Data(Insecure.SHA1.hash(data: resourceDirectory))
        )
        XCTAssertEqual(
            specialSlotHash(3, in: signedAlternateCodeDirectory),
            Data(SHA256.hash(data: resourceDirectory))
        )
    }

    func testPreparesUniversalCodeDirectoriesAndEmbedsPerSliceCMSBlobs() throws {
        let input = Fixtures.universalMachOWithTwoThinSlices()
        let prepared = try RorkSigner.prepareMachOCMSCodeDirectories(
            input,
            bundleIdentifier: "app.rork.sign.cms.universal",
            cmsSignatureLengthHints: [3, 4]
        )

        XCTAssertEqual(prepared.map(\.architectureIndex), [0, 1])
        XCTAssertEqual(prepared[0].codeDirectory.readUInt32BE(at: 0), 0xfade0c02)
        XCTAssertEqual(prepared[1].codeDirectory.readUInt32BE(at: 0), 0xfade0c02)
        XCTAssertEqual(prepared[0].codeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(prepared[1].codeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(prepared[0].codeDirectory[37], 1)
        XCTAssertEqual(prepared[1].codeDirectory[37], 1)
        XCTAssertEqual(prepared[0].alternateCodeDirectory.readUInt32BE(at: 0), 0xfade0c02)
        XCTAssertEqual(prepared[1].alternateCodeDirectory.readUInt32BE(at: 0), 0xfade0c02)
        XCTAssertEqual(prepared[0].alternateCodeDirectory[37], 2)
        XCTAssertEqual(prepared[1].alternateCodeDirectory[37], 2)

        let signed = try RorkSigner.signMachOWithCMSBlobs(
            input,
            bundleIdentifier: "app.rork.sign.cms.universal",
            cmsSignatures: [
                Data([0x10, 0x11, 0x12]),
                Data([0x20, 0x21, 0x22, 0x23]),
            ]
        )

        let firstOffset = Int(signed.readUInt32BE(at: 16))
        let firstSize = Int(signed.readUInt32BE(at: 20))
        let secondOffset = Int(signed.readUInt32BE(at: 36))
        let secondSize = Int(signed.readUInt32BE(at: 40))
        let firstSlice = signed.subdata(in: firstOffset..<(firstOffset + firstSize))
        let secondSlice = signed.subdata(in: secondOffset..<(secondOffset + secondSize))

        let firstBlobs = try signatureBlobs(in: firstSlice)
        let secondBlobs = try signatureBlobs(in: secondSlice)
        let firstCMS = try XCTUnwrap(firstBlobs[0x10000])
        let secondCMS = try XCTUnwrap(secondBlobs[0x10000])
        let firstSliceCodeDirectory = try XCTUnwrap(firstBlobs[0])
        let secondSliceCodeDirectory = try XCTUnwrap(secondBlobs[0])
        let firstSliceAlternateCodeDirectory = try XCTUnwrap(firstBlobs[0x1000])
        let secondSliceAlternateCodeDirectory = try XCTUnwrap(secondBlobs[0x1000])

        XCTAssertEqual(firstSliceCodeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(secondSliceCodeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(firstSliceAlternateCodeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(secondSliceAlternateCodeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(firstSliceAlternateCodeDirectory[37], 2)
        XCTAssertEqual(secondSliceAlternateCodeDirectory[37], 2)
        XCTAssertEqual(firstCMS.subdata(in: 8..<11), Data([0x10, 0x11, 0x12]))
        XCTAssertEqual(secondCMS.subdata(in: 8..<12), Data([0x20, 0x21, 0x22, 0x23]))
    }

    func testCMSEmbeddingRejectsWrongBlobCountForUniversalMachO() {
        XCTAssertThrowsError(
            try RorkSigner.signMachOWithCMSBlobs(
                Fixtures.universalMachOWithTwoThinSlices(),
                bundleIdentifier: "app.rork.sign.cms.universal",
                cmsSignatures: [Data([0x01])]
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .cmsSigning("Universal Mach-O signing needs one CMS blob per architecture.")
            )
        }
    }

    func testCMSPreparationRejectsNegativeLengthHint() {
        XCTAssertThrowsError(
            try RorkSigner.prepareMachOCMSCodeDirectories(
                Fixtures.machO64WithCodeSignature(),
                bundleIdentifier: "app.rork.sign.cms",
                cmsSignatureLengthHints: [-1]
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .cmsSigning("CMS signature length hints must be non-negative.")
            )
        }
    }

    func testCMSEmbeddingRejectsEmptyThinCMSBlob() {
        XCTAssertThrowsError(
            try RorkSigner.signMachOWithCMSBlob(
                Fixtures.machO64WithCodeSignature(),
                bundleIdentifier: "app.rork.sign.cms",
                cmsSignature: Data()
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .cmsSigning("Thin Mach-O signing received an empty CMS blob.")
            )
        }
    }

    func testAdHocSignsUniversalMachO() throws {
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.universalMachOWithTwoThinSlices(),
            bundleIdentifier: "app.rork.sign.universal"
        )

        let info = try RorkSigner.inspectMachO(signed)
        XCTAssertEqual(info.kind, .universal)
        XCTAssertEqual(info.architectureCount, 2)

        let firstOffset = Int(signed.readUInt32BE(at: 16))
        let firstSize = Int(signed.readUInt32BE(at: 20))
        let secondOffset = Int(signed.readUInt32BE(at: 36))
        let secondSize = Int(signed.readUInt32BE(at: 40))
        XCTAssertEqual(firstOffset, 0x1000)
        XCTAssertEqual(secondOffset, alignUpForTest(firstOffset + firstSize, alignment: 0x1000))
        XCTAssertGreaterThan(firstSize, 0x140)
        XCTAssertGreaterThan(secondSize, 0x140)

        let firstSlice = signed.subdata(in: firstOffset..<(firstOffset + firstSize))
        let secondSlice = signed.subdata(in: secondOffset..<(secondOffset + secondSize))
        let firstInfo = try RorkSigner.inspectMachO(firstSlice)
        let secondInfo = try RorkSigner.inspectMachO(secondSlice)
        XCTAssertTrue(firstInfo.hasCodeSignature)
        XCTAssertTrue(secondInfo.hasCodeSignature)
        XCTAssertEqual(firstSlice.count, Int(firstInfo.codeSignatureOffset + firstInfo.codeSignatureSize))
        XCTAssertEqual(secondSlice.count, Int(secondInfo.codeSignatureOffset + secondInfo.codeSignatureSize))
    }

    func testReadsUniversalEmbeddedCodeSignatureSlots() throws {
        let signed = try RorkSigner.signMachOAdHoc(
            Fixtures.universalMachOWithTwoThinSlices(),
            bundleIdentifier: "app.rork.sign.universal.inspect"
        )

        let signatures = try RorkSigner.readEmbeddedCodeSignatures(in: signed)

        XCTAssertEqual(signatures.map(\.architectureIndex), [0, 1])
        XCTAssertTrue(signatures.allSatisfy { $0.firstSlot(0) != nil })
        XCTAssertTrue(signatures.allSatisfy { $0.firstSlot(2) != nil })
        XCTAssertTrue(signatures.allSatisfy { $0.firstSlot(0x1000) != nil })
    }
}

private func compatibleCodeSignatureReservationSize(codeLimit: UInt64) -> UInt32 {
    let hashBudget = ((codeLimit / 4096) + 1) * UInt64(20 + 32)
    let alignedHashBudget = UInt64(alignUpForTest(Int(hashBudget), alignment: 4096))
    return UInt32(alignedHashBudget + 32 * 1024)
}

private func alignUpForTest(_ value: Int, alignment: Int) -> Int {
    let remainder = value % alignment
    return remainder == 0 ? value : value + alignment - remainder
}
