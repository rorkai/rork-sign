#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
import RorkSign
import XCTest

final class MachO32SigningTests: XCTestCase {
    func testSignsArm64_32WithAndWithoutExistingSignature() throws {
        for existingSignature in [false, true] {
            let input = Fixtures.arm64_32MachO(existingSignature: existingSignature)
            let signed = try RorkSigner.signMachOAdHoc(input, bundleIdentifier: "app.rork.watch")
            let info = try RorkSigner.inspectMachO(signed)
            XCTAssertEqual(info.kind, .machO32)
            XCTAssertEqual(info.codeSignatureOffset, 0x1000)
            XCTAssertEqual(signed.readUInt32LE(at: 4), 0x0200000c)
            XCTAssertEqual(signed.readUInt32LE(at: 8), 1)
            XCTAssertEqual(signed.readUInt32LE(at: 16), 3)
            XCTAssertEqual(signed.readUInt32LE(at: 20), 264)
            XCTAssertEqual(signed.subdata(in: 0x400..<0x480), input.subdata(in: 0x400..<0x480))

            let linkedit = 220
            let fileSize = UInt32(signed.count - 0x800)
            XCTAssertEqual(signed.readUInt32LE(at: linkedit + 24), 0x2000)
            XCTAssertEqual(signed.readUInt32LE(at: linkedit + 28), (fileSize + 4095) & ~4095)
            XCTAssertEqual(signed.readUInt32LE(at: linkedit + 32), 0x800)
            XCTAssertEqual(signed.readUInt32LE(at: linkedit + 36), fileSize)
            XCTAssertEqual(signed.readUInt32LE(at: linkedit + 40), 7)
            XCTAssertEqual(signed.readUInt32LE(at: linkedit + 44), 1)
            XCTAssertEqual(signed.readUInt32LE(at: linkedit + 48), 0)
            XCTAssertEqual(signed.readUInt32LE(at: linkedit + 52), 0)
            XCTAssertTrue(try RorkSigner.checkMachOCodeSignatures(signed).flatMap(\.codeDirectories).allSatisfy(\.codeSlotsValid))

            let blobs = try signatureBlobs(in: signed)
            let sha256 = try XCTUnwrap(blobs[0x1000])
            XCTAssertEqual(specialSlotHash(1, in: sha256), Data(SHA256.hash(data: Fixtures.watchEmbeddedInfo)))
            XCTAssertEqual(sha256.readUInt64BE(at: 72), 0x2000)
        }
    }

    func testResigningRemainsStable() throws {
        let input = Fixtures.arm64_32MachO(existingSignature: false)
        let signed = try RorkSigner.signMachOAdHoc(input, bundleIdentifier: "app.rork.watch")
        let resigned = try RorkSigner.signMachOAdHoc(signed, bundleIdentifier: "app.rork.watch")
        XCTAssertEqual(resigned, signed)
    }

    func testMixedWatchArchitecturesPreserveSlicesAndCMSCodeDirectories() throws {
        for fat64 in [false, true] {
            let input = Fixtures.universalWatchMachO(fat64: fat64)
            let signedAdHoc = try RorkSigner.signMachOAdHoc(input, bundleIdentifier: "app.rork.watch")
            XCTAssertEqual(try RorkSigner.inspectMachO(signedAdHoc).architectureCount, 2)
            XCTAssertEqual(signedAdHoc.readUInt32BE(at: 8), 0x0100000c)
            XCTAssertEqual(signedAdHoc.readUInt32BE(at: fat64 ? 40 : 28), 0x0200000c)
            let adHocReports = try RorkSigner.checkMachOCodeSignatures(signedAdHoc)
            XCTAssertEqual(adHocReports.count, 2)
            XCTAssertTrue(adHocReports.flatMap(\.codeDirectories).allSatisfy(\.codeSlotsValid))

            let signatures = [Data([1, 2, 3]), Data([4, 5, 6, 7])]
            let prepared = try RorkSigner.prepareMachOCMSCodeDirectories(
                input, bundleIdentifier: "app.rork.watch", cmsSignatureLengthHints: signatures.map(\.count)
            )
            let signedCMS = try RorkSigner.signMachOWithCMSBlobs(
                input, bundleIdentifier: "app.rork.watch", cmsSignatures: signatures
            )
            let embedded = try RorkSigner.readEmbeddedCodeSignatures(in: signedCMS)
            XCTAssertEqual(embedded.count, 2)
            for index in embedded.indices {
                XCTAssertEqual(embedded[index].firstSlot(0)?.data, prepared[index].codeDirectory)
                XCTAssertEqual(embedded[index].firstSlot(0x1000)?.data, prepared[index].alternateCodeDirectory)
                XCTAssertEqual(embedded[index].firstSlot(0x10000)?.data.dropFirst(8), signatures[index])
            }
        }
    }

    func testSignsNestedWatchBundleWithIdentityAndReusesCache() throws {
        let fixture = try SyntheticSigningFixture()
        defer { fixture.remove() }
        let host = fixture.directory.appendingPathComponent("Host.app")
        let watch = host.appendingPathComponent("Watch/Watch.app")
        for (url, executable, identifier, data) in [
            (host, "Host", "app.rork.host", Fixtures.machO64WithCodeSignature()),
            (watch, "Watch", "app.rork.host.watch", Fixtures.universalWatchMachO())
        ] {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            let plist = try PropertyListSerialization.data(fromPropertyList: [
                "CFBundleExecutable": executable, "CFBundleIdentifier": identifier,
                "CFBundlePackageType": "APPL", "CFBundleVersion": "1"
            ], format: .xml, options: 0)
            try plist.write(to: url.appendingPathComponent("Info.plist"))
            try data.write(to: url.appendingPathComponent(executable))
        }
        let options = BundleSigningOptions(signingCache: SigningCacheOptions(directoryURL: fixture.directory.appendingPathComponent("cache")))
        let first = try RorkSigner.signBundleWithIdentity(at: host, identity: fixture.identity, options: options)
        XCTAssertEqual(first.signedCode.count, 2)
        let signedWatch = try Data(contentsOf: watch.appendingPathComponent("Watch"))
        let reports = try RorkSigner.checkMachOCodeSignatures(signedWatch)
        XCTAssertEqual(reports.count, 2)
        XCTAssertTrue(reports.allSatisfy(\.cmsSignatureValid))
        XCTAssertTrue(reports.flatMap(\.codeDirectories).allSatisfy(\.codeSlotsValid))
        let second = try RorkSigner.signBundleWithIdentity(at: host, identity: fixture.identity, options: options)
        XCTAssertEqual(second.cachedCode.count, 2)
    }

    func testRejectsTruncatedAndMismatched32BitSegments() {
        var truncatedCommand = Fixtures.arm64_32MachO()
        truncatedCommand.writeUInt32LE(8, at: 32)
        var truncatedSections = Fixtures.arm64_32MachO()
        truncatedSections.writeUInt32LE(3, at: 28 + 48)
        var wrongWidth = Fixtures.arm64_32MachO()
        wrongWidth.writeUInt32LE(0x19, at: 28)
        for input in [truncatedCommand, truncatedSections, wrongWidth] {
            XCTAssertThrowsError(try RorkSigner.signMachOAdHoc(input, bundleIdentifier: "app.rork.watch"))
        }
    }
}

extension Fixtures {
    static let watchEmbeddedInfo = Data("<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>app.rork.watch</string></dict></plist>".utf8)

    static func arm64_32MachO(existingSignature: Bool = true) -> Data {
        var data = Data(repeating: 0, count: existingSignature ? 0x1040 : 0x1000)
        data.writeUInt32LE(0xfeedface, at: 0)
        data.writeUInt32LE(0x0200000c, at: 4)
        data.writeUInt32LE(1, at: 8)
        data.writeUInt32LE(2, at: 12)
        data.writeUInt32LE(existingSignature ? 3 : 2, at: 16)
        data.writeUInt32LE(existingSignature ? 264 : 248, at: 20)
        let text = 28
        data.writeUInt32LE(1, at: text)
        data.writeUInt32LE(192, at: text + 4)
        data.writeFixedString("__TEXT", at: text + 8, count: 16)
        data.writeUInt32LE(0x2000, at: text + 28)
        data.writeUInt32LE(0x800, at: text + 36)
        data.writeUInt32LE(7, at: text + 40)
        data.writeUInt32LE(5, at: text + 44)
        data.writeUInt32LE(2, at: text + 48)
        for (offset, name, size, fileOffset) in [(84, "__text", 0x80, 0x400), (152, "__info_plist", watchEmbeddedInfo.count, 0x500)] {
            data.writeFixedString(name, at: offset, count: 16)
            data.writeFixedString("__TEXT", at: offset + 16, count: 16)
            data.writeUInt32LE(UInt32(fileOffset), at: offset + 32)
            data.writeUInt32LE(UInt32(size), at: offset + 36)
            data.writeUInt32LE(UInt32(fileOffset), at: offset + 40)
        }
        data.replaceSubrange(0x400..<0x480, with: Data(repeating: 0xa5, count: 0x80))
        data.replaceSubrange(0x500..<(0x500 + watchEmbeddedInfo.count), with: watchEmbeddedInfo)
        let linkedit = 220
        data.writeUInt32LE(1, at: linkedit)
        data.writeUInt32LE(56, at: linkedit + 4)
        data.writeFixedString("__LINKEDIT", at: linkedit + 8, count: 16)
        data.writeUInt32LE(0x2000, at: linkedit + 24)
        data.writeUInt32LE(0x1000, at: linkedit + 28)
        data.writeUInt32LE(0x800, at: linkedit + 32)
        data.writeUInt32LE(UInt32(data.count - 0x800), at: linkedit + 36)
        data.writeUInt32LE(7, at: linkedit + 40)
        data.writeUInt32LE(1, at: linkedit + 44)
        if existingSignature {
            data.writeUInt32LE(0x1d, at: 276)
            data.writeUInt32LE(16, at: 280)
            data.writeUInt32LE(0x1000, at: 284)
            data.writeUInt32LE(0x40, at: 288)
        }
        return data
    }

    static func universalWatchMachO(fat64: Bool = false) -> Data {
        let slices = [machO64WithCodeSignature(), arm64_32MachO()]
        let offsets = [0x1000, 0x2000]
        var data = Data(repeating: 0, count: offsets[1] + slices[1].count)
        data.writeUInt32BE(fat64 ? 0xcafebabf : 0xcafebabe, at: 0)
        data.writeUInt32BE(2, at: 4)
        for index in slices.indices {
            let entry = 8 + index * (fat64 ? 32 : 20)
            data.writeUInt32BE(index == 0 ? 0x0100000c : 0x0200000c, at: entry)
            data.writeUInt32BE(index == 0 ? 0 : 1, at: entry + 4)
            if fat64 {
                data.writeUInt32BE(UInt32(offsets[index]), at: entry + 12)
                data.writeUInt32BE(UInt32(slices[index].count), at: entry + 20)
                data.writeUInt32BE(12, at: entry + 24)
            } else {
                data.writeUInt32BE(UInt32(offsets[index]), at: entry + 8)
                data.writeUInt32BE(UInt32(slices[index].count), at: entry + 12)
                data.writeUInt32BE(12, at: entry + 16)
            }
            data.replaceSubrange(offsets[index]..<(offsets[index] + slices[index].count), with: slices[index])
        }
        return data
    }
}
