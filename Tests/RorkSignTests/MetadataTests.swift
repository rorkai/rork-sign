import Foundation
@testable import RorkSign
import XCTest

final class MetadataTests: XCTestCase {
    func testBundleMetadataWritesZSignJSONAndLargestDeclaredIcon() throws {
        let fixture = try makeMetadataAppFixture()
        let outputDirectory = fixture.rootURL.appendingPathComponent("Metadata", isDirectory: true)
        let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }

        let report = try RorkSigner.extractBundleMetadata(
            at: fixture.appURL,
            outputDirectory: outputDirectory,
            timestamp: timestamp
        )

        XCTAssertEqual(report.appName, "Fixture App")
        XCTAssertEqual(report.appVersion, "1.2.3")
        XCTAssertEqual(report.appBundleIdentifier, "com.example.metadata")
        XCTAssertEqual(report.appSize, 0)
        XCTAssertEqual(report.fileName, "")
        XCTAssertEqual(report.timestamp, 1_700_000_000)
        XCTAssertTrue(isSHA1PNGName(report.iconName))
        XCTAssertEqual(
            try Data(contentsOf: outputDirectory.appendingPathComponent(report.iconName)),
            try Data(contentsOf: fixture.largeIconURL)
        )

        let jsonURL = outputDirectory.appendingPathComponent("metadata.json")
        let decoded = try JSONDecoder().decode(AppMetadataReport.self, from: Data(contentsOf: jsonURL))
        XCTAssertEqual(decoded, report)

        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: jsonURL)) as? [String: Any]
        )
        XCTAssertEqual(json["AppName"] as? String, "Fixture App")
        XCTAssertEqual(json["AppVersion"] as? String, "1.2.3")
        XCTAssertEqual(json["AppBundleIdentifier"] as? String, "com.example.metadata")
        XCTAssertEqual(json["IconName"] as? String, report.iconName)
    }

    /// An unreadable optional icon candidate must not prevent metadata
    /// extraction from selecting another declared icon.
    func testIconSelectionSkipsCandidateWhoseSizeCannotBeRead() throws {
        let fixture = try makeMetadataAppFixture()
        let smallIconURL = fixture.appURL.appendingPathComponent(
            "AppIcon20.png"
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }

        let iconURL = try AppMetadataExtractor.largestIcon(
            in: fixture.appURL,
            matching: ["AppIcon"],
            fileSize: { url in
                if url == fixture.largeIconURL {
                    throw NSError(
                        domain: "RorkSignTests",
                        code: 1,
                        userInfo: [
                            NSLocalizedDescriptionKey: "size unavailable",
                        ]
                    )
                }
                return Int64(try Data(contentsOf: url).count)
            }
        )

        XCTAssertEqual(iconURL, smallIconURL)
    }

    func testBundleMetadataWithoutOutputDirectoryDoesNotReturnUncopiedIconName() throws {
        let fixture = try makeMetadataAppFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }

        let report = try RorkSigner.extractBundleMetadata(
            at: fixture.appURL,
            outputDirectory: nil,
            timestamp: Date(timeIntervalSince1970: 1_700_000_001)
        )

        XCTAssertEqual(report.iconName, "")
        XCTAssertEqual(report.appSize, 0)
        XCTAssertEqual(report.fileName, "")
        XCTAssertEqual(report.timestamp, 1_700_000_001)
    }

    func testBundleMetadataCanCopyIconIntoExistingOutputDirectory() throws {
        let fixture = try makeMetadataAppFixture()
        let outputDirectory = fixture.rootURL.appendingPathComponent("Metadata", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }

        let firstReport = try RorkSigner.extractBundleMetadata(
            at: fixture.appURL,
            outputDirectory: outputDirectory,
            timestamp: Date(timeIntervalSince1970: 1_700_000_001)
        )
        try Data("stale icon".utf8).write(to: outputDirectory.appendingPathComponent(firstReport.iconName))

        let secondReport = try RorkSigner.extractBundleMetadata(
            at: fixture.appURL,
            outputDirectory: outputDirectory,
            timestamp: Date(timeIntervalSince1970: 1_700_000_002)
        )

        XCTAssertEqual(secondReport.iconName, firstReport.iconName)
        XCTAssertEqual(
            try Data(contentsOf: outputDirectory.appendingPathComponent(secondReport.iconName)),
            try Data(contentsOf: fixture.largeIconURL)
        )
    }

    /// Keeps archive-level identity separate from metadata read from the
    /// extracted app bundle, including when a custom workspace is used.
    func testIPAMetadataUsesArchiveFilenameAndSize() throws {
        let fixture = try makeMetadataAppFixture()
        let archiveRoot = fixture.rootURL.appendingPathComponent("ArchiveRoot", isDirectory: true)
        let payloadURL = archiveRoot.appendingPathComponent("Payload", isDirectory: true)
        let archivedAppURL = payloadURL.appendingPathComponent("Host.app", isDirectory: true)
        let archiveURL = fixture.rootURL.appendingPathComponent("Input.ipa")
        let outputDirectory = fixture.rootURL.appendingPathComponent("IPAMetadata", isDirectory: true)
        let tempURL = fixture.rootURL.appendingPathComponent("CustomTemp", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.rootURL)
        }

        try FileManager.default.createDirectory(at: payloadURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: tempURL, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: fixture.appURL, to: archivedAppURL)
        try FileManager.default.createIPAArchive(contentsOf: archiveRoot, at: archiveURL)

        let report = try RorkSigner.extractIPAMetadata(
            at: archiveURL,
            outputDirectory: outputDirectory,
            timestamp: Date(timeIntervalSince1970: 1_700_000_002),
            temporaryDirectory: tempURL
        )

        XCTAssertEqual(report.appName, "Fixture App")
        XCTAssertEqual(report.appVersion, "1.2.3")
        XCTAssertEqual(report.appBundleIdentifier, "com.example.metadata")
        XCTAssertEqual(report.appSize, try fileSize(archiveURL))
        XCTAssertEqual(report.fileName, "Input.ipa")
        XCTAssertEqual(report.timestamp, 1_700_000_002)
        XCTAssertTrue(isSHA1PNGName(report.iconName))
        XCTAssertEqual(
            try Data(contentsOf: outputDirectory.appendingPathComponent(report.iconName)),
            try Data(contentsOf: fixture.largeIconURL)
        )
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: tempURL.path), [])
    }

    func testMetadataFallsBackToLegacyIconAndVersionKeys() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let appURL = rootURL.appendingPathComponent("Legacy.app", isDirectory: true)
        let iconURL = appURL.appendingPathComponent("LegacyIcon@2x.png")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: rootURL)
        }

        try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
        try writeMetadataInfoPlist(
            [
                "CFBundleIdentifier": "com.example.legacy",
                "CFBundleName": "Legacy Name",
                "CFBundleVersion": "42",
                "CFBundleIconFile": "LegacyIcon",
            ],
            to: appURL.appendingPathComponent("Info.plist")
        )
        try Data("legacy icon".utf8).write(to: iconURL)

        let outputDirectory = rootURL.appendingPathComponent("Metadata", isDirectory: true)
        let report = try RorkSigner.extractBundleMetadata(
            at: appURL,
            outputDirectory: outputDirectory,
            timestamp: Date(timeIntervalSince1970: 1_700_000_003)
        )

        XCTAssertEqual(report.appName, "Legacy Name")
        XCTAssertEqual(report.appVersion, "42")
        XCTAssertEqual(report.appBundleIdentifier, "com.example.legacy")
        XCTAssertTrue(isSHA1PNGName(report.iconName))
        XCTAssertEqual(
            try Data(contentsOf: outputDirectory.appendingPathComponent(report.iconName)),
            try Data(contentsOf: iconURL)
        )
    }
}

private struct MetadataAppFixture {
    let rootURL: URL
    let appURL: URL
    let largeIconURL: URL
}

private func makeMetadataAppFixture() throws -> MetadataAppFixture {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let appURL = rootURL.appendingPathComponent("Host.app", isDirectory: true)
    let smallIconURL = appURL.appendingPathComponent("AppIcon20.png")
    let largeIconURL = appURL.appendingPathComponent("AppIcon1024@2x.png")

    try FileManager.default.createDirectory(at: appURL, withIntermediateDirectories: true)
    try writeMetadataInfoPlist(
        [
            "CFBundleIdentifier": "com.example.metadata",
            "CFBundleName": "Fallback Name",
            "CFBundleDisplayName": "Fixture App",
            "CFBundleVersion": "42",
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleIcons": [
                "CFBundlePrimaryIcon": [
                    "CFBundleIconFiles": [
                        "AppIcon20",
                        "AppIcon1024",
                    ],
                ],
            ],
        ],
        to: appURL.appendingPathComponent("Info.plist")
    )
    try Data("small".utf8).write(to: smallIconURL)
    try Data("this is the larger app icon fixture".utf8).write(to: largeIconURL)
    return MetadataAppFixture(rootURL: rootURL, appURL: appURL, largeIconURL: largeIconURL)
}

private func writeMetadataInfoPlist(_ dictionary: [String: Any], to url: URL) throws {
    let data = try PropertyListSerialization.data(
        fromPropertyList: dictionary,
        format: .xml,
        options: 0
    )
    try data.write(to: url)
}

private func fileSize(_ url: URL) throws -> Int64 {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes[.size] as? NSNumber)?.int64Value ?? 0
}

private func isSHA1PNGName(_ name: String) -> Bool {
    guard name.count == 44, name.hasSuffix(".png") else {
        return false
    }
    return name.dropLast(4).allSatisfy { character in
        character.isNumber || ("a"..."f").contains(character)
    }
}
