#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// ZSign-compatible app metadata extracted from an app bundle or IPA.
///
/// The JSON coding keys intentionally match ZSign's `metadata.json` output so
/// existing automation can consume the Swift implementation without a schema
/// adapter.
public struct AppMetadataReport: Codable, Equatable {
    /// User-facing app name from `CFBundleDisplayName` or `CFBundleName`.
    public let appName: String

    /// App version from `CFBundleShortVersionString` or `CFBundleVersion`.
    public let appVersion: String

    /// Bundle identifier from `CFBundleIdentifier`.
    public let appBundleIdentifier: String

    /// Size of the source IPA when extracting from an archive, otherwise `0`.
    public let appSize: Int64

    /// Copied icon filename inside the metadata output directory, or `""`.
    public let iconName: String

    /// Source IPA filename when extracting from an archive, otherwise `""`.
    public let fileName: String

    /// Unix timestamp written into the metadata report.
    public let timestamp: Int

    enum CodingKeys: String, CodingKey {
        case appName = "AppName"
        case appVersion = "AppVersion"
        case appBundleIdentifier = "AppBundleIdentifier"
        case appSize = "AppSize"
        case iconName = "IconName"
        case fileName = "FileName"
        case timestamp = "Timestamp"
    }
}

/// Extracts app metadata and optional icon output.
enum AppMetadataExtractor {
    /// Extracts metadata from an app bundle on disk.
    static func extractBundleMetadata(
        bundleURL: URL,
        outputDirectory: URL?,
        sourceArchiveURL: URL?,
        timestamp: Date
    ) throws -> AppMetadataReport {
        let info = try readInfoPlist(bundleURL: bundleURL)
        let outputDirectory = outputDirectory
        if let outputDirectory {
            try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        }

        let iconName = try copiedIconName(
            bundleURL: bundleURL,
            info: info,
            outputDirectory: outputDirectory
        )
        let report = AppMetadataReport(
            appName: string(info["CFBundleDisplayName"]) ?? string(info["CFBundleName"]) ?? "",
            appVersion: string(info["CFBundleShortVersionString"]) ?? string(info["CFBundleVersion"]) ?? "",
            appBundleIdentifier: string(info["CFBundleIdentifier"]) ?? "",
            appSize: try sourceArchiveURL.map(fileSize) ?? 0,
            iconName: iconName,
            fileName: sourceArchiveURL?.lastPathComponent ?? "",
            timestamp: Int(timestamp.timeIntervalSince1970)
        )

        if let outputDirectory {
            try write(report: report, to: outputDirectory.appendingPathComponent("metadata.json"))
        }
        return report
    }

    /// Extracts metadata from the single app bundle inside an IPA archive.
    static func extractIPAMetadata(
        archiveURL: URL,
        outputDirectory: URL?,
        timestamp: Date,
        temporaryDirectory: URL?
    ) throws -> AppMetadataReport {
        try withExtractedPayloadApp(archiveURL: archiveURL, temporaryDirectory: temporaryDirectory) { _, appURL in
            try extractBundleMetadata(
                bundleURL: appURL,
                outputDirectory: outputDirectory,
                sourceArchiveURL: archiveURL,
                timestamp: timestamp
            )
        }
    }

    /// Writes a JSON metadata report with deterministic key ordering.
    private static func write(report: AppMetadataReport, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(report)
        try data.writeReplacingItem(at: url)
    }

    /// Reads and validates the bundle's `Info.plist`.
    private static func readInfoPlist(bundleURL: URL) throws -> [String: Any] {
        let infoURL = bundleURL.appendingPathComponent("Info.plist")
        let data = try Data(contentsOf: infoURL)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = plist as? [String: Any] else {
            throw RorkSignError.invalidBundle("Info.plist is not a dictionary: \(infoURL.path).")
        }
        return dictionary
    }

    /// Finds the largest top-level icon whose filename matches the bundle icon declarations.
    private static func copiedIconName(
        bundleURL: URL,
        info: [String: Any],
        outputDirectory: URL?
    ) throws -> String {
        let iconPrefixes = iconNames(in: info)
        guard !iconPrefixes.isEmpty,
              let iconURL = try largestIcon(in: bundleURL, matching: iconPrefixes) else {
            return ""
        }
        guard let outputDirectory else {
            return ""
        }

        let copiedName = sha1Hex(iconURL.path) + ".png"
        let destinationURL = outputDirectory.appendingPathComponent(copiedName)
        if FileManager.default.fileExists(atPath: destinationURL.path) {
            try FileManager.default.removeItem(at: destinationURL)
        }
        try FileManager.default.copyItem(
            at: iconURL,
            to: destinationURL
        )
        return copiedName
    }

    /// Reads icon declarations in the same priority order as ZSign.
    private static func iconNames(in info: [String: Any]) -> [String] {
        if let icons = info["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] {
            let names = files.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            if !names.isEmpty {
                return names
            }
        }

        if let files = info["CFBundleIconFiles"] as? [String] {
            let names = files.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            if !names.isEmpty {
                return names
            }
        }

        return string(info["CFBundleIconFile"]).map { [$0] } ?? []
    }

    /// Selects the largest matching top-level icon file.
    private static func largestIcon(in bundleURL: URL, matching prefixes: [String]) throws -> URL? {
        let contents = try FileManager.default.entries(
            in: bundleURL,
            options: .skipsHiddenFiles
        )

        var best: (url: URL, size: Int64)?
        for entry in contents {
            guard entry.kind == .regularFile,
                  let size = try? fileSize(entry.url),
                  prefixes.contains(where: {
                      entry.url.lastPathComponent.hasPrefix($0)
                  }) else {
                continue
            }
            if best == nil || size > best!.size {
                best = (entry.url, size)
            }
        }
        return best?.url
    }

    /// Extracts an IPA into a temporary workspace and passes its payload app to `body`.
    private static func withExtractedPayloadApp<T>(
        archiveURL: URL,
        temporaryDirectory: URL?,
        body: (_ archiveRoot: URL, _ appURL: URL) throws -> T
    ) throws -> T {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: archiveURL.path) else {
            throw RorkSignError.invalidArchive("IPA archive does not exist: \(archiveURL.path).")
        }

        let workspaceRoot = try workspaceRootDirectory(temporaryDirectory)
        let workspace = workspaceRoot
            .appendingPathComponent("rork-sign-metadata-\(UUID().uuidString)", isDirectory: true)
        let archiveRoot = workspace.appendingPathComponent("ArchiveRoot", isDirectory: true)
        defer {
            try? fileManager.removeItem(at: workspace)
        }

        do {
            try fileManager.createDirectory(at: archiveRoot, withIntermediateDirectories: true)
            _ = try IPAArchive.extract(
                at: archiveURL,
                to: archiveRoot
            )
        } catch let error as RorkSignError {
            throw error
        } catch {
            throw RorkSignError.invalidArchive("IPA archive could not be extracted: \(error.localizedDescription)")
        }

        return try body(archiveRoot, try payloadAppBundle(in: archiveRoot))
    }

    /// Returns a usable parent directory for temporary metadata extraction.
    private static func workspaceRootDirectory(_ temporaryDirectory: URL?) throws -> URL {
        let fileManager = FileManager.default
        let rootURL = temporaryDirectory ?? fileManager.temporaryDirectory
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: rootURL.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                throw RorkSignError.invalidArchive("Temporary path is not a directory: \(rootURL.path).")
            }
        } else {
            do {
                try fileManager.createDirectory(at: rootURL, withIntermediateDirectories: true)
            } catch {
                throw RorkSignError.invalidArchive("Temporary directory could not be created: \(error.localizedDescription)")
            }
        }
        return rootURL
    }

    /// Finds the single app bundle inside an extracted IPA payload.
    private static func payloadAppBundle(in archiveRoot: URL) throws -> URL {
        let payloadURL = archiveRoot.appendingPathComponent("Payload", isDirectory: true)
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: payloadURL.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            throw RorkSignError.invalidArchive("IPA archive is missing a Payload directory.")
        }

        let appBundles = try FileManager.default.entries(
            in: payloadURL,
            options: .skipsHiddenFiles
        )
            .filter { entry in
                entry.kind == .directory
                    && entry.url.pathExtension.lowercased() == "app"
            }
            .map(\.url)
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        guard let appURL = appBundles.first else {
            throw RorkSignError.invalidArchive("IPA archive has no app bundle in Payload.")
        }
        guard appBundles.count == 1 else {
            throw RorkSignError.invalidArchive("IPA archive contains multiple app bundles in Payload.")
        }
        return appURL
    }

    private static func fileSize(_ url: URL) throws -> Int64 {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes[.size] as? NSNumber)?.int64Value ?? 0
    }

    private static func sha1Hex(_ string: String) -> String {
        Insecure.SHA1.hash(data: Data(string.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private static func string(_ value: Any?) -> String? {
        guard let string = value as? String else {
            return nil
        }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
