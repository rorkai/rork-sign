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
        try IPAArchive.withExtractedPayloadApp(
            from: archiveURL,
            temporaryDirectory: temporaryDirectory
        ) { payload in
            try extractBundleMetadata(
                bundleURL: payload.appBundleURL,
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
        try largestIcon(
            in: bundleURL,
            matching: prefixes,
            fileSize: fileSize
        )
    }

    /// Selects the largest readable icon matching the bundle declarations.
    ///
    /// Icon declarations are advisory metadata and can contain stale or
    /// unreadable candidates. Skipping those candidates preserves metadata
    /// extraction when another declared icon remains usable.
    static func largestIcon(
        in bundleURL: URL,
        matching prefixes: [String],
        fileSize: (URL) throws -> Int64
    ) throws -> URL? {
        let contents = try FileManager.default.entries(
            in: bundleURL,
            options: .skipsHiddenFiles
        )

        var best: (url: URL, size: Int64)?
        for entry in contents {
            guard entry.kind == .regularFile,
                  prefixes.contains(where: {
                      entry.url.lastPathComponent.hasPrefix($0)
                  }) else {
                continue
            }
            let size: Int64
            do {
                size = try fileSize(entry.url)
            } catch {
                continue
            }
            if let best, best.size >= size {
                continue
            }
            best = (entry.url, size)
        }
        return best?.url
    }

    /// Reads file size through attributes available on native and WASI hosts.
    ///
    /// URL resource values are intentionally avoided because browser Foundation
    /// does not expose them consistently.
    private static func fileSize(_ url: URL) throws -> Int64 {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes[.size] as? NSNumber)?.int64Value ?? 0
    }

    /// Produces the stable icon filename expected by ZSign-compatible metadata.
    ///
    /// The source path, rather than file contents, preserves the compatibility
    /// naming contract used by existing metadata consumers.
    private static func sha1Hex(_ string: String) -> String {
        Insecure.SHA1.hash(data: Data(string.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    /// Returns a non-empty plist string after removing incidental whitespace.
    ///
    /// Metadata fields treat empty and whitespace-only plist values as absent so
    /// their documented fallback order remains effective.
    private static func string(_ value: Any?) -> String? {
        guard let string = value as? String else {
            return nil
        }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
