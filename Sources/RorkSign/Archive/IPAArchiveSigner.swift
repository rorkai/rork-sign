import Foundation
import ZIPFoundation

/// Signs app bundles stored inside IPA archives.
///
/// This layer intentionally owns only archive mechanics: unzip to an isolated
/// workspace, find the single `Payload/*.app` bundle, delegate to the existing
/// bundle signer, then zip the archive root back into a new IPA. Keeping archive
/// handling separate prevents the Mach-O and bundle signers from learning about
/// transport formats.
enum IPAArchiveSigner {
    /// Signs the IPA's app bundle with ad-hoc signatures.
    static func signAdHoc(
        archiveURL: URL,
        outputURL: URL,
        options: BundleSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode,
        temporaryDirectory: URL?
    ) throws -> IPAArchiveSigningReport {
        try signArchive(
            archiveURL: archiveURL,
            outputURL: outputURL,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        ) { appURL in
            try BundleSigner.signAdHoc(bundleURL: appURL, options: options)
        }
    }

    /// Signs the IPA's app bundle with identity-backed CMS signatures.
    static func signWithIdentity(
        archiveURL: URL,
        outputURL: URL,
        identity: SigningIdentity,
        options: BundleSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode,
        temporaryDirectory: URL?
    ) throws -> IPAArchiveSigningReport {
        try signArchive(
            archiveURL: archiveURL,
            outputURL: outputURL,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        ) { appURL in
            try BundleSigner.signWithIdentity(
                bundleURL: appURL,
                identity: identity,
                options: options
            )
        }
    }

    /// Rewrites and ad-hoc signs the IPA's app bundle as a standalone app.
    static func signStandaloneAdHoc(
        archiveURL: URL,
        outputURL: URL,
        options: StandaloneBundleSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode,
        temporaryDirectory: URL?
    ) throws -> IPAArchiveSigningReport {
        try signArchive(
            archiveURL: archiveURL,
            outputURL: outputURL,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        ) { appURL in
            try StandaloneBundleSigner.signAdHoc(bundleURL: appURL, options: options)
        }
    }

    /// Rewrites and CMS-signs the IPA's app bundle as a standalone app.
    static func signStandaloneWithIdentity(
        archiveURL: URL,
        outputURL: URL,
        identity: SigningIdentity,
        options: StandaloneBundleSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode,
        temporaryDirectory: URL?
    ) throws -> IPAArchiveSigningReport {
        try signArchive(
            archiveURL: archiveURL,
            outputURL: outputURL,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        ) { appURL in
            try StandaloneBundleSigner.signWithIdentity(
                bundleURL: appURL,
                identity: identity,
                options: options
            )
        }
    }

    /// Performs archive extraction/repacking around one bundle-signing closure.
    private static func signArchive(
        archiveURL: URL,
        outputURL: URL,
        archiveCompressionMode: ArchiveCompressionMode,
        temporaryDirectory: URL?,
        signBundle: (URL) throws -> BundleSigningReport
    ) throws -> IPAArchiveSigningReport {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: archiveURL.path) else {
            throw RorkSignError.invalidArchive("IPA archive does not exist: \(archiveURL.path).")
        }

        let workspaceRoot = try workspaceRootDirectory(temporaryDirectory)
        let workspace = workspaceRoot
            .appendingPathComponent("rork-sign-ipa-\(UUID().uuidString)", isDirectory: true)
        let archiveRoot = workspace.appendingPathComponent("ArchiveRoot", isDirectory: true)
        defer {
            try? fileManager.removeItem(at: workspace)
        }

        do {
            try fileManager.createDirectory(at: archiveRoot, withIntermediateDirectories: true)
            try fileManager.unzipItem(at: archiveURL, to: archiveRoot)
        } catch {
            throw RorkSignError.invalidArchive("IPA archive could not be extracted: \(error.localizedDescription)")
        }

        let appURL = try payloadAppBundle(in: archiveRoot)
        let bundleReport = try signBundle(appURL)
        let report = try reportForArchive(
            outputURL: outputURL,
            archiveRoot: archiveRoot,
            appURL: appURL,
            bundleReport: bundleReport
        )

        do {
            if fileManager.fileExists(atPath: outputURL.path) {
                try fileManager.removeItem(at: outputURL)
            }
            try fileManager.createDirectory(
                at: outputURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try fileManager.zipItem(
                at: archiveRoot,
                to: outputURL,
                shouldKeepParent: false,
                compressionMethod: archiveCompressionMode.zipCompressionMethod
            )
        } catch {
            try? fileManager.removeItem(at: outputURL)
            throw RorkSignError.invalidArchive("Signed IPA archive could not be written: \(error.localizedDescription)")
        }

        return report
    }

    /// Returns the only top-level app bundle inside `Payload`.
    private static func payloadAppBundle(in archiveRoot: URL) throws -> URL {
        let payloadURL = archiveRoot.appendingPathComponent("Payload", isDirectory: true)
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: payloadURL.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            throw RorkSignError.invalidArchive("IPA archive is missing a Payload directory.")
        }

        let contents = try FileManager.default.contentsOfDirectory(
            at: payloadURL,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )
        let appBundles = contents
            .filter { url in
                url.pathExtension.lowercased() == "app"
                    && ((try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true)
            }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        guard let appURL = appBundles.first else {
            throw RorkSignError.invalidArchive("IPA archive has no app bundle in Payload.")
        }
        guard appBundles.count == 1 else {
            throw RorkSignError.invalidArchive("IPA archive contains multiple app bundles in Payload.")
        }
        return appURL
    }

    /// Converts a bundle report to archive-relative paths before cleanup.
    private static func reportForArchive(
        outputURL: URL,
        archiveRoot: URL,
        appURL: URL,
        bundleReport: BundleSigningReport
    ) throws -> IPAArchiveSigningReport {
        IPAArchiveSigningReport(
            outputArchiveURL: outputURL,
            appBundlePath: try relativePath(for: appURL, under: archiveRoot),
            sealedBundlePaths: try bundleReport.sealedBundles.map { try relativePath(for: $0, under: archiveRoot) },
            embeddedProvisioningProfilePaths: try bundleReport.embeddedProvisioningProfiles.map {
                try relativePath(for: $0, under: archiveRoot)
            },
            signedCodePaths: try bundleReport.signedCode.map { try relativePath(for: $0, under: archiveRoot) },
            cachedCodePaths: try bundleReport.cachedCode.map { try relativePath(for: $0, under: archiveRoot) }
        )
    }

    /// Produces an archive-root-relative path and rejects traversal escapes.
    private static func relativePath(for url: URL, under rootURL: URL) throws -> String {
        let rootPath = rootURL.standardizedFileURL.path
        let path = url.standardizedFileURL.path
        guard path.hasPrefix(rootPath + "/") else {
            throw RorkSignError.invalidArchive("Path escaped archive root: \(path).")
        }
        return String(path.dropFirst(rootPath.count + 1))
    }

    /// Returns a usable parent directory for temporary archive workspaces.
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
}

extension ArchiveCompressionMode {
    /// ZIPFoundation compression method for this public archive mode.
    var zipCompressionMethod: CompressionMethod {
        switch self {
        case .stored:
            return .none
        case .deflated:
            return .deflate
        }
    }
}
