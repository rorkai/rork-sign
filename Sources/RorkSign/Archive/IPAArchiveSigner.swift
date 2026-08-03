import Foundation

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

    /// Rewrites and ad-hoc signs the IPA's app bundle as an installable app.
    static func signAppAdHoc(
        archiveURL: URL,
        outputURL: URL,
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode,
        temporaryDirectory: URL?
    ) throws -> IPAArchiveSigningReport {
        try signArchive(
            archiveURL: archiveURL,
            outputURL: outputURL,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        ) { appURL in
            try AppBundleSigner.signAdHoc(bundleURL: appURL, options: options)
        }
    }

    /// Rewrites and CMS-signs the IPA's app bundle as an installable app.
    static func signAppWithIdentity(
        archiveURL: URL,
        outputURL: URL,
        identity: SigningIdentity,
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode,
        temporaryDirectory: URL?
    ) throws -> IPAArchiveSigningReport {
        try signArchive(
            archiveURL: archiveURL,
            outputURL: outputURL,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        ) { appURL in
            try AppBundleSigner.signWithIdentity(
                bundleURL: appURL,
                identity: identity,
                options: options
            )
        }
    }

    /// Packages and CMS-signs a root-level app-bundle archive as an IPA.
    static func signAppArchiveWithIdentity(
        archiveURL: URL,
        outputURL: URL,
        identity: SigningIdentity,
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode,
        temporaryDirectory: URL?
    ) throws -> IPAArchiveSigningReport {
        try IPAArchive.withExtractedAppArchive(
            from: archiveURL,
            temporaryDirectory: temporaryDirectory
        ) { payload in
            try signExtractedPayload(
                payload,
                outputURL: outputURL,
                archiveCompressionMode: archiveCompressionMode
            ) { appURL in
                try AppBundleSigner.signWithIdentity(
                    bundleURL: appURL,
                    identity: identity,
                    options: options
                )
            }
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
        try IPAArchive.withExtractedPayloadApp(
            from: archiveURL,
            temporaryDirectory: temporaryDirectory
        ) { payload in
            try signExtractedPayload(
                payload,
                outputURL: outputURL,
                archiveCompressionMode: archiveCompressionMode,
                signBundle: signBundle
            )
        }
    }

    /// Signs one extracted app and serializes its complete IPA workspace.
    private static func signExtractedPayload(
        _ payload: IPAArchive.PayloadExtraction,
        outputURL: URL,
        archiveCompressionMode: ArchiveCompressionMode,
        signBundle: (URL) throws -> BundleSigningReport
    ) throws -> IPAArchiveSigningReport {
        let bundleReport = try signBundle(payload.appBundleURL)
        let report = try reportForArchive(
            outputURL: outputURL,
            archiveRoot: payload.archiveRootURL,
            appURL: payload.appBundleURL,
            bundleReport: bundleReport
        )

        do {
            try IPAArchive.write(
                contentsOf: payload.archiveRootURL,
                to: outputURL,
                compressionMode: archiveCompressionMode,
                preservingMetadataFrom: payload.archiveMetadata
            )
        } catch {
            throw RorkSignError.invalidArchive(
                "Signed IPA archive could not be written: \(error.localizedDescription)"
            )
        }
        return report
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
        let rootPath = normalizedFileSystemPath(
            rootURL.standardizedFileURL.path
        )
        let path = normalizedFileSystemPath(
            url.standardizedFileURL.path
        )
        guard path.hasPrefix(rootPath + "/") else {
            throw RorkSignError.invalidArchive("Path escaped archive root: \(path).")
        }
        return String(path.dropFirst(rootPath.count + 1))
    }

}
