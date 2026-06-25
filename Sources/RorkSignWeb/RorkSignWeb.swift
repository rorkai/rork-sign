import Foundation
import RorkSign

/// Signed IPA bytes and archive-relative details from the signing operation.
///
/// Browser clients cannot exchange filesystem URLs with Swift code reliably,
/// so this value carries the finished archive and the stable relative paths
/// from `IPAArchiveSigningReport`.
public struct SignedIPA: Equatable, Sendable {
    /// Complete signed IPA archive.
    public let data: Data

    /// App bundle path inside the IPA, usually `Payload/AppName.app`.
    public let appBundlePath: String

    /// Bundles whose `_CodeSignature/CodeResources` file was written.
    public let sealedBundlePaths: [String]

    /// Bundles whose `embedded.mobileprovision` file was written.
    public let embeddedProvisioningProfilePaths: [String]

    /// Mach-O files rewritten with embedded signatures.
    public let signedCodePaths: [String]

    /// Mach-O files restored from the signing cache.
    public let cachedCodePaths: [String]
}

public extension RorkSigner {
    /// Rewrites and signs an IPA with an identity-backed CMS signature.
    ///
    /// The implementation uses an isolated temporary workspace because the
    /// underlying bundle signer intentionally operates on a filesystem tree.
    /// The workspace is removed before this method returns, and only the signed
    /// archive bytes and archive-relative report paths cross the browser API.
    ///
    /// Stored entries remain the default because browser callers usually pass
    /// the result directly to InstallationProxy, where recompression adds CPU
    /// work without reducing the USB transfer meaningfully.
    ///
    /// This synchronous operation performs archive extraction, code signing,
    /// and repacking. Browser applications should invoke it from a Web Worker so
    /// signing does not block rendering or user input on the main thread.
    static func signIPA(
        _ ipaData: Data,
        using identity: SigningIdentity,
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode = .stored
    ) throws -> SignedIPA {
        try signArchiveData(
            ipaData,
            inputFileName: "Input.ipa"
        ) { inputURL, outputURL, workspace in
            try RorkSigner.signIPA(
                at: inputURL,
                outputURL: outputURL,
                identity: identity,
                options: options,
                archiveCompressionMode: archiveCompressionMode,
                temporaryDirectory: workspace
            )
        }
    }

    /// Packages and signs an app-bundle ZIP as an installable IPA.
    ///
    /// The input archive must contain exactly one top-level `.app` directory.
    /// RorkSign introduces the IPA's required `Payload` directory, preserves
    /// compatible ZIP metadata, signs the app, and returns the completed IPA
    /// without requiring callers to publish or construct an unsigned IPA first.
    ///
    /// This synchronous operation performs archive extraction, code signing,
    /// and repacking. Browser applications should invoke it from a Web Worker so
    /// signing does not block rendering or user input on the main thread.
    static func signAppArchive(
        _ archiveData: Data,
        using identity: SigningIdentity,
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode = .stored
    ) throws -> SignedIPA {
        try signArchiveData(
            archiveData,
            inputFileName: "Input.app.zip"
        ) { inputURL, outputURL, workspace in
            try RorkSigner.signAppArchive(
                at: inputURL,
                outputURL: outputURL,
                identity: identity,
                options: options,
                archiveCompressionMode: archiveCompressionMode,
                temporaryDirectory: workspace
            )
        }
    }

    /// Runs one data-based signing operation inside a scoped workspace.
    private static func signArchiveData(
        _ archiveData: Data,
        inputFileName: String,
        sign: (
            _ inputURL: URL,
            _ outputURL: URL,
            _ workspace: URL
        ) throws -> IPAArchiveSigningReport
    ) throws -> SignedIPA {
        let fileManager = FileManager.default
        let workspace = fileManager.temporaryDirectory
            .appendingPathComponent(
                "rork-sign-web-\(UUID().uuidString)",
                isDirectory: true
            )
        let inputURL = workspace.appendingPathComponent(inputFileName)
        let outputURL = workspace.appendingPathComponent("Signed.ipa")
        defer {
            try? fileManager.removeItem(at: workspace)
        }

        try fileManager.createDirectory(
            at: workspace,
            withIntermediateDirectories: true
        )
        try archiveData.write(to: inputURL)
        let report = try sign(inputURL, outputURL, workspace)

        return SignedIPA(
            data: try Data(contentsOf: outputURL),
            appBundlePath: report.appBundlePath,
            sealedBundlePaths: report.sealedBundlePaths,
            embeddedProvisioningProfilePaths:
                report.embeddedProvisioningProfilePaths,
            signedCodePaths: report.signedCodePaths,
            cachedCodePaths: report.cachedCodePaths
        )
    }
}
