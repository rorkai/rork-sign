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
    static func signIPA(
        _ ipaData: Data,
        using identity: SigningIdentity,
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode = .stored
    ) throws -> SignedIPA {
        let fileManager = FileManager.default
        let workspace = fileManager.temporaryDirectory
            .appendingPathComponent(
                "rork-sign-web-\(UUID().uuidString)",
                isDirectory: true
            )
        let inputURL = workspace.appendingPathComponent("Input.ipa")
        let outputURL = workspace.appendingPathComponent("Signed.ipa")
        defer {
            try? fileManager.removeItem(at: workspace)
        }

        try fileManager.createDirectory(
            at: workspace,
            withIntermediateDirectories: true
        )
        try ipaData.write(to: inputURL)
        let report = try RorkSigner.signIPA(
            at: inputURL,
            outputURL: outputURL,
            identity: identity,
            options: options,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: workspace
        )

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
