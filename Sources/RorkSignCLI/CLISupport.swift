import ArgumentParser
import Foundation
import RorkSign

/// Shared input parsing used across `rorksign` subcommands.
///
/// These mirror the small file-reading helpers the CLI relied on before the
/// migration to swift-argument-parser, keeping the library API as the only
/// real product.
enum CLISupport {
    /// Reads an optional entitlements XML path, defaulting to empty when the
    /// trailing positional argument is omitted.
    static func readEntitlements(path: String?) throws -> String {
        guard let path else {
            return ""
        }
        return try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
    }

    /// Splits a comma-separated app-group list, trimming blanks.
    static func appGroupIdentifiers(_ value: String?) -> [String] {
        guard let value else {
            return []
        }
        return value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    /// Reads a JSON object mapping final bundle identifiers to provisioning
    /// profile paths. Relative paths are resolved from the JSON file directory.
    static func readProvisioningProfileMap(path: String) throws -> [String: Data] {
        let mapURL = URL(fileURLWithPath: path)
        let rawMap = try Data(contentsOf: mapURL)
        let parsed = try JSONSerialization.jsonObject(with: rawMap, options: [])
        guard let pathsByBundleIdentifier = parsed as? [String: String] else {
            throw ValidationError(
                "Provisioning profile map must be a JSON object from bundle identifier to profile path."
            )
        }
        guard !pathsByBundleIdentifier.isEmpty else {
            throw ValidationError("Provisioning profile map must not be empty.")
        }

        let baseURL = mapURL.deletingLastPathComponent()
        var profilesByBundleIdentifier: [String: Data] = [:]
        for (rawBundleIdentifier, rawProfilePath) in pathsByBundleIdentifier {
            let bundleIdentifier = rawBundleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !bundleIdentifier.isEmpty else {
                throw ValidationError("Provisioning profile map contains an empty bundle identifier.")
            }

            let profilePath = rawProfilePath.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !profilePath.isEmpty else {
                throw ValidationError("Provisioning profile map contains an empty profile path for \(bundleIdentifier).")
            }

            let profileURL = URL(
                fileURLWithPath: profilePath,
                relativeTo: baseURL
            ).standardizedFileURL
            profilesByBundleIdentifier[bundleIdentifier] = try Data(contentsOf: profileURL)
        }

        return profilesByBundleIdentifier
    }

    /// An IPA archive and the temporary workspace that owns it, when present.
    struct PreparedIPAInput {
        /// The archive passed to the signing pipeline.
        let archiveURL: URL

        /// The temporary directory to remove after signing a directory input.
        let workspaceURL: URL?

        /// Removes the temporary workspace without affecting file inputs.
        ///
        /// Cleanup is best-effort because it must not replace the signing
        /// command's primary result.
        func removeWorkspace() {
            guard let workspaceURL else {
                return
            }
            try? FileManager.default.removeItem(at: workspaceURL)
        }
    }

    /// Prepares an IPA archive for the signing pipeline.
    ///
    /// Directory inputs are serialized through the archive implementation so
    /// every supported input shape follows the same signing path.
    static func prepareIPAInput(at inputURL: URL) throws -> PreparedIPAInput {
        var isDirectory: ObjCBool = false
        guard
            FileManager.default.fileExists(
                atPath: inputURL.path,
                isDirectory: &isDirectory
            ),
            isDirectory.boolValue
        else {
            return PreparedIPAInput(
                archiveURL: inputURL,
                workspaceURL: nil
            )
        }

        let fileManager = FileManager.default
        let workspaceURL = fileManager.temporaryDirectory
            .appendingPathComponent(
                "rorksign-input-\(UUID().uuidString)",
                isDirectory: true
            )
        let archiveURL = workspaceURL.appendingPathComponent("Input.ipa")
        do {
            try fileManager.createDirectory(
                at: workspaceURL,
                withIntermediateDirectories: true
            )
            let archiveRootURL: URL
            if inputURL.pathExtension.lowercased() == "app" {
                archiveRootURL = workspaceURL.appendingPathComponent(
                    "ArchiveRoot",
                    isDirectory: true
                )
                let payloadURL = archiveRootURL.appendingPathComponent(
                    "Payload",
                    isDirectory: true
                )
                try fileManager.createDirectory(
                    at: payloadURL,
                    withIntermediateDirectories: true
                )
                try fileManager.copyItem(
                    at: inputURL,
                    to: payloadURL.appendingPathComponent(
                        inputURL.lastPathComponent,
                        isDirectory: true
                    )
                )
            } else {
                archiveRootURL = inputURL
            }
            try IPAArchive.write(
                contentsOf: archiveRootURL,
                to: archiveURL,
                compressionMode: .stored
            )
            return PreparedIPAInput(
                archiveURL: archiveURL,
                workspaceURL: workspaceURL
            )
        } catch {
            try? fileManager.removeItem(at: workspaceURL)
            throw error
        }
    }

    /// Writes sensitive command output through the platform's protected atomic
    /// file path.
    static func writeAtomically(_ data: Data, to outputURL: URL) throws {
        try SecureFileWriter.writeAtomically(data, to: outputURL)
    }

    /// Reads a password from one direct value or one protected file.
    ///
    /// File contents are returned verbatim, including any trailing newline. The
    /// caller remains responsible for restricting access to the password file.
    ///
    /// - Parameters:
    ///   - value: Password supplied directly by the caller.
    ///   - filePath: Optional path containing the password bytes as UTF-8.
    ///   - optionName: User-facing option group named in validation errors.
    /// - Returns: The direct value or complete file contents.
    /// - Throws: `ValidationError` when both sources are present, or a file-read
    ///   error when `filePath` cannot be decoded as UTF-8.
    static func readPassword(
        value: String,
        filePath: String?,
        optionName: String
    ) throws -> String {
        if !value.isEmpty, filePath != nil {
            throw ValidationError(
                "\(optionName) accepts either a direct password or a password file, not both."
            )
        }
        guard let filePath else {
            return value
        }
        return try String(
            contentsOf: URL(fileURLWithPath: filePath),
            encoding: .utf8
        )
    }

    /// Loads a PEM certificate/private-key pair into a signing identity.
    static func readIdentity(
        certificatePath: String,
        privateKeyPath: String,
        password: String = ""
    ) throws -> SigningIdentity {
        try readIdentity(certificatePath: certificatePath, credentialPath: privateKeyPath, password: password)
    }

    /// Loads a certificate plus signing credential into a signing identity.
    ///
    /// ZSign-style CLI inputs can mix PEM, DER, and PKCS#12 files
    /// independently, so this helper reads bytes and leaves all normalization
    /// to the library.
    static func readIdentity(
        certificatePath: String,
        credentialPath: String,
        password: String = ""
    ) throws -> SigningIdentity {
        return try SigningIdentity(
            certificateData: Data(contentsOf: URL(fileURLWithPath: certificatePath)),
            privateKeyData: Data(contentsOf: URL(fileURLWithPath: credentialPath)),
            privateKeyPassword: password
        )
    }

    /// Loads a PEM certificate/private-key pair into a signing identity.
    static func readPEMIdentity(
        certificatePath: String,
        privateKeyPath: String,
        password: String = ""
    ) throws -> SigningIdentity {
        try SigningIdentity(
            certificatePEM: String(contentsOf: URL(fileURLWithPath: certificatePath), encoding: .utf8),
            privateKeyPEM: String(contentsOf: URL(fileURLWithPath: privateKeyPath), encoding: .utf8),
            privateKeyPassword: password
        )
    }

    /// Loads a PKCS#12 bundle into a signing identity.
    static func readPKCS12Identity(pkcs12Path: String, password: String) throws -> SigningIdentity {
        try SigningIdentity(
            pkcs12Data: Data(contentsOf: URL(fileURLWithPath: pkcs12Path)),
            password: password
        )
    }

    /// Loads a signing identity from a provisioning profile path plus credential.
    static func readProfileIdentity(
        profilePath: String,
        credentialPath: String,
        password: String
    ) throws -> SigningIdentity {
        try readProfileIdentity(
            profileData: Data(contentsOf: URL(fileURLWithPath: profilePath)),
            credentialPath: credentialPath,
            password: password
        )
    }

    /// Loads a signing identity from already-read profile bytes plus credential.
    static func readProfileIdentity(
        profileData: Data,
        credentialPath: String,
        password: String
    ) throws -> SigningIdentity {
        try SigningIdentity(
            provisioningProfileData: profileData,
            credentialData: Data(contentsOf: URL(fileURLWithPath: credentialPath)),
            password: password
        )
    }

    /// Reads `CFBundleIdentifier` from a bundle's `Info.plist`.
    static func readBundleIdentifier(at bundleURL: URL) throws -> String {
        let infoURL = bundleURL.appendingPathComponent("Info.plist")
        let data = try Data(contentsOf: infoURL)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = plist as? [String: Any],
              let identifier = dictionary["CFBundleIdentifier"] as? String
        else {
            throw RorkSignError.invalidBundle("Bundle Info.plist has no CFBundleIdentifier: \(infoURL.path)")
        }
        let trimmed = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw RorkSignError.invalidBundle("Bundle Info.plist has an empty CFBundleIdentifier: \(infoURL.path)")
        }
        return trimmed
    }

    /// Derives an explicit bundle identifier from a provisioning profile.
    static func bundleIdentifier(fromProvisioningProfileData data: Data) throws -> String {
        let profile = try RorkSigner.decodeProvisioningProfile(data)
        guard let applicationIdentifier = profile.applicationIdentifier else {
            throw RorkSignError.invalidProvisioningProfile(
                "Provisioning profile has no application-identifier entitlement."
            )
        }

        let prefix = profile.teamIdentifier + "."
        guard applicationIdentifier.hasPrefix(prefix) else {
            throw RorkSignError.invalidProvisioningProfile(
                "Provisioning profile application identifier does not start with the team identifier."
            )
        }

        let bundleIdentifier = String(applicationIdentifier.dropFirst(prefix.count))
        guard !bundleIdentifier.isEmpty, bundleIdentifier != "*" else {
            throw RorkSignError.invalidProvisioningProfile(
                "Provisioning profile must use an explicit application identifier for IPA signing."
            )
        }
        return bundleIdentifier
    }

    /// Formats a CodeResources verification report as stable `key=value` fields.
    ///
    /// Both the focused `verify-resources` command and the ZSign-compatible `-C`
    /// flow use this representation so scripts can consume the same resource
    /// seal status regardless of the entry point.
    static func codeResourcesFields(_ report: CodeResourcesVerificationReport) -> String {
        [
            "resourcesVerified=\(report.isValid)",
            "sealed=\(report.sealedResourceCount)",
            "checked=\(report.verifiedResourceCount)",
            "missing=\(report.missingResources.count)",
            "mismatched=\(report.mismatchedResources.count)",
            "unsealed=\(report.unsealedResources.count)",
        ].joined(separator: " ")
    }

    /// Formats a recursive bundle CodeResources report with its relative path.
    static func codeResourcesFields(_ report: BundleCodeResourcesVerificationReport) -> String {
        "resourceBundle=\(report.relativeBundlePath) \(codeResourcesFields(report.codeResources))"
    }
}

/// Parses a positional path argument into a file URL.
///
/// `@Argument(transform:)` requires a throwing closure; `URL(fileURLWithPath:)`
/// never throws, so this wrapper exists purely to share the conversion.
func fileURL(_ path: String) -> URL {
    URL(fileURLWithPath: path)
}
