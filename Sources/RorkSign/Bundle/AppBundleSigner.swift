import Foundation

/// Configuration for rewriting and signing a copied app bundle.
///
/// App signing is stricter than generic bundle signing because the app is being
/// re-homed under a new bundle identifier. The signer rewrites
/// `CFBundleIdentifier` values first, derives entitlements from the selected
/// provisioning profiles, embeds those profiles, seals resources, and finally
/// signs the executables.
public struct AppSigningOptions: Equatable {
    /// Replacement bundle identifier for the root app.
    public var bundleIdentifier: String

    /// Provisioning profile for the root app and fallback profile for nested
    /// provisioned bundles that do not have an exact rewritten-identifier match.
    public var rootProvisioningProfile: Data?

    /// Fallback provisioning profile for embedded Apple Watch apps.
    ///
    /// Some signing flows receive one Watch profile that authorizes every
    /// embedded Watch app after identifier rebasing. Exact entries in
    /// `provisioningProfilesByBundleIdentifier` still win; this profile is used
    /// only for Watch bundles without an exact profile, before falling back to
    /// the root app profile.
    public var watchProvisioningProfile: Data?

    /// Provisioning profiles keyed by rewritten `CFBundleIdentifier`.
    ///
    /// App extensions and embedded apps need their own profile when the root app
    /// profile does not authorize their rewritten identifier. Keys must use the
    /// post-rewrite identifier, matching the identifier that will appear in the
    /// nested bundle's `Info.plist`.
    public var provisioningProfilesByBundleIdentifier: [String: Data]

    /// App-group identifiers to force into non-Watch app entitlements.
    public var appGroupIdentifiers: [String]

    /// Explicit entitlement plist XML for the rewritten root executable.
    ///
    /// When this is non-empty it wins over profile-derived root entitlements,
    /// matching the compatibility CLI's `-e/--entitlements` behavior for
    /// callers that need to supply a complete entitlement plist. Nested app and
    /// extension entitlements are still derived from their selected
    /// provisioning profiles so identifier rebasing and associated-application
    /// keys remain coherent.
    public var rootEntitlementsXML: String

    /// Bundle-local entitlements plist filename used when an executable has no
    /// embedded entitlement slot.
    ///
    /// The file is treated as the executable's original entitlement request
    /// before the selected provisioning profile constrains the final values.
    /// Leave this nil when unsigned artifacts do not carry this resource. When
    /// set, the value must be a plain filename in each bundle directory, such
    /// as `Entitlements.plist`.
    public var entitlementsResourceName: String?

    /// Replacement display name for the root app.
    ///
    /// When set, the signer writes both `CFBundleName` and
    /// `CFBundleDisplayName` in the root `Info.plist` and in localized
    /// `*.lproj/InfoPlist.strings` files that can be parsed as property lists.
    public var displayName: String?

    /// Replacement version for the root app.
    ///
    /// The signer writes the same value to both `CFBundleVersion` and
    /// `CFBundleShortVersionString`.
    public var bundleVersion: String?

    /// Replacement `MinimumOSVersion` for the root app.
    public var minimumOSVersion: String?

    /// Enables iOS Files app document browser integration in the root app.
    ///
    /// This writes `UISupportsDocumentBrowser` and `UIFileSharingEnabled` as
    /// `true` before resources are sealed.
    public var enableDocuments: Bool

    /// Removes root `PlugIns` and `Extensions` directories before signing.
    public var removeExtensions: Bool

    /// Specific embedded extensions to delete before signing, by `.appex`
    /// directory name (for example `Share.appex`).
    ///
    /// Use this to drop an individual extension the signing identity cannot
    /// provision — such as a NetworkExtension on a free Personal Team — while
    /// keeping the rest of `PlugIns`/`Extensions` (and their profiles) intact.
    /// Names are matched against direct children of the root app's `PlugIns` and
    /// `Extensions` directories. This is ignored when `removeExtensions` is
    /// `true`, which already removes every extension.
    public var extensionsToRemove: [String]

    /// Removes embedded Watch app directories before signing.
    public var removeWatchApps: Bool

    /// Removes `UISupportedDevices` from the root app's `Info.plist`.
    public var removeUISupportedDevices: Bool

    /// Files written relative to the root app bundle before signing begins.
    ///
    /// Use this for caller-owned resources that must be part of the signed app,
    /// such as runtime credentials or configuration files. Parent directories
    /// are created as needed, and an existing file at the same relative path is
    /// replaced before resources are sealed. Paths must remain relative to the
    /// root app bundle, cannot contain empty, `.` or `..` components, and cannot
    /// replace bundle metadata, provisioning profiles, signatures, or Mach-O
    /// files owned by the signing process.
    public var additionalBundleFiles: [String: Data]

    /// Whether selected provisioning profiles are embedded before resource sealing.
    ///
    /// This defaults to `true` because installable app outputs normally need an
    /// embedded provisioning profile. Compatibility workflows can disable it to
    /// mirror `--rm_provision`, in which case profile-derived entitlements are
    /// still used for signing but no `embedded.mobileprovision` file is sealed
    /// into the bundle. Existing embedded profiles are removed before the
    /// resource seal is generated.
    public var embedProvisioningProfiles: Bool

    /// Dylib files copied into the root app and loaded by the root executable.
    public var dylibInjections: [BundleDylibInjection]

    /// Dylib load commands removed from the root executable before signing.
    public var dylibLoadCommandsToRemove: [String]

    /// CodeDirectory digest layout used for every Mach-O in the rewritten app.
    ///
    /// App signing defaults to `.sha256Only` so independently installable
    /// apps avoid a legacy SHA-1 cdhash. Override this only when a caller needs
    /// the broader SHA-1-primary compatibility shape for a fixture or
    /// diagnostic artifact.
    public var codeDirectoryHashingMode: CodeDirectoryHashingMode

    /// Optional persistent cache for the final signed Mach-O outputs.
    public var signingCache: SigningCacheOptions?

    /// Optional logger-backed diagnostics for the rewrite and signing pass.
    ///
    /// Diagnostics are forwarded to the underlying bundle signer after app
    /// metadata, profiles, and entitlements have been prepared.
    public var diagnostics: SigningDiagnostics

    /// Creates app signing options.
    public init(
        bundleIdentifier: String,
        rootProvisioningProfile: Data? = nil,
        watchProvisioningProfile: Data? = nil,
        provisioningProfilesByBundleIdentifier: [String: Data] = [:],
        appGroupIdentifiers: [String] = [],
        rootEntitlementsXML: String = "",
        entitlementsResourceName: String? = nil,
        displayName: String? = nil,
        bundleVersion: String? = nil,
        minimumOSVersion: String? = nil,
        enableDocuments: Bool = false,
        removeExtensions: Bool = false,
        extensionsToRemove: [String] = [],
        removeWatchApps: Bool = false,
        removeUISupportedDevices: Bool = false,
        additionalBundleFiles: [String: Data] = [:],
        embedProvisioningProfiles: Bool = true,
        dylibInjections: [BundleDylibInjection] = [],
        dylibLoadCommandsToRemove: [String] = [],
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .sha256Only,
        signingCache: SigningCacheOptions? = nil,
        diagnostics: SigningDiagnostics = .disabled
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.rootProvisioningProfile = rootProvisioningProfile
        self.watchProvisioningProfile = watchProvisioningProfile
        self.provisioningProfilesByBundleIdentifier = provisioningProfilesByBundleIdentifier
        self.appGroupIdentifiers = appGroupIdentifiers
        self.rootEntitlementsXML = rootEntitlementsXML
        self.entitlementsResourceName = entitlementsResourceName
        self.displayName = displayName
        self.bundleVersion = bundleVersion
        self.minimumOSVersion = minimumOSVersion
        self.enableDocuments = enableDocuments
        self.removeExtensions = removeExtensions
        self.extensionsToRemove = extensionsToRemove
        self.removeWatchApps = removeWatchApps
        self.removeUISupportedDevices = removeUISupportedDevices
        self.additionalBundleFiles = additionalBundleFiles
        self.embedProvisioningProfiles = embedProvisioningProfiles
        self.dylibInjections = dylibInjections
        self.dylibLoadCommandsToRemove = dylibLoadCommandsToRemove
        self.codeDirectoryHashingMode = codeDirectoryHashingMode
        self.signingCache = signingCache
        self.diagnostics = diagnostics
    }

    /// Compares semantic signing inputs while ignoring the diagnostics sink.
    public static func == (
        lhs: AppSigningOptions,
        rhs: AppSigningOptions
    ) -> Bool {
        lhs.bundleIdentifier == rhs.bundleIdentifier
            && lhs.rootProvisioningProfile == rhs.rootProvisioningProfile
            && lhs.watchProvisioningProfile == rhs.watchProvisioningProfile
            && lhs.provisioningProfilesByBundleIdentifier == rhs.provisioningProfilesByBundleIdentifier
            && lhs.appGroupIdentifiers == rhs.appGroupIdentifiers
            && lhs.rootEntitlementsXML == rhs.rootEntitlementsXML
            && lhs.entitlementsResourceName == rhs.entitlementsResourceName
            && lhs.displayName == rhs.displayName
            && lhs.bundleVersion == rhs.bundleVersion
            && lhs.minimumOSVersion == rhs.minimumOSVersion
            && lhs.enableDocuments == rhs.enableDocuments
            && lhs.removeExtensions == rhs.removeExtensions
            && lhs.extensionsToRemove == rhs.extensionsToRemove
            && lhs.removeWatchApps == rhs.removeWatchApps
            && lhs.removeUISupportedDevices == rhs.removeUISupportedDevices
            && lhs.additionalBundleFiles == rhs.additionalBundleFiles
            && lhs.embedProvisioningProfiles == rhs.embedProvisioningProfiles
            && lhs.dylibInjections == rhs.dylibInjections
            && lhs.dylibLoadCommandsToRemove == rhs.dylibLoadCommandsToRemove
            && lhs.codeDirectoryHashingMode == rhs.codeDirectoryHashingMode
            && lhs.signingCache == rhs.signingCache
    }
}

/// Rewrites bundle identity and delegates the final inside-out signing pass.
enum AppBundleSigner {
    /// Rewrites `bundleURL` and applies ad-hoc signatures.
    static func signAdHoc(
        bundleURL: URL,
        options: AppSigningOptions
    ) throws -> BundleSigningReport {
        let profiles = try provisioningAssets(options: options, identity: nil)
        let bundleSigningOptions = try prepareBundleSigningOptions(
            bundleURL: bundleURL,
            options: options,
            profiles: profiles
        )
        return try BundleSigner.signAdHoc(bundleURL: bundleURL, options: bundleSigningOptions)
    }

    /// Rewrites `bundleURL` and applies identity-backed CMS signatures.
    static func signWithIdentity(
        bundleURL: URL,
        identity: SigningIdentity,
        options: AppSigningOptions
    ) throws -> BundleSigningReport {
        let profiles = try provisioningAssets(options: options, identity: identity)
        let effectiveIdentity = try profiles.signingIdentity(for: identity)
        let bundleSigningOptions = try prepareBundleSigningOptions(
            bundleURL: bundleURL,
            options: options,
            profiles: profiles
        )
        return try BundleSigner.signWithIdentity(
            bundleURL: bundleURL,
            identity: effectiveIdentity,
            options: bundleSigningOptions
        )
    }

    /// Builds and validates provisioning inputs before bundle mutation.
    ///
    /// Team and certificate mismatches must fail before identifiers, resources,
    /// or caller-owned files are rewritten.
    private static func provisioningAssets(
        options: AppSigningOptions,
        identity: SigningIdentity?
    ) throws -> AppProvisioningAssets {
        try AppProvisioningAssets(
            rootProvisioningProfile: options.rootProvisioningProfile,
            watchProvisioningProfile: options.watchProvisioningProfile,
            provisioningProfilesByBundleIdentifier: options.provisioningProfilesByBundleIdentifier,
            identity: identity
        )
    }

    /// Performs the mutation-only phase and returns assets for `BundleSigner`.
    private static func prepareBundleSigningOptions(
        bundleURL: URL,
        options: AppSigningOptions,
        profiles: AppProvisioningAssets
    ) throws -> BundleSigningOptions {
        let replacementIdentifier = try BundleIdentifier.normalize(
            options.bundleIdentifier
        )
        try AdditionalBundleFileWriter.write(
            options.additionalBundleFiles,
            to: bundleURL
        )
        let rewrittenBundles = try AppBundleIdentityRewriter.rewrite(
            rootBundleURL: bundleURL,
            replacementBundleIdentifier: replacementIdentifier,
            options: options
        )

        var entitlementsByIdentifier: [String: String] = [:]
        var profilesByIdentifier: [String: Data] = [:]
        let appGroups = AppGroupIdentifiers.normalize(options.appGroupIdentifiers)
        let rootEntitlementsOverride = options.rootEntitlementsXML
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .isEmpty ? nil : options.rootEntitlementsXML

        for bundle in rewrittenBundles where bundle.isProvisionedBundle {
            guard let asset = try profiles.asset(
                for: bundle.rewrittenIdentifier,
                isWatchBundle: bundle.isWatchBundle
            ) else {
                continue
            }

            profilesByIdentifier[bundle.rewrittenIdentifier] = asset.data
            if bundle.rewrittenIdentifier == replacementIdentifier,
               let rootEntitlementsOverride {
                entitlementsByIdentifier[bundle.rewrittenIdentifier] = rootEntitlementsOverride
            } else {
                entitlementsByIdentifier[bundle.rewrittenIdentifier] = try BundleEntitlements.expand(
                    profile: asset.profile,
                    bundleIdentifier: bundle.rewrittenIdentifier,
                    originalEntitlementsXML: bundle.originalEntitlementsXML,
                    associatedBundleIdentifier: bundle.associatedBundleIdentifier,
                    appGroupIdentifiers: bundle.isWatchBundle ? [] : appGroups
                )
            }
        }

        if let rootEntitlementsOverride {
            entitlementsByIdentifier[replacementIdentifier] = rootEntitlementsOverride
        }

        return BundleSigningOptions(
            defaultEntitlementsXML: entitlementsByIdentifier[replacementIdentifier] ?? "",
            rootProvisioningProfile: profilesByIdentifier[replacementIdentifier],
            entitlementsByBundleIdentifier: entitlementsByIdentifier,
            provisioningProfilesByBundleIdentifier: profilesByIdentifier,
            embedProvisioningProfiles: options.embedProvisioningProfiles,
            codeDirectoryHashingMode: options.codeDirectoryHashingMode,
            dylibInjections: options.dylibInjections,
            dylibLoadCommandsToRemove: options.dylibLoadCommandsToRemove,
            signingCache: options.signingCache,
            diagnostics: options.diagnostics
        )
    }
}

/// Writes caller-owned resources before app metadata and signatures are derived.
///
/// Every destination is validated before the first write so a malformed path
/// cannot leave an otherwise valid app bundle partially updated.
private enum AdditionalBundleFileWriter {
    /// One validated write that can be applied after the complete set is safe.
    private struct PendingFile {
        let relativePath: String
        let components: [String]
        let url: URL
        let data: Data
    }

    /// Validates and writes files relative to `rootBundleURL`.
    static func write(
        _ filesByRelativePath: [String: Data],
        to rootBundleURL: URL
    ) throws {
        let files = try filesByRelativePath
            .sorted { $0.key < $1.key }
            .map { relativePath, data in
                try pendingFile(
                    at: relativePath,
                    data: data,
                    in: rootBundleURL
                )
            }
        try validatePathConflicts(in: files)
        for file in files {
            try validateExistingPath(
                for: file,
                in: rootBundleURL
            )
        }
        try validateCallerOwnedDestinations(in: files)

        for file in files {
            try FileManager.default.createDirectory(
                at: file.url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try file.data.writeReplacingItem(at: file.url)
        }
    }

    /// Prevents resource injection from replacing inputs and outputs controlled
    /// by bundle signing.
    private static func validateCallerOwnedDestinations(
        in files: [PendingFile]
    ) throws {
        for file in files {
            let normalizedComponents = file.components.map {
                $0.lowercased()
            }
            let finalComponent = normalizedComponents.last
            if normalizedComponents.contains("_codesignature")
                || finalComponent == "info.plist"
                || finalComponent == "embedded.mobileprovision"
            {
                throw signerOwnedPathError(file.relativePath)
            }
            if FileManager.default.fileExists(atPath: file.url.path),
               try MachOFile.isMachO(at: file.url)
            {
                throw signerOwnedPathError(file.relativePath)
            }
        }
    }

    /// Resolves one lexical path before inspecting the existing filesystem.
    private static func pendingFile(
        at relativePath: String,
        data: Data,
        in rootBundleURL: URL
    ) throws -> PendingFile {
        let components = relativePath.split(
            separator: "/",
            omittingEmptySubsequences: false
        ).map(String.init)
        guard
            !relativePath.isEmpty,
            !relativePath.hasPrefix("/"),
            !relativePath.contains("\\"),
            !relativePath.contains("\0"),
            components.allSatisfy({
                !$0.isEmpty && $0 != "." && $0 != ".."
            })
        else {
            throw invalidPath(relativePath)
        }

        let destinationURL = components.reduce(rootBundleURL) {
            $0.appendingPathComponent($1)
        }
        let rootPath = normalizedFileSystemPath(
            rootBundleURL.standardizedFileURL.path
        )
        let destinationPath = normalizedFileSystemPath(
            destinationURL.standardizedFileURL.path
        )
        guard destinationPath.hasPrefix(rootPath + "/") else {
            throw invalidPath(relativePath)
        }
        return PendingFile(
            relativePath: relativePath,
            components: components,
            url: destinationURL,
            data: data
        )
    }

    /// Rejects a requested file that is also an ancestor of another write.
    ///
    /// Without this preflight, dictionary iteration order could create a file
    /// where another entry needs a directory and leave the bundle partially
    /// updated before the conflict surfaces.
    private static func validatePathConflicts(
        in files: [PendingFile]
    ) throws {
        var requestedPaths: Set<String> = []
        for file in files {
            let path = pathForComparison(file.components)
            guard requestedPaths.insert(path).inserted else {
                throw invalidPath(file.relativePath)
            }
        }

        for file in files {
            var ancestorComponents: [String] = []
            for component in file.components.dropLast() {
                ancestorComponents.append(component)
                let ancestorPath = pathForComparison(ancestorComponents)
                guard !requestedPaths.contains(ancestorPath) else {
                    throw invalidPath(file.relativePath)
                }
            }
        }
    }

    /// Normalizes requested paths before comparing them as one write set.
    ///
    /// App bundles are commonly prepared on case-insensitive filesystems, so
    /// allowing case-only differences would make preflight behavior depend on
    /// the host that performs signing.
    private static func pathForComparison(
        _ components: [String]
    ) -> String {
        components.map { $0.lowercased() }.joined(separator: "/")
    }

    /// Rejects links and non-directory ancestors before any write begins.
    ///
    /// Lexical `..` validation is insufficient when an existing bundle entry
    /// is a symbolic link. Inspecting every existing component prevents a
    /// caller-owned resource from escaping the root through that link.
    private static func validateExistingPath(
        for file: PendingFile,
        in rootBundleURL: URL
    ) throws {
        let fileManager = FileManager.default
        var candidateURL = rootBundleURL

        for (index, component) in file.components.enumerated() {
            candidateURL.appendPathComponent(component)
            if (try? fileManager.destinationOfSymbolicLink(
                atPath: candidateURL.path
            )) != nil {
                throw invalidPath(file.relativePath)
            }

            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(
                atPath: candidateURL.path,
                isDirectory: &isDirectory
            ) else {
                continue
            }

            let kind: FileSystemEntry.Kind
            do {
                kind = try FileManager.default.entry(at: candidateURL).kind
            } catch {
                throw invalidPath(file.relativePath)
            }

            let isFinalComponent = index == file.components.count - 1
            if isFinalComponent {
                guard kind == .regularFile else {
                    throw invalidPath(file.relativePath)
                }
            } else {
                guard kind == .directory else {
                    throw invalidPath(file.relativePath)
                }
            }
        }
    }

    /// Produces one stable public error for every unsafe relative-path shape.
    private static func invalidPath(_ relativePath: String) -> RorkSignError {
        .invalidBundle(
            "Additional bundle file path must remain inside the root app bundle: \(relativePath)."
        )
    }

    /// Produces one stable public error for attempts to replace signing inputs.
    private static func signerOwnedPathError(
        _ relativePath: String
    ) -> RorkSignError {
        .invalidBundle(
            "Additional bundle file path is owned by the signing process: \(relativePath)."
        )
    }
}

/// Read-only app bundle inspection entry point.
enum AppBundleInspector {
    /// Returns the identifier rewrite plan for `rootBundleURL` without changing files.
    static func inspect(
        rootBundleURL: URL,
        replacementBundleIdentifier: String
    ) throws -> AppInspectionReport {
        try AppBundleIdentityRewriter.inspect(
            rootBundleURL: rootBundleURL,
            replacementBundleIdentifier: replacementBundleIdentifier
        )
    }
}

/// One provisioned bundle after identifier rewriting.
private struct AppBundleDescriptor: Equatable {
    let url: URL
    let originalIdentifier: String
    let rewrittenIdentifier: String
    let associatedBundleIdentifier: String?
    let originalEntitlementsXML: String
    let isProvisionedBundle: Bool
    let isWatchBundle: Bool
}

/// Rewrites app and extension identifiers before resources are sealed.
private enum AppBundleIdentityRewriter {
    /// Reads root and nested bundle metadata without changing files on disk.
    static func inspect(
        rootBundleURL: URL,
        replacementBundleIdentifier: String
    ) throws -> AppInspectionReport {
        let replacementIdentifier = try BundleIdentifier.normalize(replacementBundleIdentifier)
        let rootInfo = try MutableInfoPlist(url: rootBundleURL.appendingPathComponent("Info.plist"))
        let originalRootIdentifier = try rootInfo.requireBundleIdentifier(bundleURL: rootBundleURL)

        var requirements: [AppProvisioningRequirement] = [
            try inspectOneBundle(
                bundleURL: rootBundleURL,
                originalRootIdentifier: originalRootIdentifier,
                replacementRootIdentifier: replacementIdentifier,
                isRoot: true,
                rootBundleURL: rootBundleURL
            ),
        ]

        for nestedBundleURL in try nestedRewritableBundles(in: rootBundleURL) {
            requirements.append(
                try inspectOneBundle(
                    bundleURL: nestedBundleURL,
                    originalRootIdentifier: originalRootIdentifier,
                    replacementRootIdentifier: replacementIdentifier,
                    isRoot: false,
                    rootBundleURL: rootBundleURL
                )
            )
        }

        return AppInspectionReport(
            rootBundleURL: rootBundleURL,
            rootBundleIdentifier: originalRootIdentifier,
            replacementBundleIdentifier: replacementIdentifier,
            provisioningRequirements: requirements
        )
    }

    /// Rewrites the root app and nested app/extension bundles.
    ///
    /// The root app receives the caller-supplied identifier. Extensions are
    /// rebased so they remain children of the new root identifier even when the
    /// original extension identifier did not share the original root prefix.
    static func rewrite(
        rootBundleURL: URL,
        replacementBundleIdentifier: String,
        options: AppSigningOptions
    ) throws -> [AppBundleDescriptor] {
        try AppBundleContentPruner.apply(options: options, rootBundleURL: rootBundleURL)

        let rootInfoURL = rootBundleURL.appendingPathComponent("Info.plist")
        let rootInfo = try MutableInfoPlist(url: rootInfoURL)
        let originalRootIdentifier = try rootInfo.requireBundleIdentifier(bundleURL: rootBundleURL)

        var descriptors: [AppBundleDescriptor] = []
        descriptors.append(
            try rewriteOneBundle(
                bundleURL: rootBundleURL,
                originalRootIdentifier: originalRootIdentifier,
                replacementRootIdentifier: replacementBundleIdentifier,
                isRoot: true,
                options: options
            )
        )

        for nestedBundleURL in try nestedRewritableBundles(in: rootBundleURL) {
            descriptors.append(
                try rewriteOneBundle(
                    bundleURL: nestedBundleURL,
                    originalRootIdentifier: originalRootIdentifier,
                    replacementRootIdentifier: replacementBundleIdentifier,
                    isRoot: false,
                    options: options
                )
            )
        }

        return descriptors
    }

    /// Reads one bundle's pre-rewrite and post-rewrite metadata.
    private static func inspectOneBundle(
        bundleURL: URL,
        originalRootIdentifier: String,
        replacementRootIdentifier: String,
        isRoot: Bool,
        rootBundleURL: URL
    ) throws -> AppProvisioningRequirement {
        let info = try MutableInfoPlist(url: bundleURL.appendingPathComponent("Info.plist"))
        let originalIdentifier = try info.requireBundleIdentifier(bundleURL: bundleURL)
        let rewrittenIdentifier: String
        if isRoot {
            rewrittenIdentifier = replacementRootIdentifier
        } else if bundleURL.pathExtension.lowercased() == "appex" {
            rewrittenIdentifier = BundleIdentifier.rebasedExtensionIdentifier(
                originalIdentifier,
                originalRootIdentifier: originalRootIdentifier,
                replacementRootIdentifier: replacementRootIdentifier
            )
        } else {
            rewrittenIdentifier = BundleIdentifier.rebasedNestedIdentifier(
                originalIdentifier,
                originalRootIdentifier: originalRootIdentifier,
                replacementRootIdentifier: replacementRootIdentifier
            )
        }

        let watch = isWatchBundle(info: info.dictionary, bundleURL: bundleURL)
        let bundleRelativePath = isRoot ? "." : try relativePath(for: bundleURL, under: rootBundleURL)
        let reportURL = isRoot
            ? rootBundleURL
            : rootBundleURL.appendingPathComponent(bundleRelativePath, isDirectory: true)
        return AppProvisioningRequirement(
            url: reportURL,
            relativePath: bundleRelativePath,
            originalBundleIdentifier: originalIdentifier,
            rewrittenBundleIdentifier: rewrittenIdentifier,
            kind: provisioningKind(isRoot: isRoot, bundleURL: bundleURL, isWatchBundle: watch),
            isWatchBundle: watch,
            associatedBundleIdentifier: associatedBundleIdentifier(
                in: info,
                originalRootIdentifier: originalRootIdentifier,
                replacementRootIdentifier: replacementRootIdentifier
            ),
            executableName: info.trimmedString(forKey: "CFBundleExecutable")
        )
    }

    /// Rewrites one `Info.plist` and returns the metadata needed for signing.
    private static func rewriteOneBundle(
        bundleURL: URL,
        originalRootIdentifier: String,
        replacementRootIdentifier: String,
        isRoot: Bool,
        options: AppSigningOptions
    ) throws -> AppBundleDescriptor {
        var info = try MutableInfoPlist(url: bundleURL.appendingPathComponent("Info.plist"))
        let originalIdentifier = try info.requireBundleIdentifier(bundleURL: bundleURL)
        let rewrittenIdentifier: String
        if isRoot {
            rewrittenIdentifier = replacementRootIdentifier
        } else if bundleURL.pathExtension.lowercased() == "appex" {
            rewrittenIdentifier = BundleIdentifier.rebasedExtensionIdentifier(
                originalIdentifier,
                originalRootIdentifier: originalRootIdentifier,
                replacementRootIdentifier: replacementRootIdentifier
            )
        } else {
            rewrittenIdentifier = BundleIdentifier.rebasedNestedIdentifier(
                originalIdentifier,
                originalRootIdentifier: originalRootIdentifier,
                replacementRootIdentifier: replacementRootIdentifier
            )
        }

        info.setString(rewrittenIdentifier, forKey: "CFBundleIdentifier")
        info.rewriteBundleIdentifierURLSchemes(
            replacing: originalIdentifier,
            with: rewrittenIdentifier
        )
        info.rewriteStringValue(
            forKeyPath: ["WKCompanionAppBundleIdentifier"],
            replacing: originalRootIdentifier,
            with: replacementRootIdentifier
        )
        info.rewriteStringValue(
            forKeyPath: ["NSExtension", "NSExtensionAttributes", "WKAppBundleIdentifier"],
            replacing: originalRootIdentifier,
            with: replacementRootIdentifier
        )
        if isRoot {
            try AppRootInfoRewriter.apply(options: options, info: &info)
            try AppLocalizedNameRewriter.apply(
                displayName: options.displayName,
                rootBundleURL: bundleURL
            )
        }
        try info.write()

        return AppBundleDescriptor(
            url: bundleURL,
            originalIdentifier: originalIdentifier,
            rewrittenIdentifier: rewrittenIdentifier,
            associatedBundleIdentifier: associatedBundleIdentifier(
                in: info,
                originalRootIdentifier: originalRootIdentifier,
                replacementRootIdentifier: replacementRootIdentifier
            ),
            originalEntitlementsXML: try originalEntitlementsXML(bundleURL: bundleURL, info: info, options: options),
            isProvisionedBundle: isProvisionedBundle(bundleURL),
            isWatchBundle: isWatchBundle(info: info.dictionary, bundleURL: bundleURL)
        )
    }

    /// Finds nested `.app` and `.appex` bundles whose identifiers may need to
    /// follow the rewritten root app identifier.
    private static func nestedRewritableBundles(in rootBundleURL: URL) throws -> [URL] {
        var bundles: [URL] = []
        try FileManager.default.enumerateDescendants(of: rootBundleURL) { entry in
            guard
                try relativePath(for: entry.url, under: rootBundleURL)
                    != "Info.plist"
            else {
                return .visitDescendants
            }
            guard entry.kind == .directory else {
                return .visitDescendants
            }
            guard
                isProvisionedBundle(entry.url),
                FileManager.default.fileExists(
                    atPath: entry.url
                        .appendingPathComponent("Info.plist")
                        .path
                )
            else {
                return .visitDescendants
            }
            bundles.append(entry.url)
            return .visitDescendants
        }
        return bundles.sorted { $0.path < $1.path }
    }

    /// Reads the executable's current entitlement slot before the final signer
    /// overwrites it.
    private static func originalEntitlementsXML(
        bundleURL: URL,
        info: MutableInfoPlist,
        options: AppSigningOptions
    ) throws -> String {
        guard let executableName = info.trimmedString(forKey: "CFBundleExecutable") else {
            return ""
        }
        guard !executableName.contains("/"), !executableName.contains("\\") else {
            throw RorkSignError.invalidBundle("CFBundleExecutable is not a plain filename: \(executableName).")
        }

        let executableURL = bundleURL.appendingPathComponent(executableName)
        guard FileManager.default.fileExists(atPath: executableURL.path) else {
            return ""
        }
        let executableEntitlementsXML = try MachOSigner.readEntitlementsXML(Data(contentsOf: executableURL))
        if !executableEntitlementsXML.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return executableEntitlementsXML
        }
        return try bundledEntitlementsXML(
            bundleURL: bundleURL,
            resourceName: options.entitlementsResourceName
        )
    }

    /// Reads the entitlement request bundled with unsigned host artifacts.
    private static func bundledEntitlementsXML(bundleURL: URL, resourceName: String?) throws -> String {
        guard let rawResourceName = resourceName?.trimmingCharacters(in: .whitespacesAndNewlines),
              !rawResourceName.isEmpty else {
            return ""
        }
        guard !rawResourceName.contains("/"), !rawResourceName.contains("\\") else {
            throw RorkSignError.invalidEntitlements(
                "Entitlement request resource name must be a plain filename: \(rawResourceName)."
            )
        }

        let entitlementsURL = bundleURL.appendingPathComponent(rawResourceName)
        guard FileManager.default.fileExists(atPath: entitlementsURL.path) else {
            return ""
        }

        let data = try Data(contentsOf: entitlementsURL)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = plist as? [String: Any] else {
            throw RorkSignError.invalidEntitlements("\(rawResourceName) must contain a dictionary.")
        }
        return try EntitlementPlist.xml(from: dictionary)
    }

    /// Returns whether a bundle can carry an embedded provisioning profile.
    private static func isProvisionedBundle(_ url: URL) -> Bool {
        let pathExtension = url.pathExtension.lowercased()
        return pathExtension == "app" || pathExtension == "appex"
    }

    /// Detects Watch bundles from path and common watchOS Info.plist markers.
    private static func isWatchBundle(info: [String: Any], bundleURL: URL) -> Bool {
        if bundleURL.path.contains("/Watch/") {
            return true
        }
        if let platformName = info["DTPlatformName"] as? String,
           platformName.range(of: "watch", options: .caseInsensitive) != nil {
            return true
        }
        if let platforms = info["CFBundleSupportedPlatforms"] as? [String],
           platforms.contains(where: { $0.range(of: "watch", options: .caseInsensitive) != nil }) {
            return true
        }
        return (info["WKApplication"] as? Bool) == true
    }

    /// Classifies the bundle role while keeping Watch-ness as a separate flag.
    private static func provisioningKind(
        isRoot: Bool,
        bundleURL: URL,
        isWatchBundle: Bool
    ) -> AppProvisioningKind {
        if isRoot {
            return .rootApp
        }
        if bundleURL.pathExtension.lowercased() == "appex" {
            return .appExtension
        }
        if isWatchBundle {
            return .watchApp
        }
        return .nestedApp
    }

    /// Returns the associated bundle identifier after applying the root rewrite.
    private static func associatedBundleIdentifier(
        in info: MutableInfoPlist,
        originalRootIdentifier: String,
        replacementRootIdentifier: String
    ) -> String? {
        let rawAssociatedIdentifier = info.string(forKeyPath: ["WKCompanionAppBundleIdentifier"])
            ?? info.string(forKeyPath: ["NSExtension", "NSExtensionAttributes", "WKAppBundleIdentifier"])
        guard let rawAssociatedIdentifier else {
            return nil
        }
        return BundleIdentifier.rebasedNestedIdentifier(
            rawAssociatedIdentifier,
            originalRootIdentifier: originalRootIdentifier,
            replacementRootIdentifier: replacementRootIdentifier
        )
    }
}

/// Removes optional bundle content before nested bundles are discovered.
private enum AppBundleContentPruner {
    /// Root-relative directories that hold app extensions.
    private static let extensionDirectories = ["PlugIns", "Extensions"]

    /// Applies root app cleanup options before signing.
    static func apply(options: AppSigningOptions, rootBundleURL: URL) throws {
        let fileManager = FileManager.default
        if options.removeExtensions {
            try removeExistingDirectories(
                extensionDirectories,
                rootBundleURL: rootBundleURL,
                fileManager: fileManager
            )
        } else {
            // Removing every extension already covers the named subset, so this
            // only runs when the whole-directory removal is off.
            try removeNamedExtensions(
                options.extensionsToRemove,
                rootBundleURL: rootBundleURL,
                fileManager: fileManager
            )
        }
        if options.removeWatchApps {
            try removeExistingDirectories(
                ["Watch", "WatchKit", "com.apple.WatchPlaceholder"],
                rootBundleURL: rootBundleURL,
                fileManager: fileManager
            )
        }
    }

    /// Deletes individually named `.appex` bundles from the root app's extension
    /// directories, leaving the rest of `PlugIns`/`Extensions` intact.
    private static func removeNamedExtensions(
        _ names: [String],
        rootBundleURL: URL,
        fileManager: FileManager
    ) throws {
        guard !names.isEmpty else {
            return
        }
        // Confine each entry to a direct child of an extension directory so a
        // caller-supplied name cannot escape the bundle via path traversal.
        let relativePaths = try names.flatMap { name -> [String] in
            guard !name.isEmpty,
                  name != ".",
                  name != "..",
                  !name.contains("/"),
                  !name.contains("\\")
            else {
                throw RorkSignError.invalidBundle(
                    "extensionsToRemove entries must be plain bundle names, not \"\(name)\"."
                )
            }
            return extensionDirectories.map { "\($0)/\(name)" }
        }
        try removeExistingDirectories(
            relativePaths,
            rootBundleURL: rootBundleURL,
            fileManager: fileManager
        )
    }

    private static func removeExistingDirectories(
        _ relativePaths: [String],
        rootBundleURL: URL,
        fileManager: FileManager
    ) throws {
        for relativePath in relativePaths {
            let url = rootBundleURL.appendingPathComponent(relativePath, isDirectory: true)
            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
                continue
            }
            guard isDirectory.boolValue else {
                continue
            }
            try fileManager.removeItem(at: url)
        }
    }
}

/// Applies root-only `Info.plist` mutations before resources are sealed.
private enum AppRootInfoRewriter {
    /// Limits caller-supplied metadata changes to the host app.
    ///
    /// Nested bundle identifiers and profiles are rewritten by their dedicated
    /// signing paths, so applying these options recursively would overwrite
    /// extension-owned metadata.
    static func apply(options: AppSigningOptions, info: inout MutableInfoPlist) throws {
        if let displayName = nonEmptyTrimmed(options.displayName) {
            info.setString(displayName, forKey: "CFBundleName")
            info.setString(displayName, forKey: "CFBundleDisplayName")
        }
        if let bundleVersion = nonEmptyTrimmed(options.bundleVersion) {
            info.setString(bundleVersion, forKey: "CFBundleVersion")
            info.setString(bundleVersion, forKey: "CFBundleShortVersionString")
        }
        if let minimumOSVersion = nonEmptyTrimmed(options.minimumOSVersion) {
            info.setString(minimumOSVersion, forKey: "MinimumOSVersion")
        }
        if options.enableDocuments {
            info.setBool(true, forKey: "UISupportsDocumentBrowser")
            info.setBool(true, forKey: "UIFileSharingEnabled")
        }
        if options.removeUISupportedDevices {
            info.removeValue(forKey: "UISupportedDevices")
        }
    }
}

/// Rewrites localized display-name strings when they are plist-backed files.
private enum AppLocalizedNameRewriter {
    /// Updates localizations that Foundation can decode as property lists.
    ///
    /// A bundle may contain strings files in other encodings or syntaxes.
    /// Leaving those files untouched is safer than attempting a lossy textual
    /// rewrite while the surrounding resources are being resealed.
    static func apply(displayName: String?, rootBundleURL: URL) throws {
        guard let displayName = nonEmptyTrimmed(displayName) else {
            return
        }

        try FileManager.default.enumerateDescendants(
            of: rootBundleURL,
            options: .skipsHiddenFiles
        ) { entry in
            if entry.kind == .directory, entry.url.pathExtension == "lproj" {
                return .visitDescendants
            }
            if entry.kind == .directory {
                return .skipDescendants
            }
            guard
                entry.kind == .regularFile,
                entry.url.lastPathComponent == "InfoPlist.strings",
                entry.url.deletingLastPathComponent().pathExtension == "lproj"
            else {
                return .visitDescendants
            }
            try rewriteStringsFile(
                at: entry.url,
                displayName: displayName
            )
            return .visitDescendants
        }
    }

    /// Rewrites a decoded strings dictionary and preserves unsupported files.
    private static func rewriteStringsFile(at url: URL, displayName: String) throws {
        let data = try Data(contentsOf: url)
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data,
            options: [.mutableContainersAndLeaves],
            format: nil
        ) else {
            return
        }
        guard var dictionary = plist as? [String: Any] else {
            return
        }
        dictionary["CFBundleName"] = displayName
        dictionary["CFBundleDisplayName"] = displayName
        let output = try PropertyListWriter.data(
            from: dictionary,
            format: .xml
        )
        try output.writeReplacingItem(at: url)
    }
}

/// Decoded provisioning profile plus its original bytes.
private struct AppProvisioningAsset {
    let data: Data
    let profile: ProvisioningProfile
}

/// Resolves root, Watch, and per-bundle provisioning profiles.
private struct AppProvisioningAssets {
    let rootAsset: AppProvisioningAsset?
    let watchAsset: AppProvisioningAsset?
    let assetsByBundleIdentifier: [String: AppProvisioningAsset]
    let teamIdentifier: String?

    init(
        rootProvisioningProfile: Data?,
        watchProvisioningProfile: Data?,
        provisioningProfilesByBundleIdentifier: [String: Data],
        identity: SigningIdentity?
    ) throws {
        rootAsset = try rootProvisioningProfile.map { data in
            try AppProvisioningAsset(
                data: data,
                profile: RorkSigner.decodeProvisioningProfile(data)
            )
        }
        watchAsset = try watchProvisioningProfile.map { data in
            try AppProvisioningAsset(
                data: data,
                profile: RorkSigner.decodeProvisioningProfile(data)
            )
        }

        var decoded: [String: AppProvisioningAsset] = [:]
        for (rawIdentifier, data) in provisioningProfilesByBundleIdentifier {
            let identifier = try BundleIdentifier.normalize(rawIdentifier)
            decoded[identifier] = try AppProvisioningAsset(
                data: data,
                profile: RorkSigner.decodeProvisioningProfile(data)
            )
        }
        assetsByBundleIdentifier = decoded

        let assets = [rootAsset, watchAsset].compactMap { $0 } + Array(decoded.values)
        try Self.validateTeams(assets)
        teamIdentifier = assets.first?.profile.teamIdentifier
        if let identity {
            try Self.validateIdentity(identity, assets: assets)
        }
    }

    /// Returns the identity retagged with the profiles' Apple team so the
    /// signature's team matches the embedded provisioning profiles.
    func signingIdentity(for identity: SigningIdentity) throws -> SigningIdentity {
        guard let teamIdentifier else {
            return identity
        }
        return try identity.withTeamIdentifier(teamIdentifier)
    }

    /// Returns an exact per-bundle profile, then Watch/root fallback profiles.
    ///
    /// Profile selection happens after identifier rewriting, so this also
    /// verifies that the selected App ID authorizes the rewritten bundle
    /// identifier before the profile is embedded or used for entitlements.
    func asset(for bundleIdentifier: String, isWatchBundle: Bool) throws -> AppProvisioningAsset? {
        if let exactAsset = assetsByBundleIdentifier[bundleIdentifier] {
            try validateAuthorization(exactAsset, bundleIdentifier: bundleIdentifier)
            return exactAsset
        }
        if isWatchBundle, let watchAsset {
            try validateAuthorization(watchAsset, bundleIdentifier: bundleIdentifier)
            return watchAsset
        }
        guard let rootAsset else {
            return nil
        }
        try validateAuthorization(rootAsset, bundleIdentifier: bundleIdentifier)
        return rootAsset
    }

    /// Rejects mixed-team profile sets before producing inconsistent output.
    private static func validateTeams(_ assets: [AppProvisioningAsset]) throws {
        guard let team = assets.first?.profile.teamIdentifier else {
            return
        }
        for asset in assets where asset.profile.teamIdentifier != team {
            throw RorkSignError.invalidProvisioningProfile(
                "App signing provisioning profiles must belong to the same Apple team."
            )
        }
    }

    /// Ensures identity-backed signing uses a certificate authorized by every
    /// selected profile.
    private static func validateIdentity(
        _ identity: SigningIdentity,
        assets: [AppProvisioningAsset]
    ) throws {
        for asset in assets where !asset.profile.containsDeveloperCertificate(for: identity) {
            throw RorkSignError.invalidSigningIdentity(
                "Signing identity is not authorized by one of the provisioning profiles."
            )
        }
    }

    /// Ensures the selected provisioning profile can legally cover the final
    /// bundle identifier written to `Info.plist`.
    private func validateAuthorization(
        _ asset: AppProvisioningAsset,
        bundleIdentifier: String
    ) throws {
        guard asset.profile.supportsBundleIdentifier(bundleIdentifier) else {
            throw RorkSignError.invalidProvisioningProfile(
                "Provisioning profile does not authorize bundle identifier \(bundleIdentifier)."
            )
        }
    }
}

/// Safe mutable wrapper for an `Info.plist` dictionary on disk.
private struct MutableInfoPlist {
    let url: URL
    var dictionary: [String: Any]

    init(url: URL) throws {
        self.url = url
        let data = try Data(contentsOf: url)
        let plist = try PropertyListSerialization.propertyList(
            from: data,
            options: [.mutableContainersAndLeaves],
            format: nil
        )
        guard let dictionary = plist as? [String: Any] else {
            throw RorkSignError.invalidBundle("Info.plist is not a dictionary: \(url.path).")
        }
        self.dictionary = dictionary
    }

    func requireBundleIdentifier(bundleURL: URL) throws -> String {
        guard let identifier = trimmedString(forKey: "CFBundleIdentifier") else {
            throw RorkSignError.invalidBundle("Bundle has no CFBundleIdentifier: \(bundleURL.path).")
        }
        return identifier
    }

    func trimmedString(forKey key: String) -> String? {
        guard let string = dictionary[key] as? String else {
            return nil
        }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    func string(forKeyPath keyPath: [String]) -> String? {
        value(forKeyPath: keyPath) as? String
    }

    mutating func setString(_ value: String, forKey key: String) {
        dictionary[key] = value
    }

    mutating func setBool(_ value: Bool, forKey key: String) {
        dictionary[key] = value
    }

    mutating func removeValue(forKey key: String) {
        dictionary.removeValue(forKey: key)
    }

    /// Rewrites one nested string value if the path exists.
    mutating func rewriteStringValue(
        forKeyPath keyPath: [String],
        replacing oldRootIdentifier: String,
        with replacementRootIdentifier: String
    ) {
        guard let value = string(forKeyPath: keyPath) else {
            return
        }
        setValue(
            BundleIdentifier.rebasedNestedIdentifier(
                value,
                originalRootIdentifier: oldRootIdentifier,
                replacementRootIdentifier: replacementRootIdentifier
            ),
            forKeyPath: keyPath
        )
    }

    /// Rebases URL schemes whose final component is the bundle identifier.
    mutating func rewriteBundleIdentifierURLSchemes(
        replacing originalIdentifier: String,
        with replacementIdentifier: String
    ) {
        guard var urlTypes = dictionary["CFBundleURLTypes"]
            as? [[String: Any]]
        else {
            return
        }

        for index in urlTypes.indices {
            guard var schemes = urlTypes[index]["CFBundleURLSchemes"]
                as? [String]
            else {
                continue
            }
            for schemeIndex in schemes.indices {
                schemes[schemeIndex] = BundleIdentifier.rebasedURLScheme(
                    schemes[schemeIndex],
                    originalBundleIdentifier: originalIdentifier,
                    replacementBundleIdentifier: replacementIdentifier
                )
            }
            urlTypes[index]["CFBundleURLSchemes"] = schemes
        }
        dictionary["CFBundleURLTypes"] = urlTypes
    }

    /// Persists the modified metadata through the shared plist boundary.
    ///
    /// The metadata remains open-ended while it is edited, so the writer
    /// validates the dynamic value graph before Foundation serializes it.
    func write() throws {
        let data = try PropertyListWriter.data(
            from: dictionary,
            format: .xml
        )
        try data.writeReplacingItem(at: url)
    }

    private func value(forKeyPath keyPath: [String]) -> Any? {
        var current: Any = dictionary
        for key in keyPath {
            guard let dictionary = current as? [String: Any],
                  let next = dictionary[key] else {
                return nil
            }
            current = next
        }
        return current
    }

    private mutating func setValue(_ value: Any, forKeyPath keyPath: [String]) {
        guard !keyPath.isEmpty else {
            return
        }
        dictionary = Self.setting(value, forKeyPath: keyPath, in: dictionary)
    }

    private static func setting(_ value: Any, forKeyPath keyPath: [String], in dictionary: [String: Any]) -> [String: Any] {
        var result = dictionary
        let key = keyPath[0]
        if keyPath.count == 1 {
            result[key] = value
            return result
        }

        let child = dictionary[key] as? [String: Any] ?? [:]
        result[key] = setting(value, forKeyPath: Array(keyPath.dropFirst()), in: child)
        return result
    }
}

/// Bundle identifier helpers shared by rewriting and profile lookup.
private enum BundleIdentifier {
    /// Trims a bundle identifier and rejects empty or path-separator values.
    static func normalize(_ value: String) throws -> String {
        let identifier = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !identifier.isEmpty else {
            throw RorkSignError.invalidBundle("Bundle identifier is empty.")
        }
        guard !identifier.contains("/"), !identifier.contains("\\") else {
            throw RorkSignError.invalidBundle("Bundle identifier contains a path separator: \(identifier).")
        }
        return identifier
    }

    /// Re-homes an app-extension identifier under the replacement root.
    ///
    /// Like `rebasedNestedIdentifier`, but an extension must always end up a
    /// child of the new root: when the original identifier did not share the
    /// original root prefix, its last component (or a stable fallback) is
    /// appended to the new root so the result stays a valid nested identifier.
    static func rebasedExtensionIdentifier(
        _ originalIdentifier: String,
        originalRootIdentifier: String,
        replacementRootIdentifier: String
    ) -> String {
        let rewritten = rebasedNestedIdentifier(
            originalIdentifier,
            originalRootIdentifier: originalRootIdentifier,
            replacementRootIdentifier: replacementRootIdentifier
        )
        let requiredPrefix = replacementRootIdentifier + "."
        guard !rewritten.hasPrefix(requiredPrefix) else {
            return rewritten
        }

        let originalPrefix = originalRootIdentifier + "."
        let suffix: String
        if originalIdentifier.hasPrefix(originalPrefix) {
            suffix = String(originalIdentifier.dropFirst(originalPrefix.count))
        } else {
            suffix = originalIdentifier.split(separator: ".").last.map(String.init) ?? "extension"
        }
        return requiredPrefix + (suffix.isEmpty ? "extension" : suffix)
    }

    /// Re-homes a nested identifier under the replacement root.
    ///
    /// An identifier equal to the original root becomes the new root; one that
    /// shares the original root prefix keeps its suffix under the new root; an
    /// unrelated identifier is returned unchanged.
    static func rebasedNestedIdentifier(
        _ originalIdentifier: String,
        originalRootIdentifier: String,
        replacementRootIdentifier: String
    ) -> String {
        guard originalIdentifier != originalRootIdentifier else {
            return replacementRootIdentifier
        }

        let originalPrefix = originalRootIdentifier + "."
        guard originalIdentifier.hasPrefix(originalPrefix) else {
            return originalIdentifier
        }
        return replacementRootIdentifier + "." + originalIdentifier.dropFirst(originalPrefix.count)
    }

    /// Rebases a URL scheme explicitly tied to one bundle identifier.
    static func rebasedURLScheme(
        _ scheme: String,
        originalBundleIdentifier: String,
        replacementBundleIdentifier: String
    ) -> String {
        let lowercaseScheme = scheme.lowercased()
        let lowercaseIdentifier = originalBundleIdentifier.lowercased()
        guard lowercaseScheme.hasSuffix(lowercaseIdentifier) else {
            return scheme
        }

        let identifierStart = scheme.index(
            scheme.endIndex,
            offsetBy: -originalBundleIdentifier.count
        )
        let prefix = String(scheme[..<identifierStart])
        switch prefix.last {
        case nil, ".", "-", "+":
            return prefix + replacementBundleIdentifier
        default:
            return scheme
        }
    }
}

/// Trims user-facing optional strings and treats blank values as unset.
private func nonEmptyTrimmed(_ value: String?) -> String? {
    guard let value else {
        return nil
    }
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
}

/// Produces a bundle-relative path and rejects traversal outside `rootURL`.
private func relativePath(for url: URL, under rootURL: URL) throws -> String {
    let rootPath = normalizedFileSystemPath(
        rootURL.standardizedFileURL.path
    )
    let path = normalizedFileSystemPath(
        url.standardizedFileURL.path
    )
    guard path.hasPrefix(rootPath + "/") else {
        throw RorkSignError.invalidBundle("Path escaped bundle root: \(path).")
    }
    return String(path.dropFirst(rootPath.count + 1))
}
