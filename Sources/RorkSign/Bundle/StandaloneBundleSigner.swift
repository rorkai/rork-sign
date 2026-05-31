import Foundation

/// Configuration for turning a copied app bundle into a standalone app.
///
/// Standalone signing is stricter than generic bundle signing because the app is
/// being re-homed under a new bundle identifier. The signer rewrites
/// `CFBundleIdentifier` values first, derives entitlements from the selected
/// provisioning profiles, embeds those profiles, seals resources, and finally
/// signs the executables.
public struct StandaloneBundleSigningOptions: Equatable {
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
    /// mirroring ZSign's `-e/--entitlements` behavior for callers that need to
    /// supply a complete entitlement plist. Nested app and extension
    /// entitlements are still derived from their selected provisioning profiles
    /// so identifier rebasing and associated-application keys remain coherent.
    public var rootEntitlementsXML: String

    /// Replacement display name for the root app.
    ///
    /// When set, the signer writes both `CFBundleName` and
    /// `CFBundleDisplayName` in the root `Info.plist` and in localized
    /// `*.lproj/InfoPlist.strings` files that can be parsed as property lists.
    public var displayName: String?

    /// Replacement version for the root app.
    ///
    /// This mirrors ZSign-style bundle editing by writing the same value to
    /// both `CFBundleVersion` and `CFBundleShortVersionString`.
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

    /// Removes embedded Watch app directories before signing.
    public var removeWatchApps: Bool

    /// Removes `UISupportedDevices` from the root app's `Info.plist`.
    public var removeUISupportedDevices: Bool

    /// Whether selected provisioning profiles are embedded before resource sealing.
    ///
    /// This defaults to `true` because standalone app outputs normally need an
    /// embedded provisioning profile. ZSign-compatible workflows can disable it
    /// to mirror `--rm_provision`, in which case profile-derived entitlements
    /// are still used for signing but no `embedded.mobileprovision` file is
    /// sealed into the bundle. Existing embedded profiles are removed before
    /// the resource seal is generated.
    public var embedProvisioningProfiles: Bool

    /// Dylib files copied into the root app and loaded by the root executable.
    public var dylibInjections: [BundleDylibInjection]

    /// Dylib load commands removed from the root executable before signing.
    public var dylibLoadCommandsToRemove: [String]

    /// CodeDirectory digest layout used for every Mach-O in the rewritten app.
    ///
    /// Standalone apps default to `.sha256Only` so independently installable
    /// apps avoid a legacy SHA-1 cdhash. Override this only when a caller needs
    /// the broader SHA-1-primary compatibility shape for a fixture or
    /// diagnostic artifact.
    public var codeDirectoryHashingMode: CodeDirectoryHashingMode

    /// Optional persistent cache for the final signed Mach-O outputs.
    public var signingCache: SigningCacheOptions?

    /// Creates standalone signing options.
    public init(
        bundleIdentifier: String,
        rootProvisioningProfile: Data? = nil,
        watchProvisioningProfile: Data? = nil,
        provisioningProfilesByBundleIdentifier: [String: Data] = [:],
        appGroupIdentifiers: [String] = [],
        rootEntitlementsXML: String = "",
        displayName: String? = nil,
        bundleVersion: String? = nil,
        minimumOSVersion: String? = nil,
        enableDocuments: Bool = false,
        removeExtensions: Bool = false,
        removeWatchApps: Bool = false,
        removeUISupportedDevices: Bool = false,
        embedProvisioningProfiles: Bool = true,
        dylibInjections: [BundleDylibInjection] = [],
        dylibLoadCommandsToRemove: [String] = [],
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .sha256Only,
        signingCache: SigningCacheOptions? = nil
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.rootProvisioningProfile = rootProvisioningProfile
        self.watchProvisioningProfile = watchProvisioningProfile
        self.provisioningProfilesByBundleIdentifier = provisioningProfilesByBundleIdentifier
        self.appGroupIdentifiers = appGroupIdentifiers
        self.rootEntitlementsXML = rootEntitlementsXML
        self.displayName = displayName
        self.bundleVersion = bundleVersion
        self.minimumOSVersion = minimumOSVersion
        self.enableDocuments = enableDocuments
        self.removeExtensions = removeExtensions
        self.removeWatchApps = removeWatchApps
        self.removeUISupportedDevices = removeUISupportedDevices
        self.embedProvisioningProfiles = embedProvisioningProfiles
        self.dylibInjections = dylibInjections
        self.dylibLoadCommandsToRemove = dylibLoadCommandsToRemove
        self.codeDirectoryHashingMode = codeDirectoryHashingMode
        self.signingCache = signingCache
    }
}

/// Rewrites bundle identity and delegates the final inside-out signing pass.
enum StandaloneBundleSigner {
    /// Rewrites `bundleURL` and applies ad-hoc signatures.
    static func signAdHoc(
        bundleURL: URL,
        options: StandaloneBundleSigningOptions
    ) throws -> BundleSigningReport {
        let bundleSigningOptions = try prepareBundleSigningOptions(
            bundleURL: bundleURL,
            options: options,
            identity: nil
        )
        return try BundleSigner.signAdHoc(bundleURL: bundleURL, options: bundleSigningOptions)
    }

    /// Rewrites `bundleURL` and applies identity-backed CMS signatures.
    static func signWithIdentity(
        bundleURL: URL,
        identity: SigningIdentity,
        options: StandaloneBundleSigningOptions
    ) throws -> BundleSigningReport {
        let bundleSigningOptions = try prepareBundleSigningOptions(
            bundleURL: bundleURL,
            options: options,
            identity: identity
        )
        return try BundleSigner.signWithIdentity(
            bundleURL: bundleURL,
            identity: identity,
            options: bundleSigningOptions
        )
    }

    /// Performs the mutation-only phase and returns assets for `BundleSigner`.
    private static func prepareBundleSigningOptions(
        bundleURL: URL,
        options: StandaloneBundleSigningOptions,
        identity: SigningIdentity?
    ) throws -> BundleSigningOptions {
        let replacementIdentifier = try BundleIdentifier.normalize(options.bundleIdentifier)
        let profiles = try StandaloneProvisioningAssets(
            rootProvisioningProfile: options.rootProvisioningProfile,
            watchProvisioningProfile: options.watchProvisioningProfile,
            provisioningProfilesByBundleIdentifier: options.provisioningProfilesByBundleIdentifier,
            identity: identity
        )
        let rewrittenBundles = try StandaloneBundleIdentityRewriter.rewrite(
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
                entitlementsByIdentifier[bundle.rewrittenIdentifier] = try StandaloneEntitlements.expand(
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
            signingCache: options.signingCache
        )
    }
}

/// One provisioned bundle after identifier rewriting.
private struct StandaloneBundleDescriptor: Equatable {
    let url: URL
    let originalIdentifier: String
    let rewrittenIdentifier: String
    let associatedBundleIdentifier: String?
    let originalEntitlementsXML: String
    let isProvisionedBundle: Bool
    let isWatchBundle: Bool
}

/// Rewrites app and extension identifiers before resources are sealed.
private enum StandaloneBundleIdentityRewriter {
    /// Rewrites the root app and nested app/extension bundles.
    ///
    /// The root app receives the caller-supplied identifier. Extensions are
    /// rebased so they remain children of the new root identifier even when the
    /// original extension identifier did not share the original root prefix.
    static func rewrite(
        rootBundleURL: URL,
        replacementBundleIdentifier: String,
        options: StandaloneBundleSigningOptions
    ) throws -> [StandaloneBundleDescriptor] {
        try StandaloneBundleContentPruner.apply(options: options, rootBundleURL: rootBundleURL)

        let rootInfoURL = rootBundleURL.appendingPathComponent("Info.plist")
        let rootInfo = try MutableInfoPlist(url: rootInfoURL)
        let originalRootIdentifier = try rootInfo.requireBundleIdentifier(bundleURL: rootBundleURL)

        var descriptors: [StandaloneBundleDescriptor] = []
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

    /// Rewrites one `Info.plist` and returns the metadata needed for signing.
    private static func rewriteOneBundle(
        bundleURL: URL,
        originalRootIdentifier: String,
        replacementRootIdentifier: String,
        isRoot: Bool,
        options: StandaloneBundleSigningOptions
    ) throws -> StandaloneBundleDescriptor {
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
            try StandaloneRootInfoRewriter.apply(options: options, info: &info)
            try StandaloneLocalizedNameRewriter.apply(
                displayName: options.displayName,
                rootBundleURL: bundleURL
            )
        }
        try info.write()

        return StandaloneBundleDescriptor(
            url: bundleURL,
            originalIdentifier: originalIdentifier,
            rewrittenIdentifier: rewrittenIdentifier,
            associatedBundleIdentifier: info.string(forKeyPath: ["WKCompanionAppBundleIdentifier"]),
            originalEntitlementsXML: try originalEntitlementsXML(bundleURL: bundleURL, info: info),
            isProvisionedBundle: isProvisionedBundle(bundleURL),
            isWatchBundle: isWatchBundle(info: info.dictionary, bundleURL: bundleURL)
        )
    }

    /// Finds nested `.app` and `.appex` bundles whose identifiers may need to
    /// follow the rewritten root app identifier.
    private static func nestedRewritableBundles(in rootBundleURL: URL) throws -> [URL] {
        let resourceKeys: Set<URLResourceKey> = [.isDirectoryKey]
        guard let enumerator = FileManager.default.enumerator(
            at: rootBundleURL,
            includingPropertiesForKeys: Array(resourceKeys),
            options: []
        ) else {
            throw RorkSignError.invalidBundle("Unable to enumerate bundle: \(rootBundleURL.path).")
        }

        var bundles: [URL] = []
        for case let url as URL in enumerator {
            guard try relativePath(for: url, under: rootBundleURL) != "Info.plist" else {
                continue
            }
            guard (try? url.resourceValues(forKeys: resourceKeys).isDirectory) == true else {
                continue
            }
            guard isProvisionedBundle(url),
                  FileManager.default.fileExists(atPath: url.appendingPathComponent("Info.plist").path) else {
                continue
            }
            bundles.append(url)
        }
        return bundles.sorted { $0.path < $1.path }
    }

    /// Reads the executable's current entitlement slot before the final signer
    /// overwrites it.
    private static func originalEntitlementsXML(bundleURL: URL, info: MutableInfoPlist) throws -> String {
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
        return try MachOSigner.readEntitlementsXML(Data(contentsOf: executableURL))
    }

    private static func isProvisionedBundle(_ url: URL) -> Bool {
        let pathExtension = url.pathExtension.lowercased()
        return pathExtension == "app" || pathExtension == "appex"
    }

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
}

/// Removes optional bundle content before nested bundles are discovered.
private enum StandaloneBundleContentPruner {
    /// Applies ZSign-style root app cleanup options.
    static func apply(options: StandaloneBundleSigningOptions, rootBundleURL: URL) throws {
        let fileManager = FileManager.default
        if options.removeExtensions {
            try removeExistingDirectories(
                ["PlugIns", "Extensions"],
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
private enum StandaloneRootInfoRewriter {
    static func apply(options: StandaloneBundleSigningOptions, info: inout MutableInfoPlist) throws {
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
private enum StandaloneLocalizedNameRewriter {
    static func apply(displayName: String?, rootBundleURL: URL) throws {
        guard let displayName = nonEmptyTrimmed(displayName) else {
            return
        }

        let resourceKeys: Set<URLResourceKey> = [.isDirectoryKey, .isRegularFileKey]
        guard let enumerator = FileManager.default.enumerator(
            at: rootBundleURL,
            includingPropertiesForKeys: Array(resourceKeys),
            options: [.skipsHiddenFiles]
        ) else {
            throw RorkSignError.invalidBundle("Unable to enumerate bundle: \(rootBundleURL.path).")
        }

        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: resourceKeys)
            if values.isDirectory == true, url.pathExtension == "lproj" {
                continue
            }
            if values.isDirectory == true {
                enumerator.skipDescendants()
                continue
            }
            guard values.isRegularFile == true,
                  url.lastPathComponent == "InfoPlist.strings",
                  url.deletingLastPathComponent().pathExtension == "lproj" else {
                continue
            }
            try rewriteStringsFile(at: url, displayName: displayName)
        }
    }

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
        let output = try PropertyListSerialization.data(
            fromPropertyList: dictionary,
            format: .xml,
            options: 0
        )
        try output.write(to: url, options: .atomic)
    }
}

/// Decoded provisioning profile plus its original bytes.
private struct StandaloneProvisioningAsset {
    let data: Data
    let profile: ProvisioningProfile
}

/// Resolves root, Watch, and per-bundle provisioning profiles.
private struct StandaloneProvisioningAssets {
    let rootAsset: StandaloneProvisioningAsset?
    let watchAsset: StandaloneProvisioningAsset?
    let assetsByBundleIdentifier: [String: StandaloneProvisioningAsset]

    init(
        rootProvisioningProfile: Data?,
        watchProvisioningProfile: Data?,
        provisioningProfilesByBundleIdentifier: [String: Data],
        identity: SigningIdentity?
    ) throws {
        rootAsset = try rootProvisioningProfile.map { data in
            try StandaloneProvisioningAsset(
                data: data,
                profile: RorkSigner.decodeProvisioningProfile(data)
            )
        }
        watchAsset = try watchProvisioningProfile.map { data in
            try StandaloneProvisioningAsset(
                data: data,
                profile: RorkSigner.decodeProvisioningProfile(data)
            )
        }

        var decoded: [String: StandaloneProvisioningAsset] = [:]
        for (rawIdentifier, data) in provisioningProfilesByBundleIdentifier {
            let identifier = try BundleIdentifier.normalize(rawIdentifier)
            decoded[identifier] = try StandaloneProvisioningAsset(
                data: data,
                profile: RorkSigner.decodeProvisioningProfile(data)
            )
        }
        assetsByBundleIdentifier = decoded

        let assets = [rootAsset, watchAsset].compactMap { $0 } + Array(decoded.values)
        try Self.validateTeams(assets)
        if let identity {
            try Self.validateIdentity(identity, assets: assets)
        }
    }

    /// Returns an exact per-bundle profile, then Watch/root fallback profiles.
    ///
    /// Profile selection happens after identifier rewriting, so this also
    /// verifies that the selected App ID authorizes the rewritten bundle
    /// identifier before the profile is embedded or used for entitlements.
    func asset(for bundleIdentifier: String, isWatchBundle: Bool) throws -> StandaloneProvisioningAsset? {
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
    private static func validateTeams(_ assets: [StandaloneProvisioningAsset]) throws {
        guard let team = assets.first?.profile.teamIdentifier else {
            return
        }
        for asset in assets where asset.profile.teamIdentifier != team {
            throw RorkSignError.invalidProvisioningProfile(
                "Standalone provisioning profiles must belong to the same Apple team."
            )
        }
    }

    /// Ensures identity-backed signing uses a certificate authorized by every
    /// selected profile.
    private static func validateIdentity(
        _ identity: SigningIdentity,
        assets: [StandaloneProvisioningAsset]
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
        _ asset: StandaloneProvisioningAsset,
        bundleIdentifier: String
    ) throws {
        guard asset.profile.supportsBundleIdentifier(bundleIdentifier) else {
            throw RorkSignError.invalidProvisioningProfile(
                "Provisioning profile does not authorize bundle identifier \(bundleIdentifier)."
            )
        }
    }
}

/// Builds final entitlement XML from profile and executable state.
private enum StandaloneEntitlements {
    /// Expands profile entitlements for one rewritten bundle identifier.
    ///
    /// The profile is the upper bound of allowed capabilities. The original
    /// executable entitlement plist is used as a filter so optional profile
    /// capabilities are kept only when the executable already asked for them.
    static func expand(
        profile: ProvisioningProfile,
        bundleIdentifier: String,
        originalEntitlementsXML: String,
        associatedBundleIdentifier: String?,
        appGroupIdentifiers: [String]
    ) throws -> String {
        var entitlements = try EntitlementPlist.dictionary(fromXML: profile.entitlementsXML)
        guard !entitlements.isEmpty else {
            return ""
        }

        let original = try EntitlementPlist.dictionary(fromXML: originalEntitlementsXML)
        let appGroups = AppGroupIdentifiers.normalize(appGroupIdentifiers)
        for key in entitlements.keys where !shouldKeep(key, original: original, appGroupIdentifiers: appGroups) {
            entitlements.removeValue(forKey: key)
        }

        let applicationIdentifier = "\(profile.teamIdentifier).\(bundleIdentifier)"
        entitlements["application-identifier"] = applicationIdentifier
        entitlements["com.apple.developer.team-identifier"] = profile.teamIdentifier
        entitlements["keychain-access-groups"] = normalizedKeychainGroups(
            original: original,
            teamIdentifier: profile.teamIdentifier,
            applicationIdentifier: applicationIdentifier
        )

        if let associatedBundleIdentifier,
           !associatedBundleIdentifier.isEmpty,
           entitlements["com.apple.developer.associated-application-identifier"] != nil {
            entitlements["com.apple.developer.associated-application-identifier"] =
                "\(profile.teamIdentifier).\(associatedBundleIdentifier)"
        }

        if !appGroups.isEmpty {
            entitlements["com.apple.security.application-groups"] = appGroups
        }

        return try EntitlementPlist.xml(from: entitlements)
    }

    private static func shouldKeep(
        _ key: String,
        original: [String: Any],
        appGroupIdentifiers: [String]
    ) -> Bool {
        let alwaysKept: Set<String> = [
            "application-identifier",
            "com.apple.developer.team-identifier",
            "get-task-allow",
            "keychain-access-groups",
        ]
        if alwaysKept.contains(key) {
            return true
        }
        if key == "com.apple.security.application-groups" {
            return !appGroupIdentifiers.isEmpty || original[key] != nil
        }
        return original[key] != nil
    }

    private static func normalizedKeychainGroups(
        original: [String: Any],
        teamIdentifier: String,
        applicationIdentifier: String
    ) -> [String] {
        var groups: [String] = []
        for value in original["keychain-access-groups"] as? [String] ?? [] {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                continue
            }

            let normalized: String
            if let dot = trimmed.firstIndex(of: ".") {
                normalized = teamIdentifier + trimmed[dot...]
            } else {
                normalized = "\(teamIdentifier).\(trimmed)"
            }
            if !groups.contains(normalized) {
                groups.append(normalized)
            }
        }

        if groups.isEmpty {
            groups.append(applicationIdentifier)
        }
        return groups
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

    func write() throws {
        let data = try PropertyListSerialization.data(
            fromPropertyList: dictionary,
            format: .xml,
            options: 0
        )
        try data.write(to: url, options: .atomic)
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
}

/// Normalizes caller-provided app-group identifiers while preserving order.
private enum AppGroupIdentifiers {
    static func normalize(_ values: [String]) -> [String] {
        var result: [String] = []
        for value in values {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, !result.contains(trimmed) else {
                continue
            }
            result.append(trimmed)
        }
        return result
    }
}

/// XML property-list helpers for entitlement dictionaries.
private enum EntitlementPlist {
    static func dictionary(fromXML xml: String) throws -> [String: Any] {
        let trimmed = xml.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return [:]
        }
        do {
            let data = Data(trimmed.utf8)
            let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            guard let dictionary = plist as? [String: Any] else {
                throw RorkSignError.invalidEntitlements("Entitlement plist must contain a dictionary.")
            }
            return dictionary
        } catch let error as RorkSignError {
            throw error
        } catch {
            throw RorkSignError.invalidEntitlements("Entitlement plist could not be parsed.")
        }
    }

    static func xml(from dictionary: [String: Any]) throws -> String {
        do {
            let data = try PropertyListSerialization.data(
                fromPropertyList: dictionary,
                format: .xml,
                options: 0
            )
            return String(decoding: data, as: UTF8.self)
        } catch {
            throw RorkSignError.invalidEntitlements("Entitlement plist could not be serialized.")
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
    let rootPath = rootURL.standardizedFileURL.path
    let path = url.standardizedFileURL.path
    guard path.hasPrefix(rootPath + "/") else {
        throw RorkSignError.invalidBundle("Path escaped bundle root: \(path).")
    }
    return String(path.dropFirst(rootPath.count + 1))
}
