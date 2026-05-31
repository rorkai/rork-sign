import Foundation

/// Coordinates bundle signing in the same inside-out order Apple tooling expects.
///
/// A bundle signature is not just the executable signature. Nested bundles must
/// be signed first, then the parent bundle's resources are sealed, and only then
/// can the parent executable hash that resource seal into its CodeDirectory.
/// Keeping that order centralized makes the public API small while making tests
/// able to assert the exact signing sequence.
enum BundleSigner {
    /// Signs `bundleURL` with ad-hoc Mach-O signatures.
    ///
    /// The implementation supports application-style bundles and nested
    /// `.app`, `.appex`, `.bundle`, `.framework`, and `.xpc` bundles. It also
    /// signs standalone Mach-O files found inside a bundle before resource
    /// sealing so helper tools and dylibs are protected by the parent seal.
    static func signAdHoc(bundleURL: URL, options: BundleSigningOptions) throws -> BundleSigningReport {
        var context = BundleSigningContext(options: options)
        try signBundle(
            bundleURL,
            isRoot: true,
            options: options,
            signingMode: .adHoc,
            context: &context
        )
        return BundleSigningReport(
            sealedBundles: context.sealedBundles,
            embeddedProvisioningProfiles: context.embeddedProvisioningProfiles,
            signedCode: context.signedCode,
            cachedCode: context.cachedCode
        )
    }

    /// Signs `bundleURL` with identity-backed CMS signatures.
    static func signWithIdentity(
        bundleURL: URL,
        identity: SigningIdentity,
        options: BundleSigningOptions
    ) throws -> BundleSigningReport {
        var context = BundleSigningContext(
            options: options,
            profileValidationPolicy: .strictBundleIdentifier
        )
        try signBundle(
            bundleURL,
            isRoot: true,
            options: options,
            signingMode: .identity(identity),
            context: &context
        )
        return BundleSigningReport(
            sealedBundles: context.sealedBundles,
            embeddedProvisioningProfiles: context.embeddedProvisioningProfiles,
            signedCode: context.signedCode,
            cachedCode: context.cachedCode
        )
    }

    /// Signs `bundleURL` with a credential/profile pair while preserving IDs.
    ///
    /// This folder-signing flow lets the profile authorize the signing
    /// certificate and supply entitlement material while callers choose whether
    /// to embed it. When the profile is not embedded, the bundle identifier
    /// check is skipped so hosts can sign guest bundles that keep their
    /// original identifiers.
    static func signWithCredential(
        bundleURL: URL,
        identity: SigningIdentity,
        options: BundleSigningOptions
    ) throws -> BundleSigningReport {
        var context = BundleSigningContext(
            options: options,
            profileValidationPolicy: options.embedProvisioningProfiles
                ? .strictBundleIdentifier
                : .certificateOnly
        )
        try signBundle(
            bundleURL,
            isRoot: true,
            options: options,
            signingMode: .identity(identity),
            context: &context
        )
        return BundleSigningReport(
            sealedBundles: context.sealedBundles,
            embeddedProvisioningProfiles: context.embeddedProvisioningProfiles,
            signedCode: context.signedCode,
            cachedCode: context.cachedCode
        )
    }

    /// Recursively signs one bundle. Nested bundles are fully completed before
    /// the current bundle writes its CodeResources plist.
    private static func signBundle(
        _ bundleURL: URL,
        isRoot: Bool,
        options: BundleSigningOptions,
        signingMode: BundleCodeSigningMode,
        context: inout BundleSigningContext
    ) throws {
        let bundle = try SigningBundle(url: bundleURL)
        if isRoot, bundle.executableURL == nil {
            throw RorkSignError.invalidBundle("Root bundle has no CFBundleExecutable: \(bundle.url.path).")
        }
        if isRoot {
            try BundleDylibEditor.apply(to: bundle, options: options)
        }

        for nestedBundleURL in try BundleCodeScanner.nestedBundles(in: bundle.url) {
            try signBundle(
                nestedBundleURL,
                isRoot: false,
                options: options,
                signingMode: signingMode,
                context: &context
            )
        }

        for codeURL in try BundleCodeScanner.standaloneCodeFiles(in: bundle) {
            try signCode(
                at: codeURL,
                bundleIdentifier: bundle.standaloneCodeIdentifier(for: codeURL),
                entitlementsXML: "",
                infoPlist: Data(),
                resourceDirectory: Data(),
                signingMode: signingMode,
                context: &context
            )
        }

        if let provisioningProfile = options.provisioningProfile(for: bundle, isRoot: isRoot) {
            try signingMode.validateProvisioningProfile(
                provisioningProfile,
                bundleIdentifier: try bundle.requireIdentifier(),
                requireBundleIdentifierMatch: context.profileValidationPolicy == .strictBundleIdentifier
            )
            if options.embedProvisioningProfiles {
                let embeddedProfileURL = bundle.url.appendingPathComponent("embedded.mobileprovision")
                try provisioningProfile.write(to: embeddedProfileURL, options: .atomic)
                context.embeddedProvisioningProfiles.append(embeddedProfileURL)
            }
        }
        if !options.embedProvisioningProfiles {
            try removeEmbeddedProvisioningProfile(from: bundle.url)
        }

        let codeResourcesURL = try CodeResourcesBuilder.write(bundleURL: bundle.url)
        context.sealedBundles.append(bundle.url)

        guard let executableURL = bundle.executableURL else {
            return
        }

        let codeResources = try Data(contentsOf: codeResourcesURL)
        let infoPlist = try bundle.infoPlistData()
        let originalEntitlementsXML = try originalEntitlementsXML(at: executableURL)
        try signCode(
            at: executableURL,
            bundleIdentifier: try bundle.requireIdentifier(),
            entitlementsXML: try options.entitlementsXML(
                for: bundle,
                isRoot: isRoot,
                originalEntitlementsXML: originalEntitlementsXML
            ),
            infoPlist: infoPlist,
            resourceDirectory: codeResources,
            signingMode: signingMode,
            context: &context
        )
    }

    /// Rewrites one Mach-O file in place while preserving its executable mode.
    private static func signCode(
        at url: URL,
        bundleIdentifier: String,
        entitlementsXML: String,
        infoPlist: Data,
        resourceDirectory: Data,
        signingMode: BundleCodeSigningMode,
        context: inout BundleSigningContext
    ) throws {
        let fileManager = FileManager.default
        let attributes = try fileManager.attributesOfItem(atPath: url.path)
        let input = try Data(contentsOf: url)
        let cacheKey = try context.signatureCache?.makeKey(
            input: input,
            bundleIdentifier: bundleIdentifier,
            entitlementsXML: entitlementsXML,
            infoPlist: infoPlist,
            resourceDirectory: resourceDirectory,
            signingMode: signingMode,
            codeDirectoryHashingMode: context.codeDirectoryHashingMode
        )
        if let cacheKey,
           let cached = context.signatureCache?.signedMachO(for: cacheKey) {
            try writeSignedCode(cached, to: url, originalAttributes: attributes)
            context.signedCode.append(url)
            context.cachedCode.append(url)
            return
        }

        let signed: Data
        switch signingMode {
        case .adHoc:
            signed = try RorkSigner.signMachOAdHoc(
                input,
                bundleIdentifier: bundleIdentifier,
                entitlementsXML: entitlementsXML,
                infoPlist: infoPlist,
                resourceDirectory: resourceDirectory,
                codeDirectoryHashingMode: context.codeDirectoryHashingMode
            )
        case .identity(let identity):
            signed = try RorkSigner.signMachOWithIdentity(
                input,
                bundleIdentifier: bundleIdentifier,
                identity: identity,
                entitlementsXML: entitlementsXML,
                infoPlist: infoPlist,
                resourceDirectory: resourceDirectory,
                codeDirectoryHashingMode: context.codeDirectoryHashingMode
            )
        }
        try writeSignedCode(signed, to: url, originalAttributes: attributes)
        if let cacheKey {
            context.signatureCache?.store(signed, for: cacheKey)
        }
        context.signedCode.append(url)
    }

    /// Writes signed bytes while preserving the original executable mode.
    private static func writeSignedCode(
        _ signed: Data,
        to url: URL,
        originalAttributes attributes: [FileAttributeKey: Any]
    ) throws {
        try signed.write(to: url)
        if let permissions = attributes[.posixPermissions] {
            try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
        }
    }

    /// Removes an existing embedded provisioning profile before sealing.
    ///
    /// In remove-provision mode, the profile may still drive entitlement
    /// selection and identity validation, but the bundle should not contain or
    /// seal `embedded.mobileprovision` in the final output.
    private static func removeEmbeddedProvisioningProfile(from bundleURL: URL) throws {
        let profileURL = bundleURL.appendingPathComponent("embedded.mobileprovision")
        guard FileManager.default.fileExists(atPath: profileURL.path) else {
            return
        }
        try FileManager.default.removeItem(at: profileURL)
    }

    /// Reads the current executable entitlements before the signature is replaced.
    private static func originalEntitlementsXML(at executableURL: URL) throws -> String {
        do {
            return try MachOSigner.readEntitlementsXML(Data(contentsOf: executableURL))
        } catch {
            return ""
        }
    }
}

/// Applies root-executable dylib edits before resources are sealed.
private enum BundleDylibEditor {
    static func apply(to bundle: SigningBundle, options: BundleSigningOptions) throws {
        guard !options.dylibInjections.isEmpty || !options.dylibLoadCommandsToRemove.isEmpty else {
            return
        }
        guard let executableURL = bundle.executableURL else {
            throw RorkSignError.invalidBundle("Root bundle has no executable for dylib edits: \(bundle.url.path).")
        }

        let fileManager = FileManager.default
        var executable = try Data(contentsOf: executableURL)
        if !options.dylibLoadCommandsToRemove.isEmpty {
            executable = try RorkSigner.removeDylibLoadCommands(
                from: executable,
                matching: options.dylibLoadCommandsToRemove
            )
            try removeRootDylibFiles(
                matching: options.dylibLoadCommandsToRemove,
                from: bundle.url,
                fileManager: fileManager
            )
        }

        for injection in options.dylibInjections {
            let installName = injection.installName?.trimmingCharacters(in: .whitespacesAndNewlines)
            let copiedDylibURL = try copyDylib(
                injection.sourceURL,
                into: bundle.url,
                installName: installName,
                fileManager: fileManager
            )
            executable = try RorkSigner.injectDylibLoadCommand(
                into: executable,
                path: installName?.isEmpty == false
                    ? installName!
                    : "@executable_path/\(copiedDylibURL.lastPathComponent)",
                weak: injection.weak
            )
        }
        try executable.write(to: executableURL)
    }

    private static func copyDylib(
        _ sourceURL: URL,
        into bundleURL: URL,
        installName: String?,
        fileManager: FileManager
    ) throws -> URL {
        let fileName = sourceURL.lastPathComponent.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fileName.isEmpty,
              fileName != ".",
              fileName != "..",
              !fileName.contains("/"),
              !fileName.contains("\\") else {
            throw RorkSignError.invalidBundle("Dylib file name is not safe: \(sourceURL.lastPathComponent).")
        }
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: sourceURL.path, isDirectory: &isDirectory),
              !isDirectory.boolValue else {
            throw RorkSignError.invalidBundle("Dylib file does not exist: \(sourceURL.path).")
        }
        do {
            _ = try RorkSigner.inspectMachO(Data(contentsOf: sourceURL))
        } catch {
            throw RorkSignError.invalidBundle("Dylib file is not a supported Mach-O: \(sourceURL.path).")
        }

        let destinationURL = try destinationURL(
            forSourceFileName: fileName,
            installName: installName,
            bundleURL: bundleURL
        )
        if destinationURL.standardizedFileURL.path != sourceURL.standardizedFileURL.path {
            if fileManager.fileExists(atPath: destinationURL.path) {
                var isDirectory: ObjCBool = false
                guard fileManager.fileExists(atPath: destinationURL.path, isDirectory: &isDirectory),
                      !isDirectory.boolValue else {
                    throw RorkSignError.invalidBundle("Dylib destination is a directory: \(destinationURL.path).")
                }
                try fileManager.removeItem(at: destinationURL)
            }
            try fileManager.createDirectory(
                at: destinationURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try fileManager.copyItem(at: sourceURL, to: destinationURL)
        }
        return destinationURL
    }

    /// Chooses where the copied dylib should live inside the root app.
    ///
    /// The default compatibility behavior copies to the app root. When a caller
    /// supplies an `@executable_path/...` install name, the filesystem copy
    /// follows that same bundle-relative path so dyld can resolve the load
    /// command and CodeResources seals the actual loaded file.
    private static func destinationURL(
        forSourceFileName fileName: String,
        installName: String?,
        bundleURL: URL
    ) throws -> URL {
        guard let installName,
              !installName.isEmpty,
              installName.hasPrefix("@executable_path/") else {
            return bundleURL.appendingPathComponent(fileName)
        }

        let relativePath = String(installName.dropFirst("@executable_path/".count))
        return try safeRelativeURL(for: relativePath, under: bundleURL)
    }

    /// Removes root-bundle dylib files for load commands that resolve through
    /// `@executable_path`.
    ///
    /// Copied dylib files are removed at the same time as matching
    /// root-executable load commands. Keeping that mutation before resource
    /// sealing prevents stale hook dylibs from being signed and sealed after
    /// the executable no longer loads them.
    private static func removeRootDylibFiles(
        matching installNames: [String],
        from bundleURL: URL,
        fileManager: FileManager
    ) throws {
        for installName in installNames {
            guard let relativePath = rootDylibRelativePath(forRemovalInstallName: installName) else {
                continue
            }
            let url = try safeRelativeURL(for: relativePath, under: bundleURL)
            guard fileManager.fileExists(atPath: url.path) else {
                continue
            }
            try fileManager.removeItem(at: url)
        }
    }

    /// Maps a removal argument to the copied bundle-relative file it can represent.
    private static func rootDylibRelativePath(forRemovalInstallName installName: String) -> String? {
        let trimmed = installName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("\u{0}") else {
            return nil
        }

        let relativePath: String
        if trimmed.hasPrefix("@executable_path/") {
            relativePath = String(trimmed.dropFirst("@executable_path/".count))
        } else if !trimmed.contains("/") && !trimmed.contains("\\") {
            relativePath = trimmed
        } else {
            return nil
        }

        return isSafeRelativePath(relativePath) ? relativePath : nil
    }

    /// Resolves a slash-separated path under `bundleURL` after traversal checks.
    private static func safeRelativeURL(for relativePath: String, under bundleURL: URL) throws -> URL {
        guard isSafeRelativePath(relativePath) else {
            throw RorkSignError.invalidBundle("Dylib bundle-relative path is not safe: \(relativePath).")
        }

        return relativePath
            .split(separator: "/", omittingEmptySubsequences: false)
            .reduce(bundleURL) { url, component in
                url.appendingPathComponent(String(component))
            }
    }

    /// Rejects absolute paths, traversal, empty components, backslashes, and NULs.
    private static func isSafeRelativePath(_ relativePath: String) -> Bool {
        guard !relativePath.isEmpty,
              !relativePath.hasPrefix("/"),
              !relativePath.contains("\\"),
              !relativePath.contains("\u{0}") else {
            return false
        }

        let components = relativePath.split(separator: "/", omittingEmptySubsequences: false)
        return components.allSatisfy { component in
            !component.isEmpty && component != "." && component != ".."
        }
    }
}

private struct BundleSigningContext {
    var sealedBundles: [URL] = []
    var embeddedProvisioningProfiles: [URL] = []
    var signedCode: [URL] = []
    var cachedCode: [URL] = []
    var codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible
    var profileValidationPolicy: ProvisioningProfileValidationPolicy = .strictBundleIdentifier
    var signatureCache: BundleSignatureCache?

    init(
        options: BundleSigningOptions,
        profileValidationPolicy: ProvisioningProfileValidationPolicy = .strictBundleIdentifier
    ) {
        self.codeDirectoryHashingMode = options.codeDirectoryHashingMode
        self.profileValidationPolicy = profileValidationPolicy
        self.signatureCache = options.signingCache.map { BundleSignatureCache(options: $0) }
    }
}

private enum ProvisioningProfileValidationPolicy {
    case strictBundleIdentifier
    case certificateOnly
}

enum BundleCodeSigningMode {
    case adHoc
    case identity(SigningIdentity)

    /// Validates profile/identity compatibility before embedding a profile.
    ///
    /// Ad-hoc signing is often used for synthetic fixtures and unsigned
    /// development artifacts, so it keeps treating profile bytes as opaque
    /// resources. CMS signing must be stricter: if a bundle embeds a
    /// provisioning profile, the profile must authorize the bundle identifier
    /// and the selected identity needs to be one of that profile's developer
    /// certificates, matching Apple's install-time authorization model.
    func validateProvisioningProfile(
        _ data: Data,
        bundleIdentifier: String,
        requireBundleIdentifierMatch: Bool
    ) throws {
        guard case .identity(let identity) = self else {
            return
        }

        let profile = try RorkSigner.decodeProvisioningProfile(data)
        guard !requireBundleIdentifierMatch || profile.supportsBundleIdentifier(bundleIdentifier) else {
            throw RorkSignError.invalidProvisioningProfile(
                "Provisioning profile does not authorize bundle identifier \(bundleIdentifier)."
            )
        }
        guard profile.containsDeveloperCertificate(for: identity) else {
            throw RorkSignError.invalidProvisioningProfile(
                "Signing identity is not authorized by provisioning profile for \(bundleIdentifier)."
            )
        }
    }
}

private extension BundleSigningOptions {
    /// Selects entitlements for a bundle by identifier.
    ///
    /// Explicit identifier entries always win. The root bundle then gets the
    /// caller's default entitlements when present. When the caller supplies a
    /// decodable provisioning profile but no explicit entitlements, the profile
    /// entitlement dictionary becomes the fallback because those are the
    /// capabilities Apple authorizes for the bundle. Nested bundles otherwise
    /// default to empty entitlements so frameworks do not inherit app-only
    /// capabilities by accident.
    func entitlementsXML(
        for bundle: SigningBundle,
        isRoot: Bool,
        originalEntitlementsXML: String
    ) throws -> String {
        let bundleIdentifier = try bundle.requireIdentifier()
        if let entitlementsXML = entitlementsByBundleIdentifier[bundleIdentifier] {
            return entitlementsXML
        }
        if isRoot, !defaultEntitlementsXML.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return defaultEntitlementsXML
        }
        if let data = provisioningProfile(for: bundle, isRoot: isRoot),
           let profile = try? RorkSigner.decodeProvisioningProfile(data) {
            return try BundleEntitlements.expand(
                profile: profile,
                bundleIdentifier: bundleIdentifier,
                originalEntitlementsXML: originalEntitlementsXML
            )
        }
        return isRoot ? defaultEntitlementsXML : ""
    }

    /// Returns an embedded provisioning profile for a bundle identifier.
    ///
    /// Exact per-identifier entries win for every bundle. The root fallback is
    /// used only for the app bundle currently being signed, which keeps nested
    /// frameworks and extensions from accidentally inheriting the app profile.
    func provisioningProfile(for bundle: SigningBundle, isRoot: Bool) -> Data? {
        guard let identifier = bundle.identifier else {
            return nil
        }
        if let exactProfile = provisioningProfilesByBundleIdentifier[identifier] {
            return exactProfile
        }
        return isRoot ? rootProvisioningProfile : nil
    }
}

/// Reads just enough bundle metadata for signing decisions.
///
/// This deliberately does not use `Bundle` because these bundles are often
/// being prepared off-device and should be treated as filesystem artifacts.
private struct SigningBundle {
    let url: URL
    let identifier: String?
    let executableURL: URL?

    init(url: URL) throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw RorkSignError.invalidBundle("Bundle does not exist: \(url.path).")
        }

        let info = try Self.readInfoPlist(bundleURL: url)
        self.url = url
        self.identifier = Self.nonEmptyString(info?["CFBundleIdentifier"])

        if let executableName = Self.nonEmptyString(info?["CFBundleExecutable"]) {
            guard Self.isSafeExecutableName(executableName) else {
                throw RorkSignError.invalidBundle("CFBundleExecutable is not a plain filename: \(executableName).")
            }
            let executableURL = url.appendingPathComponent(executableName)
            guard FileManager.default.fileExists(atPath: executableURL.path) else {
                throw RorkSignError.invalidBundle("Bundle executable does not exist: \(executableURL.path).")
            }
            self.executableURL = executableURL
        } else {
            self.executableURL = nil
        }

        if self.executableURL != nil, self.identifier == nil {
            throw RorkSignError.invalidBundle("Executable bundle has no CFBundleIdentifier: \(url.path).")
        }
    }

    /// Returns a bundle identifier or fails with a path-specific diagnostic.
    func requireIdentifier() throws -> String {
        guard let identifier else {
            throw RorkSignError.invalidBundle("Bundle has no CFBundleIdentifier: \(url.path).")
        }
        return identifier
    }

    /// Derives the CodeDirectory identifier for a standalone code file.
    ///
    /// Loose code inside a bundle, such as dylibs and helper binaries, is often
    /// loaded directly by dyld rather than launched as the parent app. Using the
    /// file basename keeps that signature identity local to the image instead
    /// of binding it to the parent bundle identifier.
    func standaloneCodeIdentifier(for codeURL: URL) throws -> String {
        IdentifierSanitizer.sanitize(codeURL.lastPathComponent)
    }

    /// Reads the exact `Info.plist` bytes that CodeResources omits and the main
    /// executable's CodeDirectory must bind through CSSLOT_INFOSLOT.
    func infoPlistData() throws -> Data {
        let infoURL = url.appendingPathComponent("Info.plist")
        guard FileManager.default.fileExists(atPath: infoURL.path) else {
            return Data()
        }
        return try Data(contentsOf: infoURL)
    }

    private static func readInfoPlist(bundleURL: URL) throws -> [String: Any]? {
        let infoURL = bundleURL.appendingPathComponent("Info.plist")
        guard FileManager.default.fileExists(atPath: infoURL.path) else {
            return nil
        }

        let data = try Data(contentsOf: infoURL)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = plist as? [String: Any] else {
            throw RorkSignError.invalidBundle("Info.plist is not a dictionary.")
        }
        return dictionary
    }

    private static func nonEmptyString(_ value: Any?) -> String? {
        guard let string = value as? String else {
            return nil
        }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Prevents Info.plist executable names from escaping the bundle directory.
    private static func isSafeExecutableName(_ value: String) -> Bool {
        !value.contains("/") && !value.contains("\\") && value != "." && value != ".."
    }
}

/// Finds signable code without descending into nested bundles that are signed by
/// their own recursive pass.
private enum BundleCodeScanner {
    private static let nestedBundleExtensions: Set<String> = [
        "app",
        "appex",
        "bundle",
        "framework",
        "xctest",
        "xpc",
    ]

    static func nestedBundles(in bundleURL: URL) throws -> [URL] {
        let resourceKeys: Set<URLResourceKey> = [.isDirectoryKey]
        guard let enumerator = FileManager.default.enumerator(
            at: bundleURL,
            includingPropertiesForKeys: Array(resourceKeys),
            options: []
        ) else {
            throw RorkSignError.invalidBundle("Unable to enumerate bundle: \(bundleURL.path).")
        }

        var bundles: [URL] = []
        for case let url as URL in enumerator {
            if shouldSkip(relativePath: try BundlePath.relativePath(for: url, under: bundleURL)) {
                if isDirectory(url) {
                    enumerator.skipDescendants()
                }
                continue
            }
            guard isDirectory(url), isNestedBundle(url) else {
                continue
            }
            bundles.append(url)
            enumerator.skipDescendants()
        }
        return bundles.sorted { $0.path < $1.path }
    }

    static func standaloneCodeFiles(in bundle: SigningBundle) throws -> [URL] {
        let resourceKeys: Set<URLResourceKey> = [
            .isDirectoryKey,
            .isRegularFileKey,
        ]
        guard let enumerator = FileManager.default.enumerator(
            at: bundle.url,
            includingPropertiesForKeys: Array(resourceKeys),
            options: []
        ) else {
            throw RorkSignError.invalidBundle("Unable to enumerate bundle: \(bundle.url.path).")
        }

        var codeFiles: [URL] = []
        for case let url as URL in enumerator {
            let relativePath = try BundlePath.relativePath(for: url, under: bundle.url)
            if shouldSkip(relativePath: relativePath) {
                if isDirectory(url) {
                    enumerator.skipDescendants()
                }
                continue
            }
            if isDirectory(url), isNestedBundle(url) {
                enumerator.skipDescendants()
                continue
            }
            if let executableURL = bundle.executableURL,
               url.standardizedFileURL.path == executableURL.standardizedFileURL.path {
                continue
            }

            let values = try url.resourceValues(forKeys: resourceKeys)
            guard values.isRegularFile == true, try isMachO(url) else {
                continue
            }
            codeFiles.append(url)
        }
        return codeFiles.sorted { $0.path < $1.path }
    }

    private static func isNestedBundle(_ url: URL) -> Bool {
        nestedBundleExtensions.contains(url.pathExtension.lowercased())
    }

    private static func shouldSkip(relativePath: String) -> Bool {
        let pathComponents = relativePath.split(separator: "/").map(String.init)
        return relativePath == "_CodeSignature"
            || relativePath.hasPrefix("_CodeSignature/")
            || relativePath == "SC_Info"
            || relativePath.hasPrefix("SC_Info/")
            || pathComponents.contains(where: { $0.hasSuffix(".dSYM") })
            || pathComponents.contains(where: { $0 == "_WatchKitStub" })
    }

    private static func isDirectory(_ url: URL) -> Bool {
        (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
    }

    /// Checks only the magic; full validation happens when the Mach-O is signed.
    private static func isMachO(_ url: URL) throws -> Bool {
        let handle = try FileHandle(forReadingFrom: url)
        defer {
            try? handle.close()
        }
        let magic = handle.readData(ofLength: 4)
        switch Array(magic) {
        case [0xce, 0xfa, 0xed, 0xfe],
             [0xcf, 0xfa, 0xed, 0xfe],
             [0xfe, 0xed, 0xfa, 0xce],
             [0xfe, 0xed, 0xfa, 0xcf],
             [0xca, 0xfe, 0xba, 0xbe],
             [0xca, 0xfe, 0xba, 0xbf],
             [0xbe, 0xba, 0xfe, 0xca],
             [0xbf, 0xba, 0xfe, 0xca]:
            return true
        default:
            return false
        }
    }
}

private enum BundlePath {
    /// Produces a bundle-relative path and rejects traversal outside `rootURL`.
    static func relativePath(for url: URL, under rootURL: URL) throws -> String {
        let rootPath = rootURL.standardizedFileURL.path
        let path = url.standardizedFileURL.path
        guard path.hasPrefix(rootPath + "/") else {
            throw RorkSignError.invalidBundle("Path escaped bundle root: \(path).")
        }
        return String(path.dropFirst(rootPath.count + 1))
    }
}

private enum IdentifierSanitizer {
    /// Converts a relative path into a conservative identifier suffix.
    static func sanitize(_ value: String) -> String {
        let scalars = value.unicodeScalars.map { scalar -> Character in
            if CharacterSet.alphanumerics.contains(scalar) || scalar == "." || scalar == "-" || scalar == "_" {
                return Character(scalar)
            }
            return "."
        }
        return String(scalars)
            .split(separator: ".", omittingEmptySubsequences: true)
            .joined(separator: ".")
    }
}
