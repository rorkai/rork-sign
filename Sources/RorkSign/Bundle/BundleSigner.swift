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
    static func signAdHoc(
        bundleURL: URL,
        options: BundleSigningOptions
    ) throws -> BundleSigningReport {
        var context = try BundleSigningContext(options: options)
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
        var context = try BundleSigningContext(
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
        var context = try BundleSigningContext(
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

    /// Signs one standalone `.framework` bundle with ad-hoc Mach-O signatures.
    ///
    /// This is the direct framework API used when callers already have a
    /// framework artifact and do not want to wrap it in a temporary app just to
    /// reuse app-bundle signing. The framework is still signed in the normal
    /// inside-out order, but provisioning profiles are intentionally disabled.
    static func signFrameworkAdHoc(
        frameworkURL: URL,
        options: FrameworkSigningOptions
    ) throws -> BundleSigningReport {
        try validateFrameworkURL(frameworkURL)
        return try signAdHoc(
            bundleURL: frameworkURL,
            options: options.bundleSigningOptions
        )
    }

    /// Signs one standalone `.framework` bundle with identity-backed signatures.
    ///
    /// The identity may have been created from a provisioning profile, but the
    /// profile is not embedded or used as an entitlement fallback for framework
    /// code. Framework entitlements must be explicit.
    static func signFrameworkWithIdentity(
        frameworkURL: URL,
        identity: SigningIdentity,
        options: FrameworkSigningOptions
    ) throws -> BundleSigningReport {
        try validateFrameworkURL(frameworkURL)
        return try signWithIdentity(
            bundleURL: frameworkURL,
            identity: identity,
            options: options.bundleSigningOptions
        )
    }

    /// Signs a hosted bundle with a temporary host executable and identity.
    ///
    /// This intentionally reuses the ordinary inside-out bundle signer after
    /// preparing a temporary root executable identity. The hosted transaction is
    /// responsible for restoring `Info.plist` and removing the copied stub even
    /// when signing fails.
    static func signHostedWithIdentity(
        bundleURL: URL,
        identity: SigningIdentity,
        options: HostedBundleSigningOptions
    ) throws -> BundleSigningReport {
        let transaction = try HostedBundleSigningTransaction.prepare(
            bundleURL: bundleURL,
            options: options
        )
        var signingOptions = options.bundleSigningOptions
        signingOptions.codeDirectoryIdentifier = options.hostBundleIdentifier
        let result: Result<BundleSigningReport, Error>
        do {
            var context = try BundleSigningContext(
                options: signingOptions,
                profileValidationPolicy: .strictBundleIdentifier,
                codeDirectoryIdentifiers: transaction.codeDirectoryIdentifiers
            )
            try signBundle(
                bundleURL,
                isRoot: true,
                options: signingOptions,
                signingMode: .identity(identity),
                context: &context
            )
            result = .success(
                BundleSigningReport(
                    sealedBundles: context.sealedBundles,
                    embeddedProvisioningProfiles: context.embeddedProvisioningProfiles,
                    signedCode: context.signedCode.removing(transaction.stubURL),
                    cachedCode: context.cachedCode.removing(transaction.stubURL)
                )
            )
        } catch {
            result = .failure(error)
        }

        do {
            try transaction.restore()
        } catch {
            if case .failure(let signingError) = result {
                throw signingError
            }
            throw error
        }
        return try result.get()
    }

    /// Ensures direct framework APIs are not accidentally used for app bundles.
    private static func validateFrameworkURL(_ url: URL) throws {
        guard url.pathExtension.lowercased() == "framework" else {
            throw RorkSignError.invalidBundle("Expected a .framework bundle: \(url.path).")
        }
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
            logSigningStart(
                bundle: bundle,
                signingMode: signingMode,
                options: options,
                context: context
            )
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

        let bundleEntitlementsXML = try entitlementsXML(
            for: bundle,
            isRoot: isRoot,
            options: options
        )

        for codeURL in try BundleCodeScanner.standaloneCodeFiles(in: bundle) {
            let codeDirectoryIdentifier: String
            if let explicitIdentifier = context.codeDirectoryIdentifiers.identifier(for: codeURL) {
                codeDirectoryIdentifier = explicitIdentifier
            } else {
                codeDirectoryIdentifier = try bundle.standaloneCodeIdentifier(for: codeURL)
            }
            try signCode(
                at: codeURL,
                bundleIdentifier: codeDirectoryIdentifier,
                entitlementsXML: bundleEntitlementsXML,
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
                try provisioningProfile.writeReplacingItem(
                    at: embeddedProfileURL
                )
                context.embeddedProvisioningProfiles.append(embeddedProfileURL)
                context.diagnostics.debug("embeddedProfile=\(embeddedProfileURL.path)")
            }
        }
        if !options.embedProvisioningProfiles {
            try removeEmbeddedProvisioningProfile(from: bundle.url)
        }

        let codeResourcesURL = try CodeResourcesBuilder.write(bundleURL: bundle.url)
        context.sealedBundles.append(bundle.url)
        context.diagnostics.debug("sealedBundle=\(bundle.url.path)")

        guard let executableURL = bundle.executableURL else {
            return
        }

        let codeResources = try Data(contentsOf: codeResourcesURL)
        let infoPlist = try bundle.infoPlistData()
        let codeDirectoryIdentifier: String
        if isRoot, let rootIdentifier = context.codeDirectoryIdentifiers.root {
            codeDirectoryIdentifier = rootIdentifier
        } else {
            codeDirectoryIdentifier = try bundle.requireIdentifier()
        }
        try signCode(
            at: executableURL,
            bundleIdentifier: codeDirectoryIdentifier,
            entitlementsXML: bundleEntitlementsXML,
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
            context.diagnostics.debug("cachedCode=\(url.path)")
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
        context.diagnostics.debug("signedCode=\(url.path)")
    }

    /// Emits a ZSign-shaped root bundle preflight header through SwiftLog.
    private static func logSigningStart(
        bundle: SigningBundle,
        signingMode: BundleCodeSigningMode,
        options: BundleSigningOptions,
        context: BundleSigningContext
    ) {
        context.diagnostics.info(">>> Signing: \t\(bundle.url.path) ...")
        context.diagnostics.info(">>> AppName: \t\(bundle.displayName)")
        context.diagnostics.info(">>> BundleId: \t\(context.codeDirectoryIdentifiers.root ?? bundle.identifier ?? "-")")
        context.diagnostics.info(">>> Version: \t\(bundle.version)")
        context.diagnostics.info(">>> TeamId: \t\(signingMode.diagnosticsTeamIdentifier)")
        context.diagnostics.info(">>> SubjectCN: \t\(signingMode.diagnosticsSubjectCommonName)")
        context.diagnostics.info(">>> ReadCache: \t\(options.signingCache?.readExistingEntries == true ? "YES" : "NO")")
    }

    /// Writes signed bytes while preserving the original executable mode.
    private static func writeSignedCode(
        _ signed: Data,
        to url: URL,
        originalAttributes attributes: [FileAttributeKey: Any]
    ) throws {
        try signed.write(to: url)
        if let permissions = restorablePOSIXPermissions(in: attributes) {
            try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
        }
    }

    /// Returns permissions that can be restored after rewriting an executable.
    ///
    /// WASI Foundation reports `0` when its filesystem cannot represent POSIX
    /// permissions. Treating that sentinel as real metadata would make browser
    /// signing fail while attempting an unsupported attribute update.
    static func restorablePOSIXPermissions(
        in attributes: [FileAttributeKey: Any]
    ) -> NSNumber? {
        guard
            let permissions = attributes[.posixPermissions] as? NSNumber,
            permissions.intValue != 0
        else {
            return nil
        }
        return permissions
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

    /// Selects the entitlement XML that should be written to code in `bundle`.
    ///
    /// Identifier-less bundles cannot be matched against explicit entitlement or
    /// provisioning-profile rules, so they intentionally get no entitlement
    /// payload. Bundles with identifiers may use their executable's current
    /// entitlement slot as input when expanding provisioning-profile values.
    private static func entitlementsXML(
        for bundle: SigningBundle,
        isRoot: Bool,
        options: BundleSigningOptions
    ) throws -> String {
        guard bundle.identifier != nil else {
            return ""
        }
        return try options.entitlementsXML(
            for: bundle,
            isRoot: isRoot,
            originalEntitlementsXML: originalExecutableEntitlementsXML(for: bundle)
        )
    }

    /// Reads the bundle executable's current entitlement slot when one exists.
    private static func originalExecutableEntitlementsXML(for bundle: SigningBundle) throws -> String {
        guard let executableURL = bundle.executableURL else {
            return ""
        }
        return try originalEntitlementsXML(at: executableURL)
    }
}

/// Adapts framework-specific options to the shared recursive bundle signer.
private extension FrameworkSigningOptions {
    /// Maps framework-specific options onto the shared bundle signer.
    ///
    /// The shared signer owns the ordering and CodeResources machinery. This
    /// adapter deliberately omits provisioning profiles so a framework cannot
    /// inherit root app entitlements or seal an `embedded.mobileprovision` file
    /// by accident.
    var bundleSigningOptions: BundleSigningOptions {
        BundleSigningOptions(
            defaultEntitlementsXML: entitlementsXML,
            embedProvisioningProfiles: false,
            codeDirectoryIdentifier: codeDirectoryIdentifier,
            codeDirectoryHashingMode: codeDirectoryHashingMode,
            signingCache: signingCache,
            diagnostics: diagnostics
        )
    }
}

/// Resolves explicit CodeDirectory identifiers for a recursive signing pass.
private struct CodeDirectoryIdentifiers {
    /// Explicit identifier for the root executable, when one is required.
    private(set) var root: String?

    /// Explicit identifiers for code files that cannot use their default identity.
    private let overrides: [URL: String]

    /// Creates a set of explicit CodeDirectory identifiers.
    init(overrides: [URL: String] = [:]) {
        root = nil
        self.overrides = overrides.reduce(into: [:]) { result, entry in
            result[entry.key.standardizedFileURL] = entry.value
        }
    }

    /// Sets the root identifier supplied through bundle options.
    mutating func setRoot(to identifier: String) throws {
        let normalizedIdentifier = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedIdentifier.isEmpty else {
            throw RorkSignError.invalidBundle("CodeDirectory identifier is empty.")
        }
        guard !normalizedIdentifier.contains("\u{0}") else {
            throw RorkSignError.invalidBundle("CodeDirectory identifier contains a NUL character.")
        }
        root = normalizedIdentifier
    }

    /// Returns the explicit identifier for a code file, when configured.
    func identifier(for codeURL: URL) -> String? {
        overrides[codeURL.standardizedFileURL]
    }
}

/// Manages the temporary filesystem mutations needed by hosted signing.
///
/// The signer needs a host-shaped root executable signature, while the final
/// guest bundle must keep its original `Info.plist`. This transaction captures
/// the exact original plist bytes, copies the host executable under a safe
/// temporary name, writes the temporary host identity, and later restores the
/// bundle to its public shape.
private struct HostedBundleSigningTransaction {
    /// Location of the bundle Info.plist mutated during hosted signing.
    let infoPlistURL: URL

    /// Exact Info.plist bytes restored after hosted signing.
    let originalInfoPlistData: Data

    /// Explicit CodeDirectory identifiers required during the signing pass.
    let codeDirectoryIdentifiers: CodeDirectoryIdentifiers

    /// Temporary host executable copied into the guest bundle.
    let stubURL: URL

    /// Prepares the bundle for a hosted signing pass.
    static func prepare(
        bundleURL: URL,
        options: HostedBundleSigningOptions
    ) throws -> HostedBundleSigningTransaction {
        let fileManager = FileManager.default
        try validateBundleDirectory(bundleURL, fileManager: fileManager)

        let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
        guard fileManager.fileExists(atPath: infoPlistURL.path) else {
            throw RorkSignError.invalidBundle("Bundle Info.plist does not exist: \(infoPlistURL.path).")
        }
        let originalInfoPlistData = try Data(contentsOf: infoPlistURL)
        let originalInfo = try readInfoPlist(originalInfoPlistData)
        let originalExecutableName = try requirePlainFilename(
            originalInfo["CFBundleExecutable"],
            key: "CFBundleExecutable"
        )
        let originalExecutableURL = bundleURL.appendingPathComponent(originalExecutableName)
        _ = try requireBundleIdentifier(originalInfo["CFBundleIdentifier"], key: "CFBundleIdentifier")

        let stubExecutableName = try requirePlainFilename(
            options.stubExecutableName,
            key: "stubExecutableName"
        )
        guard stubExecutableName != originalExecutableName else {
            throw RorkSignError.invalidBundle("Hosted signing stub must not replace the original executable.")
        }
        let hostBundleIdentifier = try requireBundleIdentifier(
            options.hostBundleIdentifier,
            key: "hostBundleIdentifier"
        )

        try validateHostExecutable(options.hostExecutableURL, fileManager: fileManager)
        let stubURL = bundleURL.appendingPathComponent(stubExecutableName)
        guard options.hostExecutableURL.standardizedFileURL.path != stubURL.standardizedFileURL.path else {
            throw RorkSignError.invalidBundle("Host executable already points at the hosted signing stub.")
        }

        let transaction = HostedBundleSigningTransaction(
            infoPlistURL: infoPlistURL,
            originalInfoPlistData: originalInfoPlistData,
            codeDirectoryIdentifiers: CodeDirectoryIdentifiers(
                overrides: [
                    originalExecutableURL: hostBundleIdentifier
                ]
            ),
            stubURL: stubURL
        )

        do {
            if fileManager.fileExists(atPath: stubURL.path) {
                var isDirectory: ObjCBool = false
                guard fileManager.fileExists(atPath: stubURL.path, isDirectory: &isDirectory),
                      !isDirectory.boolValue else {
                    throw RorkSignError.invalidBundle("Hosted signing stub destination is a directory: \(stubURL.path).")
                }
                try fileManager.removeItem(at: stubURL)
            }
            try fileManager.copyItem(at: options.hostExecutableURL, to: stubURL)

            var temporaryInfo = originalInfo
            temporaryInfo["CFBundleExecutable"] = stubExecutableName
            temporaryInfo["CFBundleIdentifier"] = hostBundleIdentifier
            let temporaryInfoData = try PropertyListWriter.data(
                from: temporaryInfo,
                format: .binary
            )
            try temporaryInfoData.writeReplacingItem(at: infoPlistURL)
        } catch {
            try? transaction.restore()
            throw error
        }

        return transaction
    }

    /// Restores the original `Info.plist` bytes and removes the temporary stub.
    func restore() throws {
        let fileManager = FileManager.default
        var firstError: Error?
        do {
            try originalInfoPlistData.writeReplacingItem(at: infoPlistURL)
        } catch {
            firstError = error
        }
        if fileManager.fileExists(atPath: stubURL.path) {
            do {
                try fileManager.removeItem(at: stubURL)
            } catch {
                if firstError == nil {
                    firstError = error
                }
            }
        }
        if let firstError {
            throw firstError
        }
    }

    /// Ensures the target is an existing bundle directory.
    private static func validateBundleDirectory(_ bundleURL: URL, fileManager: FileManager) throws {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: bundleURL.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            throw RorkSignError.invalidBundle("Bundle does not exist: \(bundleURL.path).")
        }
    }

    /// Parses the root Info.plist into a mutable dictionary.
    private static func readInfoPlist(_ data: Data) throws -> [String: Any] {
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = plist as? [String: Any] else {
            throw RorkSignError.invalidBundle("Info.plist is not a dictionary.")
        }
        return dictionary
    }

    /// Reads and validates a plain file name from a plist or option value.
    private static func requirePlainFilename(_ value: Any?, key: String) throws -> String {
        guard let string = value as? String else {
            throw RorkSignError.invalidBundle("\(key) must be a string.")
        }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed != ".",
              trimmed != "..",
              !trimmed.contains("/"),
              !trimmed.contains("\\"),
              !trimmed.contains("\u{0}") else {
            throw RorkSignError.invalidBundle("\(key) is not a plain filename: \(string).")
        }
        return trimmed
    }

    /// Reads and validates the bundle identifier used during hosted signing.
    private static func requireBundleIdentifier(_ value: Any?, key: String) throws -> String {
        guard let string = value as? String else {
            throw RorkSignError.invalidBundle("\(key) must be a string.")
        }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.contains("/"),
              !trimmed.contains("\\"),
              !trimmed.contains("\u{0}") else {
            throw RorkSignError.invalidBundle("\(key) is not a valid bundle identifier: \(string).")
        }
        return trimmed
    }

    /// Verifies the host stub source exists and is a supported Mach-O file.
    private static func validateHostExecutable(_ url: URL, fileManager: FileManager) throws {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory),
              !isDirectory.boolValue else {
            throw RorkSignError.invalidBundle("Host executable does not exist: \(url.path).")
        }
        do {
            _ = try RorkSigner.inspectMachO(Data(contentsOf: url))
        } catch {
            throw RorkSignError.invalidBundle("Host executable is not a supported Mach-O: \(url.path).")
        }
    }
}

/// Adds report filtering used when temporary hosted-signing code is removed.
private extension Array where Element == URL {
    /// Removes one URL using standardized filesystem paths for comparison.
    func removing(_ removedURL: URL) -> [URL] {
        let removedPath = removedURL.standardizedFileURL.path
        return filter { url in
            url.standardizedFileURL.path != removedPath
        }
    }
}

/// Applies root-executable dylib edits before resources are sealed.
private enum BundleDylibEditor {
    /// Applies requested root-executable load-command and dylib-file mutations.
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

    /// Validates and copies one injected dylib into its bundle-relative destination.
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

/// Mutable report, policy, cache, and diagnostics state for one recursive pass.
private struct BundleSigningContext {
    /// Bundles whose CodeResources files were written during this pass.
    var sealedBundles: [URL] = []

    /// Provisioning profiles embedded during this pass.
    var embeddedProvisioningProfiles: [URL] = []

    /// Mach-O files signed during this pass.
    var signedCode: [URL] = []

    /// Signed Mach-O files restored from the persistent cache.
    var cachedCode: [URL] = []

    /// CodeDirectory digest layout applied to signed Mach-O files.
    var codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible

    /// Bundle-identifier validation applied to provisioning profiles.
    var profileValidationPolicy: ProvisioningProfileValidationPolicy = .strictBundleIdentifier

    /// Explicit CodeDirectory identifiers applied during this signing pass.
    let codeDirectoryIdentifiers: CodeDirectoryIdentifiers

    /// Optional persistent cache for signed Mach-O outputs.
    var signatureCache: BundleSignatureCache?

    /// Opt-in signing diagnostics sink.
    var diagnostics: SigningDiagnostics = .disabled

    /// Creates one mutable signing context for a recursive bundle pass.
    init(
        options: BundleSigningOptions,
        profileValidationPolicy: ProvisioningProfileValidationPolicy = .strictBundleIdentifier,
        codeDirectoryIdentifiers: CodeDirectoryIdentifiers = CodeDirectoryIdentifiers()
    ) throws {
        self.codeDirectoryHashingMode = options.codeDirectoryHashingMode
        self.profileValidationPolicy = profileValidationPolicy
        var resolvedIdentifiers = codeDirectoryIdentifiers
        if let rootIdentifier = options.codeDirectoryIdentifier {
            try resolvedIdentifiers.setRoot(to: rootIdentifier)
        }
        self.codeDirectoryIdentifiers = resolvedIdentifiers
        self.signatureCache = options.signingCache.map { BundleSignatureCache(options: $0) }
        self.diagnostics = options.diagnostics
    }
}

/// Controls whether profile validation also enforces the bundle identifier.
private enum ProvisioningProfileValidationPolicy {
    /// Requires both certificate authorization and bundle-identifier coverage.
    case strictBundleIdentifier

    /// Requires certificate authorization while preserving arbitrary bundle IDs.
    case certificateOnly
}

enum BundleCodeSigningMode {
    case adHoc
    case identity(SigningIdentity)

    /// Team identifier reported in signing diagnostics.
    var diagnosticsTeamIdentifier: String {
        switch self {
        case .adHoc:
            return "AdHoc"
        case .identity(let identity):
            let teamIdentifier = identity.teamIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
            return teamIdentifier.isEmpty ? "-" : teamIdentifier
        }
    }

    /// Certificate common name reported in signing diagnostics.
    var diagnosticsSubjectCommonName: String {
        switch self {
        case .adHoc:
            return "AdHoc"
        case .identity(let identity):
            let subjectCommonName = identity.subjectCommonName.trimmingCharacters(in: .whitespacesAndNewlines)
            return subjectCommonName.isEmpty ? "-" : subjectCommonName
        }
    }

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

/// Resolves shared entitlements and provisioning-profile options per bundle.
private extension BundleSigningOptions {
    /// Selects entitlements for a bundle by identifier.
    ///
    /// Explicit identifier entries always win. The root bundle then gets the
    /// caller's default entitlements when present. When the caller supplies a
    /// decodable provisioning profile but no explicit entitlements, the profile
    /// entitlement dictionary becomes the fallback because those are the
    /// capabilities Apple authorizes for the bundle. Nested bundles otherwise
    /// default to no entitlement payload so frameworks do not inherit app-only
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
    /// Filesystem URL of the bundle being signed.
    let url: URL

    /// Bundle identifier read from Info.plist, when present.
    let identifier: String?

    /// Main executable URL derived from Info.plist, when present.
    let executableURL: URL?

    /// Human-readable bundle name used in diagnostics.
    let displayName: String

    /// Bundle version used in diagnostics.
    let version: String

    /// Reads and validates the signing metadata for one filesystem bundle.
    init(url: URL) throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw RorkSignError.invalidBundle("Bundle does not exist: \(url.path).")
        }

        let info = try Self.readInfoPlist(bundleURL: url)
        self.url = url
        self.identifier = Self.nonEmptyString(info?["CFBundleIdentifier"])
        self.displayName = Self.nonEmptyString(info?["CFBundleDisplayName"])
            ?? Self.nonEmptyString(info?["CFBundleName"])
            ?? url.deletingPathExtension().lastPathComponent
        self.version = Self.nonEmptyString(info?["CFBundleShortVersionString"])
            ?? Self.nonEmptyString(info?["CFBundleVersion"])
            ?? "-"

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

    /// Reads an optional bundle Info.plist dictionary.
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

    /// Returns a trimmed non-empty string from an untyped plist value.
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
    /// Bundle extensions that receive their own recursive signing pass.
    private static let nestedBundleExtensions: Set<String> = [
        "app",
        "appex",
        "bundle",
        "framework",
        "xctest",
        "xpc",
    ]

    /// Finds nested bundles without descending into their contents.
    static func nestedBundles(in bundleURL: URL) throws -> [URL] {
        var bundles: [URL] = []
        try FileManager.default.enumerateDescendants(of: bundleURL) { entry in
            let relativePath = try BundlePath.relativePath(
                for: entry.url,
                under: bundleURL
            )
            if shouldSkip(relativePath: relativePath) {
                return entry.kind == .directory
                    ? .skipDescendants
                    : .visitDescendants
            }
            guard
                entry.kind == .directory,
                isNestedBundle(entry.url)
            else {
                return .visitDescendants
            }
            bundles.append(entry.url)
            return .skipDescendants
        }
        return bundles.sorted { $0.path < $1.path }
    }

    /// Finds loose Mach-O files owned by the current bundle.
    static func standaloneCodeFiles(in bundle: SigningBundle) throws -> [URL] {
        var codeFiles: [URL] = []
        try FileManager.default.enumerateDescendants(of: bundle.url) { entry in
            let relativePath = try BundlePath.relativePath(
                for: entry.url,
                under: bundle.url
            )
            if shouldSkip(relativePath: relativePath) {
                return entry.kind == .directory
                    ? .skipDescendants
                    : .visitDescendants
            }
            if entry.kind == .directory, isNestedBundle(entry.url) {
                return .skipDescendants
            }
            if let executableURL = bundle.executableURL,
               entry.url.standardizedFileURL.path
                == executableURL.standardizedFileURL.path {
                return .visitDescendants
            }

            guard
                entry.kind == .regularFile,
                try MachOFile.isMachO(at: entry.url)
            else {
                return .visitDescendants
            }
            codeFiles.append(entry.url)
            return .visitDescendants
        }
        return codeFiles.sorted { $0.path < $1.path }
    }

    /// Returns whether a directory extension identifies a nested bundle.
    private static func isNestedBundle(_ url: URL) -> Bool {
        nestedBundleExtensions.contains(url.pathExtension.lowercased())
    }

    /// Returns whether scanner traversal should ignore a bundle-relative path.
    private static func shouldSkip(relativePath: String) -> Bool {
        let pathComponents = relativePath.split(separator: "/").map(String.init)
        return relativePath == "_CodeSignature"
            || relativePath.hasPrefix("_CodeSignature/")
            || relativePath == "SC_Info"
            || relativePath.hasPrefix("SC_Info/")
            || pathComponents.contains(where: { $0.hasSuffix(".dSYM") })
            || pathComponents.contains(where: { $0 == "_WatchKitStub" })
    }
}

/// Identifies Mach-O files without performing full structural validation.
enum MachOFile {
    /// Checks only the leading magic because complete validation belongs to the
    /// signing or inspection operation that later consumes the file.
    static func isMachO(at url: URL) throws -> Bool {
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

/// Provides traversal-safe bundle-relative path handling.
private enum BundlePath {
    /// Produces a bundle-relative path and rejects traversal outside `rootURL`.
    static func relativePath(for url: URL, under rootURL: URL) throws -> String {
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
}

/// Converts loose-code file names into conservative CodeDirectory identifiers.
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
