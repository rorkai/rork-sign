import ArgumentParser
import Foundation
import Logging
import RorkSign

/// Bridges ZSign-style root command options to the library API.
///
/// The CLI intentionally uses swift-argument-parser for the compatibility
/// surface instead of parsing `CommandLine.arguments` by hand. This type only
/// performs semantic routing after `RorkSignCommand` has already decoded typed
/// flags and options.
struct ZSignCompatibleRunner {
    /// Parsed root command options.
    let command: ZSignOptions

    /// Executes the compatibility command for one positional input path.
    func run(inputPath: String) async throws {
        try validateUnsupportedOptions()

        let inputURL = fileURL(inputPath)
        guard FileManager.default.fileExists(atPath: inputURL.path) else {
            throw ValidationError("Invalid input path: \(inputURL.path)")
        }

        if isCertificateCheckOnlyCommand {
            try await checkCertificateInput(at: inputURL)
            return
        }

        try printSigningPreflightIfRequested()

        if isMetadataOnlyCommand {
            try extractMetadata(from: inputURL)
            return
        }

        if try isDirectory(inputURL) {
            try signDirectory(at: inputURL)
        } else if isIPAArchive(inputURL) {
            try signIPA(at: inputURL)
        } else {
            try signOrInspectMachO(at: inputURL)
        }
    }

    /// Validates compatibility options that need semantic checks after parsing.
    private func validateUnsupportedOptions() throws {
        if let zipLevel = command.zipLevel, !(0...9).contains(zipLevel) {
            throw ValidationError("Invalid zip level. Use a value from 0 through 9.")
        }
        if command.onlineOCSP && !command.checkCertificate {
            throw ValidationError("--online-ocsp requires -C/--check.")
        }
        _ = try temporaryDirectory()
    }

    /// Returns true when `-C` should inspect the input instead of signing it.
    private var isCertificateCheckOnlyCommand: Bool {
        command.checkCertificate
            && !hasSigningOrRewriteWork
            && command.metadataDirectoryPath == nil
    }

    /// Returns true when the command should only emit metadata output.
    private var isMetadataOnlyCommand: Bool {
        command.metadataDirectoryPath != nil && !hasSigningOrRewriteWork
    }

    /// Returns true when parsed options request signing or artifact mutation.
    private var hasSigningOrRewriteWork: Bool {
        command.adHoc
            || command.certificatePath != nil
            || command.credentialPath != nil
            || !command.provisioningProfilePaths.isEmpty
            || command.bundleIdentifier != nil
            || command.displayName != nil
            || command.bundleVersion != nil
            || command.entitlementsPath != nil
            || command.outputPath != nil
            || !command.dylibPaths.isEmpty
            || !command.dylibLoadCommandsToRemove.isEmpty
            || command.sha256Only
            || command.removeProvisioningProfiles
            || command.enableDocuments
            || command.minimumOSVersion != nil
            || command.hasBundledEntitlementsResource
            || command.removeExtensions
            || command.removeWatchApps
            || command.removeUISupportedDevices
            || command.install
    }

    /// Signs an IPA and optionally writes post-sign metadata.
    private func signIPA(at inputURL: URL) throws {
        let output = try outputArchiveURL()
        defer {
            if output.removeAfterInstall {
                try? FileManager.default.removeItem(at: output.url)
            }
        }

        let report: IPAArchiveSigningReport
        if try shouldUseAppSigning(for: inputURL) {
            report = try signAppIPA(inputURL: inputURL, outputURL: output.url)
        } else if let identity = try signingIdentity() {
            report = try RorkSigner.signIPAWithIdentity(
                at: inputURL,
                outputURL: output.url,
                identity: identity,
                options: try bundleSigningOptions(),
                archiveCompressionMode: archiveCompressionMode,
                temporaryDirectory: try temporaryDirectory()
            )
        } else {
            report = try RorkSigner.signIPAAdHoc(
                at: inputURL,
                outputURL: output.url,
                options: try bundleSigningOptions(),
                archiveCompressionMode: archiveCompressionMode,
                temporaryDirectory: try temporaryDirectory()
            )
        }

        try writeMetadataIfRequested(from: output.url)
        try writeDebugArtifactsIfRequested(fromSignedIPA: output.url, signedCodePaths: report.signedCodePaths)
        printReport(report)
        try printPostSigningCheckIfRequested(forSignedIPA: output.url)
        try installIfRequested(output.url)
    }

    /// Signs an app bundle or extracted IPA directory.
    private func signDirectory(at inputURL: URL) throws {
        let directoryInput = try resolveDirectoryInput(inputURL)

        let report: BundleSigningReport
        if try shouldUseAppSigning(for: directoryInput.bundleURL) {
            report = try signAppBundle(bundleURL: directoryInput.bundleURL)
        } else if let identity = try signingIdentity() {
            report = try RorkSigner.signBundleWithIdentity(
                at: directoryInput.bundleURL,
                identity: identity,
                options: try bundleSigningOptions()
            )
        } else {
            report = try RorkSigner.signBundleAdHoc(
                at: directoryInput.bundleURL,
                options: try bundleSigningOptions()
            )
        }

        let archiveOutput = try optionalOutputArchiveURL()
        defer {
            if archiveOutput?.removeAfterInstall == true, let outputURL = archiveOutput?.url {
                try? FileManager.default.removeItem(at: outputURL)
            }
        }

        if let archiveOutput {
            let archiveRoot = try archiveRootForDirectoryOutput(directoryInput)
            defer {
                if archiveRoot.removeAfterUse {
                    try? FileManager.default.removeItem(at: archiveRoot.url)
                }
            }
            try writeArchive(archiveRoot: archiveRoot.url, outputURL: archiveOutput.url)
            try writeMetadataIfRequested(from: archiveOutput.url)
            try writeDebugArtifactsIfRequested(fromSignedCode: report.signedCode.last)
            printReport(report)
            try printPostSigningCheckIfRequested(forSignedBundle: directoryInput.bundleURL)
            try installIfRequested(archiveOutput.url)
        } else {
            try writeMetadataIfRequested(from: directoryInput.bundleURL)
            try writeDebugArtifactsIfRequested(fromSignedCode: report.signedCode.last)
            printReport(report)
            try printPostSigningCheckIfRequested(forSignedBundle: directoryInput.bundleURL)
        }
    }

    /// Rewrites, signs, or inspects a single Mach-O file.
    private func signOrInspectMachO(at inputURL: URL) throws {
        if command.install {
            throw ValidationError("Installing expects an IPA or extracted archive directory.")
        }

        var data = try Data(contentsOf: inputURL)

        if !command.dylibPaths.isEmpty {
            for installName in command.dylibPaths {
                data = try RorkSigner.injectDylibLoadCommand(
                    into: data,
                    path: installName,
                    weak: command.weakDylibInjection
                )
            }
        }

        if !command.dylibLoadCommandsToRemove.isEmpty {
            data = try RorkSigner.removeDylibLoadCommands(
                from: data,
                matching: command.dylibLoadCommandsToRemove
            )
        }

        if shouldSignSingleMachO {
            let bundleIdentifier = try bundleIdentifierForSingleMachO(at: inputURL)
            if let identity = try signingIdentity() {
                data = try RorkSigner.signMachOWithIdentity(
                    data,
                    bundleIdentifier: bundleIdentifier,
                    identity: identity,
                    entitlementsXML: try entitlementsXML(),
                    codeDirectoryHashingMode: codeDirectoryHashingMode
                )
            } else {
                data = try RorkSigner.signMachOAdHoc(
                    data,
                    bundleIdentifier: bundleIdentifier,
                    entitlementsXML: try entitlementsXML(),
                    codeDirectoryHashingMode: codeDirectoryHashingMode
                )
            }
        } else if !hasMachOLoadCommandMutation {
            let info = try RorkSigner.inspectMachO(data)
            if !command.quiet {
                print("kind=\(info.kind) fileType=\(info.fileType) architectures=\(info.architectureCount) codeSignature=\(info.hasCodeSignature)")
            }
            return
        }

        let outputURL = command.outputPath.map(fileURL) ?? inputURL
        try data.write(to: outputURL)
        try writeDebugArtifactsIfRequested(fromMachOAt: outputURL)
        try printVerboseMachOReportIfRequested(outputURL)
        if !command.quiet {
            print("signed=\(outputURL.path)")
        }
    }

    /// Returns true when single-file work changed load commands.
    private var hasMachOLoadCommandMutation: Bool {
        !command.dylibPaths.isEmpty || !command.dylibLoadCommandsToRemove.isEmpty
    }

    /// Returns true when a Mach-O file should get a new embedded signature.
    private var shouldSignSingleMachO: Bool {
        command.adHoc
            || command.certificatePath != nil
            || command.credentialPath != nil
            || !command.provisioningProfilePaths.isEmpty
            || command.entitlementsPath != nil
            || command.bundleIdentifier != nil
            || command.sha256Only
    }

    /// Signs an IPA through the app-signing pipeline.
    private func signAppIPA(inputURL: URL, outputURL: URL) throws -> IPAArchiveSigningReport {
        let options = try appSigningOptions(
            for: nil,
            fallbackBundleIdentifier: try inferredArchiveBundleIdentifierIfNeeded(inputURL)
        )
        if let identity = try signingIdentity() {
            return try RorkSigner.signIPA(
                at: inputURL,
                outputURL: outputURL,
                identity: identity,
                options: options,
                archiveCompressionMode: archiveCompressionMode,
                temporaryDirectory: try temporaryDirectory()
            )
        }
        return try RorkSigner.signIPA(
            at: inputURL,
            outputURL: outputURL,
            options: options,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: try temporaryDirectory()
        )
    }

    /// Signs an app bundle through the app-signing pipeline.
    private func signAppBundle(bundleURL: URL) throws -> BundleSigningReport {
        let options = try appSigningOptions(for: bundleURL)
        if let identity = try signingIdentity() {
            return try RorkSigner.signBundle(
                at: bundleURL,
                identity: identity,
                options: options
            )
        }
        return try RorkSigner.signBundle(
            at: bundleURL,
            options: options
        )
    }

    /// Returns app-signing options for ZSign-style bundle mutation flags.
    private func appSigningOptions(
        for bundleURL: URL?,
        fallbackBundleIdentifier: String? = nil
    ) throws -> AppSigningOptions {
        let profiles = try provisioningProfileData()
        let replacementIdentifier = try explicitBundleIdentifier
            ?? bundleURL.map { try CLISupport.readBundleIdentifier(at: $0) }
            ?? fallbackBundleIdentifier
            ?? requiredBundleIdentifier()

        return AppSigningOptions(
            bundleIdentifier: replacementIdentifier,
            rootProvisioningProfile: profiles.first,
            provisioningProfilesByBundleIdentifier: try provisioningProfilesByIdentifier(profiles),
            rootEntitlementsXML: try entitlementsXML(),
            entitlementsResourceName: command.entitlementsResourceName,
            displayName: command.displayName,
            bundleVersion: command.bundleVersion,
            minimumOSVersion: command.minimumOSVersion,
            enableDocuments: command.enableDocuments,
            removeExtensions: command.removeExtensions,
            removeWatchApps: command.removeWatchApps,
            removeUISupportedDevices: command.removeUISupportedDevices,
            embedProvisioningProfiles: !command.removeProvisioningProfiles,
            dylibInjections: try dylibInjections(),
            dylibLoadCommandsToRemove: command.dylibLoadCommandsToRemove,
            codeDirectoryHashingMode: codeDirectoryHashingMode,
            signingCache: signingCacheOptions(),
            diagnostics: signingDiagnostics()
        )
    }

    /// Returns generic bundle-signing options for preserve-identifier signing.
    private func bundleSigningOptions() throws -> BundleSigningOptions {
        let profiles = try provisioningProfileData()
        return BundleSigningOptions(
            defaultEntitlementsXML: try entitlementsXML(),
            rootProvisioningProfile: profiles.first,
            provisioningProfilesByBundleIdentifier: try provisioningProfilesByIdentifier(profiles),
            embedProvisioningProfiles: !command.removeProvisioningProfiles,
            codeDirectoryHashingMode: codeDirectoryHashingMode,
            dylibInjections: try dylibInjections(),
            dylibLoadCommandsToRemove: command.dylibLoadCommandsToRemove,
            signingCache: signingCacheOptions(),
            diagnostics: signingDiagnostics()
        )
    }

    /// Creates the optional SwiftLog diagnostics sink for verbose signing runs.
    private func signingDiagnostics() -> SigningDiagnostics {
        guard command.verbose, !command.quiet else {
            return .disabled
        }

        var logger = Logger(label: "rork-sign.signing")
        logger.logLevel = command.debug ? .debug : .info
        return SigningDiagnostics(logger: logger)
    }

    /// Returns the default ZSign-style folder signing cache configuration.
    private func signingCacheOptions() -> SigningCacheOptions {
        SigningCacheOptions(
            directoryURL: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent(".zsign_cache", isDirectory: true),
            readExistingEntries: !command.force
        )
    }

    /// Returns true when options require root bundle rewriting.
    private func shouldUseAppSigning(for inputURL: URL) throws -> Bool {
        command.bundleIdentifier != nil
            || command.displayName != nil
            || command.bundleVersion != nil
            || command.minimumOSVersion != nil
            || command.hasBundledEntitlementsResource
            || command.enableDocuments
            || command.removeExtensions
            || command.removeWatchApps
            || command.removeUISupportedDevices
    }

    /// Reads the app's existing bundle identifier when an IPA rewrite preserves it.
    ///
    /// ZSign-style metadata rewrites such as `-n` or `-r` should not require a
    /// replacement `-b` value. Directory inputs can read `Info.plist` directly;
    /// archive inputs need a short metadata extraction pass before signing.
    private func inferredArchiveBundleIdentifierIfNeeded(_ inputURL: URL) throws -> String? {
        guard explicitBundleIdentifier == nil else {
            return nil
        }
        let metadata = try RorkSigner.extractIPAMetadata(
            at: inputURL,
            temporaryDirectory: try temporaryDirectory()
        )
        let bundleIdentifier = metadata.appBundleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !bundleIdentifier.isEmpty else {
            throw RorkSignError.invalidArchive("IPA app bundle has no CFBundleIdentifier.")
        }
        return bundleIdentifier
    }

    /// Resolves a directory input to the app or extension bundle that should be signed.
    ///
    /// ZSign users commonly pass either the bundle itself, an extracted archive
    /// root, the `Payload` folder, or a wrapper directory that contains the real
    /// bundle. The resolver keeps those shapes deterministic while still
    /// rejecting ambiguous `Payload` folders with multiple top-level bundles.
    private func resolveDirectoryInput(_ inputURL: URL) throws -> DirectorySigningInput {
        if isSignableBundle(inputURL) {
            return DirectorySigningInput(
                bundleURL: inputURL,
                archiveRootURL: archiveRootContainingPayload(forBundleAt: inputURL)
            )
        }

        if let bundleURL = try payloadSignableBundle(in: inputURL.appendingPathComponent("Payload", isDirectory: true)) {
            return DirectorySigningInput(bundleURL: bundleURL, archiveRootURL: inputURL)
        }

        if inputURL.lastPathComponent == "Payload",
           let bundleURL = try payloadSignableBundle(in: inputURL) {
            return DirectorySigningInput(bundleURL: bundleURL, archiveRootURL: inputURL.deletingLastPathComponent())
        }

        if let bundleURL = try firstSignableBundle(in: inputURL) {
            return DirectorySigningInput(
                bundleURL: bundleURL,
                archiveRootURL: archiveRootContainingPayload(forBundleAt: bundleURL)
            )
        }

        throw RorkSignError.unsupported(
            "Directory signing expects an .app/.appex bundle or a folder containing one."
        )
    }

    /// Finds the single signable bundle directly under a `Payload` directory.
    private func payloadSignableBundle(in payloadURL: URL) throws -> URL? {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: payloadURL.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            return nil
        }

        let contents = try FileManager.default.contentsOfDirectory(
            at: payloadURL,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )
        let bundles = contents
            .filter { url in
                isSignableBundle(url)
            }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        guard bundles.count <= 1 else {
            throw RorkSignError.invalidArchive("Extracted archive contains multiple signable bundles in Payload.")
        }
        return bundles.first
    }

    /// Returns the archive root when a signable bundle lives under `Payload`.
    private func archiveRootContainingPayload(forBundleAt bundleURL: URL) -> URL? {
        let payloadURL = bundleURL.deletingLastPathComponent()
        guard payloadURL.lastPathComponent == "Payload" else {
            return nil
        }
        return payloadURL.deletingLastPathComponent()
    }

    /// Returns the first `.app` or `.appex` directory below a wrapper folder.
    ///
    /// The search is breadth-first and name-sorted so wrapper inputs resolve
    /// predictably across file systems. Bundle directories are terminal: once
    /// found, their children are not traversed, which keeps nested plug-ins from
    /// winning over the containing app.
    private func firstSignableBundle(in rootURL: URL) throws -> URL? {
        var pending = [rootURL]

        while !pending.isEmpty {
            let directoryURL = pending.removeFirst()
            let contents = try FileManager.default.contentsOfDirectory(
                at: directoryURL,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles]
            )
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

            for childURL in contents {
                guard childURL.lastPathComponent != "__MACOSX",
                      ((try? childURL.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true) else {
                    continue
                }

                if isSignableBundle(childURL) {
                    return childURL
                }
                pending.append(childURL)
            }
        }

        return nil
    }

    /// Returns true when a URL names a bundle format the compatibility command can sign.
    private func isSignableBundle(_ url: URL) -> Bool {
        let bundleExtension = url.pathExtension.lowercased()
        guard bundleExtension == "app" || bundleExtension == "appex" else {
            return false
        }
        return (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
    }

    /// Returns an archive root suitable for writing an IPA from directory input.
    ///
    /// Extracted archives already have `Payload/*.app` and can be zipped in
    /// place. A direct `.app` input needs a temporary archive layout, so the
    /// already-signed app bundle is copied under `Payload/` and removed after
    /// writing or installing the output IPA.
    private func archiveRootForDirectoryOutput(_ input: DirectorySigningInput) throws -> DirectoryArchiveRoot {
        if let archiveRootURL = input.archiveRootURL {
            return DirectoryArchiveRoot(url: archiveRootURL, removeAfterUse: false)
        }

        let workspaceRoot = try temporaryDirectory() ?? FileManager.default.temporaryDirectory
        try FileManager.default.createDirectory(at: workspaceRoot, withIntermediateDirectories: true)
        let archiveRootURL = workspaceRoot.appendingPathComponent(
            "rorksign-app-archive-\(UUID().uuidString)",
            isDirectory: true
        )
        let payloadURL = archiveRootURL.appendingPathComponent("Payload", isDirectory: true)
        try FileManager.default.createDirectory(at: payloadURL, withIntermediateDirectories: true)
        try FileManager.default.copyItem(
            at: input.bundleURL,
            to: payloadURL.appendingPathComponent(input.bundleURL.lastPathComponent, isDirectory: true)
        )
        return DirectoryArchiveRoot(url: archiveRootURL, removeAfterUse: true)
    }

    /// Writes an extracted archive root back to an IPA file.
    private func writeArchive(archiveRoot: URL, outputURL: URL) throws {
        do {
            try IPAArchive.write(
                contentsOf: archiveRoot,
                to: outputURL,
                compressionMode: archiveCompressionMode
            )
        } catch {
            try? FileManager.default.removeItem(at: outputURL)
            throw RorkSignError.invalidArchive("Signed IPA archive could not be written: \(error.localizedDescription)")
        }
    }

    /// Returns an IPA output path for signing work that must produce an archive.
    private func outputArchiveURL() throws -> OutputArchive {
        if let outputPath = command.outputPath {
            return OutputArchive(url: fileURL(outputPath), removeAfterInstall: false)
        }
        guard command.install else {
            throw ValidationError("Signing an IPA requires -o/--output unless -i/--install is used.")
        }
        return OutputArchive(url: try temporaryInstallArchiveURL(), removeAfterInstall: true)
    }

    /// Returns an optional IPA output path when directory signing should archive.
    private func optionalOutputArchiveURL() throws -> OutputArchive? {
        guard command.outputPath != nil || command.install else {
            return nil
        }
        return try outputArchiveURL()
    }

    /// Creates a temporary IPA path for `-i` flows that do not specify `-o`.
    private func temporaryInstallArchiveURL() throws -> URL {
        let rootURL = try temporaryDirectory() ?? FileManager.default.temporaryDirectory
        try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: true)
        return rootURL.appendingPathComponent("rorksign-install-\(UUID().uuidString).ipa")
    }

    /// Installs a signed IPA with `ideviceinstaller` when `-i` was requested.
    private func installIfRequested(_ ipaURL: URL) throws {
        guard command.install else {
            return
        }

        let installerURL = try ideviceInstallerURL()
        let process = Process()
        process.executableURL = installerURL
        process.arguments = ["install", ipaURL.path]

        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()

        let data = output.fileHandleForReading.readDataToEndOfFile()
        let message = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard process.terminationStatus == 0 else {
            throw RorkSignError.unsupported(
                message.isEmpty
                    ? "ideviceinstaller failed with status \(process.terminationStatus)."
                    : "ideviceinstaller failed with status \(process.terminationStatus): \(message)"
            )
        }

        if !command.quiet {
            print("installed=\(ipaURL.path)")
        }
    }

    /// Locates `ideviceinstaller` for ZSign-compatible `-i` installs.
    private func ideviceInstallerURL() throws -> URL {
        let environment = ProcessInfo.processInfo.environment
        if let override = environment["RORKSIGN_IDEVICEINSTALLER"],
           !override.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let url = fileURL(override)
            guard isRunnableExecutable(at: url) else {
                throw RorkSignError.unsupported("Configured ideviceinstaller is not executable: \(url.path)")
            }
            return url
        }

        let pathValue = environment["PATH"] ?? ""
        #if os(Windows)
        let pathSeparator: Character = ";"
        let executableNames = ["ideviceinstaller.exe", "ideviceinstaller"]
        #else
        let pathSeparator: Character = ":"
        let executableNames = ["ideviceinstaller"]
        #endif
        for directory in pathValue.split(separator: pathSeparator).map(String.init) {
            for executableName in executableNames {
                let url = URL(fileURLWithPath: directory)
                    .appendingPathComponent(executableName)
                if isRunnableExecutable(at: url) {
                    return url
                }
            }
        }
        throw RorkSignError.unsupported("ideviceinstaller was not found in PATH.")
    }

    /// Uses filename-based executable discovery on Windows and permission checks elsewhere.
    private func isRunnableExecutable(at url: URL) -> Bool {
        #if os(Windows)
        var isDirectory = ObjCBool(false)
        return FileManager.default.fileExists(
            atPath: url.path,
            isDirectory: &isDirectory
        ) && !isDirectory.boolValue
        #else
        return FileManager.default.isExecutableFile(atPath: url.path)
        #endif
    }

    /// Loads the signing identity requested by the compatibility options.
    private func signingIdentity() throws -> SigningIdentity? {
        guard let credentialPath = command.credentialPath else {
            return nil
        }

        let credentialURL = fileURL(credentialPath)
        let credentialData = try Data(contentsOf: credentialURL)
        if let certificatePath = command.certificatePath {
            return try CLISupport.readIdentity(
                certificatePath: certificatePath,
                credentialPath: credentialPath,
                password: command.password
            )
        }

        if let profileData = try provisioningProfileData().first {
            return try SigningIdentity(
                provisioningProfileData: profileData,
                credentialData: credentialData,
                password: command.password
            )
        }

        return try SigningIdentity(
            pkcs12Data: credentialData,
            password: command.password
        )
    }

    /// Loads provisioning-profile files in command-line order.
    private func provisioningProfileData() throws -> [Data] {
        try command.provisioningProfilePaths.map {
            try Data(contentsOf: fileURL($0))
        }
    }

    /// Builds a map for profiles with explicit application identifiers.
    private func provisioningProfilesByIdentifier(_ profiles: [Data]) throws -> [String: Data] {
        var result: [String: Data] = [:]
        for data in profiles {
            guard let identifier = try explicitBundleIdentifier(fromProvisioningProfileData: data) else {
                continue
            }
            result[identifier] = data
        }
        return result
    }

    /// Extracts a non-wildcard bundle identifier from a provisioning profile.
    private func explicitBundleIdentifier(fromProvisioningProfileData data: Data) throws -> String? {
        let profile = try RorkSigner.decodeProvisioningProfile(data)
        guard let applicationIdentifier = profile.applicationIdentifier,
              applicationIdentifier.hasPrefix(profile.teamIdentifier + ".") else {
            return nil
        }
        let identifier = String(applicationIdentifier.dropFirst(profile.teamIdentifier.count + 1))
        guard !identifier.isEmpty, !identifier.contains("*") else {
            return nil
        }
        return identifier
    }

    /// Loads an optional entitlements XML file.
    private func entitlementsXML() throws -> String {
        try CLISupport.readEntitlements(path: command.entitlementsPath)
    }

    /// Returns dylib copy/injection requests for bundle signing.
    private func dylibInjections() throws -> [BundleDylibInjection] {
        try command.dylibPaths.map { path in
            let url = fileURL(path)
            try validateDylib(at: url)
            return BundleDylibInjection(sourceURL: url, weak: command.weakDylibInjection)
        }
    }

    /// Verifies that a dylib input exists and at least parses as Mach-O.
    private func validateDylib(at url: URL) throws {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw ValidationError("Dylib file not found: \(url.path)")
        }
        _ = try RorkSigner.inspectMachO(Data(contentsOf: url))
    }

    /// Returns the CodeDirectory mode requested by CLI flags.
    private var codeDirectoryHashingMode: CodeDirectoryHashingMode {
        command.sha256Only ? .sha256Only : .compatible
    }

    /// Returns the archive compression requested by `-z/--zip_level`.
    ///
    /// The archive backend exposes stored-vs-deflated output, not numeric
    /// Deflate levels. We preserve the ZSign CLI shape by mapping level `0` to
    /// stored entries and any non-zero valid level to Deflate.
    private var archiveCompressionMode: ArchiveCompressionMode {
        switch command.zipLevel {
        case 0, nil:
            return .stored
        default:
            return .deflated
        }
    }

    /// Returns the required bundle identifier for APIs that cannot infer it.
    private func requiredBundleIdentifier() throws -> String {
        guard let bundleIdentifier = explicitBundleIdentifier else {
            throw ValidationError("Signing this input requires -b/--bundle_id.")
        }
        return bundleIdentifier
    }

    /// Returns the explicit bundle identifier after trimming empty input.
    private var explicitBundleIdentifier: String? {
        guard let bundleIdentifier = command.bundleIdentifier else {
            return nil
        }
        let trimmed = bundleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Returns the bundle identifier for a single Mach-O signing operation.
    ///
    /// ZSign commonly signs an executable inside an app bundle with commands
    /// like `-a -l @executable_path/Hook.dylib Demo.app/Demo`. In that case the
    /// bundle identifier is already available in the adjacent Info.plist, so the
    /// compatibility runner can infer it instead of requiring an extra `-b`.
    private func bundleIdentifierForSingleMachO(at executableURL: URL) throws -> String {
        if let explicitBundleIdentifier {
            return explicitBundleIdentifier
        }
        if let inferredBundleIdentifier = try bundleIdentifierContainingExecutable(executableURL) {
            return inferredBundleIdentifier
        }
        throw ValidationError("Signing this input requires -b/--bundle_id.")
    }

    /// Finds the nearest containing bundle whose declared executable is `url`.
    ///
    /// Single-file operations can target `Demo.app/Demo`,
    /// `PlugIns/Share.appex/Share`, or a framework binary directly. In those
    /// cases the surrounding `Info.plist` already names the bundle identifier,
    /// so the compatibility command should not force callers to repeat it with
    /// `-b/--bundle_id`.
    private func bundleIdentifierContainingExecutable(_ url: URL) throws -> String? {
        let normalizedExecutablePath = url.resolvingSymlinksInPath().standardizedFileURL.path
        var directory = url.deletingLastPathComponent()

        while directory.path != directory.deletingLastPathComponent().path {
            if isBundleDirectory(directory) {
                guard let executableURL = try appExecutableURL(in: directory) else {
                    return nil
                }
                let normalizedDeclaredPath = executableURL
                    .resolvingSymlinksInPath()
                    .standardizedFileURL
                    .path
                guard normalizedDeclaredPath == normalizedExecutablePath else {
                    return nil
                }
                return try appBundleIdentifier(in: directory)
            }
            directory = directory.deletingLastPathComponent()
        }
        return nil
    }

    /// Returns true when a directory is a bundle whose `Info.plist` can identify code.
    private func isBundleDirectory(_ url: URL) -> Bool {
        switch url.pathExtension.lowercased() {
        case "app", "appex", "framework", "xctest":
            return (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
        default:
            return false
        }
    }

    /// Reads a non-empty CFBundleIdentifier from one bundle Info.plist.
    private func appBundleIdentifier(in appURL: URL) throws -> String? {
        let plist = try appInfoPlist(in: appURL)
        guard let bundleIdentifier = plist["CFBundleIdentifier"] as? String else {
            return nil
        }
        let trimmed = bundleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Performs the ZSign-style `-C` input inspection flow.
    private func checkCertificateInput(at inputURL: URL) async throws {
        if try isDirectory(inputURL) {
            let directoryInput = try resolveDirectoryInput(inputURL)
            try checkAppSignatureOrEmbeddedProfile(in: directoryInput.bundleURL)
            return
        }

        if isIPAArchive(inputURL) {
            try checkIPAAppSignatureOrEmbeddedProfile(at: inputURL)
            return
        }

        switch inputURL.pathExtension.lowercased() {
        case "mobileprovision", "provisionprofile":
            printProfileReport(try RorkSigner.checkProvisioningProfile(at: inputURL))
        case "p12", "pfx":
            let credentialData = try Data(contentsOf: inputURL)
            let identity = try SigningIdentity(pkcs12Data: credentialData, password: command.password)
            printCredentialReport(
                try RorkSigner.checkPKCS12Identity(credentialData, password: command.password)
            )
            printCertificateChainValidationReport(try RorkSigner.validateCertificateChain(identity: identity))
            try await printOnlineOCSPStatusIfRequested(identity: identity)
        case "cer", "cert", "der", "pem":
            let certificateData = try Data(contentsOf: inputURL)
            printCertificateReports(try RorkSigner.checkCertificateChain(certificateData))
            printCertificateChainValidationReport(try RorkSigner.validateCertificateChain(certificateData))
            try await printOnlineOCSPStatusIfRequested(certificateChainData: certificateData)
        default:
            printMachOCodeSignatureReports(
                try RorkSigner.checkMachOCodeSignatures(at: inputURL)
            )
        }
    }

    /// Fetches and prints online OCSP status for a certificate chain when requested.
    private func printOnlineOCSPStatusIfRequested(certificateChainData: Data) async throws {
        guard command.onlineOCSP else {
            return
        }
        let report = try await RorkSigner.checkOCSPStatus(
            certificateChainData: certificateChainData,
            httpOptions: OCSPHTTPOptions(userAgent: "rorksign")
        )
        printOCSPStatusReport(report)
    }

    /// Fetches and prints online OCSP status for a signing identity when requested.
    private func printOnlineOCSPStatusIfRequested(identity: SigningIdentity) async throws {
        guard command.onlineOCSP else {
            return
        }
        let report = try await RorkSigner.checkOCSPStatus(
            identity: identity,
            httpOptions: OCSPHTTPOptions(userAgent: "rorksign")
        )
        printOCSPStatusReport(report)
    }

    /// Prints profile/credential preflight details before signing when `-C` is set.
    private func printSigningPreflightIfRequested() throws {
        guard command.checkCertificate else {
            return
        }

        if let profilePath = command.provisioningProfilePaths.first,
           let credentialPath = command.credentialPath {
            let report = try RorkSigner.checkProfileCredential(
                provisioningProfileData: Data(contentsOf: fileURL(profilePath)),
                credentialData: Data(contentsOf: fileURL(credentialPath)),
                password: command.password
            )
            printProfileCredentialReport(report)
            return
        }

        if let certificatePath = command.certificatePath,
           let credentialPath = command.credentialPath {
            let report = try RorkSigner.checkSigningIdentity(
                certificateData: Data(contentsOf: fileURL(certificatePath)),
                privateKeyData: Data(contentsOf: fileURL(credentialPath)),
                password: command.password
            )
            printCredentialReport(report)
            return
        }

        if let profilePath = command.provisioningProfilePaths.first {
            printProfileReport(
                try RorkSigner.checkProvisioningProfile(at: fileURL(profilePath))
            )
            return
        }

        if let credentialPath = command.credentialPath {
            printCredentialReport(
                try RorkSigner.checkPKCS12Identity(
                    at: fileURL(credentialPath),
                    password: command.password
                )
            )
        }
    }

    /// Prints the signed app's certificate metadata after bundle signing.
    ///
    /// ZSign treats `-C` with signing inputs as both a credential preflight and
    /// a post-sign inspection. Keeping that second step in the compatibility
    /// runner lets scripts verify the certificate actually embedded into the
    /// app that was just produced.
    private func printPostSigningCheckIfRequested(forSignedBundle appURL: URL) throws {
        guard command.checkCertificate else {
            return
        }
        try checkAppSignatureOrEmbeddedProfile(in: appURL)
    }

    /// Prints the signed app's certificate metadata after IPA signing.
    private func printPostSigningCheckIfRequested(forSignedIPA ipaURL: URL) throws {
        guard command.checkCertificate else {
            return
        }
        try checkIPAAppSignatureOrEmbeddedProfile(at: ipaURL)
    }

    /// Checks an app bundle's executable signature, falling back to its profile.
    private func checkAppSignatureOrEmbeddedProfile(in appURL: URL) throws {
        try printCodeResourcesCheckIfPresent(in: appURL)

        if let executableURL = try appExecutableURL(in: appURL) {
            let reports = try RorkSigner.checkMachOCodeSignatures(at: executableURL)
            if !reports.isEmpty {
                printMachOCodeSignatureReports(reports)
                return
            }
        }
        try checkEmbeddedProvisioningProfile(in: appURL)
    }

    /// Prints the bundle resource-seal status when the app carries one.
    ///
    /// `-C` is primarily a certificate/signature inspection flow, but a bundle
    /// signature is incomplete without the resource seal referenced by the
    /// executable's CodeDirectory. Missing CodeResources is tolerated here for
    /// parity with existing loose inspection behavior; malformed or present-but-
    /// invalid seals are reported through the verification fields.
    private func printCodeResourcesCheckIfPresent(in appURL: URL) throws {
        guard !command.quiet else {
            return
        }
        for report in try RorkSigner.verifyCodeResourcesRecursively(forBundleAt: appURL) {
            print(CLISupport.codeResourcesFields(report))
        }
    }

    /// Checks the embedded profile in one app bundle.
    private func checkEmbeddedProvisioningProfile(in appURL: URL) throws {
        let profileURL = appURL.appendingPathComponent("embedded.mobileprovision")
        guard FileManager.default.fileExists(atPath: profileURL.path) else {
            throw RorkSignError.invalidProvisioningProfile(
                "App bundle has no embedded.mobileprovision: \(appURL.path)"
            )
        }
        printProfileReport(try RorkSigner.checkProvisioningProfile(at: profileURL))
    }

    /// Extracts an IPA temporarily and checks the root app's signature/profile.
    private func checkIPAAppSignatureOrEmbeddedProfile(at archiveURL: URL) throws {
        let workspaceRoot = try certificateCheckWorkspaceRoot()
        let workspaceURL = workspaceRoot.appendingPathComponent(
            "rork-sign-check-\(UUID().uuidString)",
            isDirectory: true
        )
        defer {
            try? FileManager.default.removeItem(at: workspaceURL)
        }

        try FileManager.default.createDirectory(at: workspaceURL, withIntermediateDirectories: true)
        do {
            _ = try IPAArchive.extract(
                at: archiveURL,
                to: workspaceURL
            )
        } catch {
            throw RorkSignError.invalidArchive("IPA archive could not be extracted for certificate check.")
        }

        guard let appURL = try payloadSignableBundle(
            in: workspaceURL.appendingPathComponent("Payload", isDirectory: true)
        ) else {
            throw RorkSignError.invalidArchive("IPA archive does not contain Payload/*.app.")
        }
        try checkAppSignatureOrEmbeddedProfile(in: appURL)
    }

    /// Resolves the executable declared by an app bundle's Info.plist.
    private func appExecutableURL(in appURL: URL) throws -> URL? {
        let info = try appInfoPlist(in: appURL)
        guard let executableName = info["CFBundleExecutable"] as? String else {
            return nil
        }

        let trimmedName = executableName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            return nil
        }
        guard !trimmedName.contains("/") && !trimmedName.contains("\\") else {
            throw RorkSignError.invalidBundle("CFBundleExecutable is not a plain filename: \(trimmedName).")
        }

        let executableURL = appURL.appendingPathComponent(trimmedName)
        return FileManager.default.fileExists(atPath: executableURL.path) ? executableURL : nil
    }

    /// Reads one app bundle Info.plist as a dictionary.
    private func appInfoPlist(in appURL: URL) throws -> [String: Any] {
        let infoURL = appURL.appendingPathComponent("Info.plist")
        guard FileManager.default.fileExists(atPath: infoURL.path) else {
            return [:]
        }

        let infoData = try Data(contentsOf: infoURL)
        let plist = try PropertyListSerialization.propertyList(
            from: infoData,
            options: [],
            format: nil
        )
        return plist as? [String: Any] ?? [:]
    }

    /// Returns the root directory used for temporary certificate-check workspaces.
    private func certificateCheckWorkspaceRoot() throws -> URL {
        let rootURL = try temporaryDirectory() ?? FileManager.default.temporaryDirectory
        try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: true)
        return rootURL
    }

    /// Extracts metadata from an app bundle or IPA.
    private func extractMetadata(from inputURL: URL) throws {
        guard let metadataDirectoryPath = command.metadataDirectoryPath else {
            return
        }
        let outputDirectory = fileURL(metadataDirectoryPath)
        if isIPAArchive(inputURL) {
            let report = try RorkSigner.extractIPAMetadata(
                at: inputURL,
                outputDirectory: outputDirectory,
                temporaryDirectory: try temporaryDirectory()
            )
            printMetadataReport(report, outputDirectory: outputDirectory)
        } else if try isDirectory(inputURL) {
            let directoryInput = try resolveDirectoryInput(inputURL)
            let report = try RorkSigner.extractBundleMetadata(at: directoryInput.bundleURL, outputDirectory: outputDirectory)
            printMetadataReport(report, outputDirectory: outputDirectory)
        } else {
            throw RorkSignError.unsupported("Metadata extraction expects an app bundle, wrapper directory, or IPA archive.")
        }
    }

    /// Writes metadata after a signing operation when requested.
    private func writeMetadataIfRequested(from signedURL: URL) throws {
        guard command.metadataDirectoryPath != nil else {
            return
        }
        try extractMetadata(from: signedURL)
    }

    /// Writes `-d/--debug` artifacts from the selected signed Mach-O file.
    private func writeDebugArtifactsIfRequested(fromSignedCode signedCodeURL: URL?) throws {
        guard command.debug, let signedCodeURL else {
            return
        }
        try writeDebugArtifactsIfRequested(fromMachOAt: signedCodeURL)
    }

    /// Writes `-d/--debug` artifacts from a signed Mach-O path.
    private func writeDebugArtifactsIfRequested(fromMachOAt machOURL: URL) throws {
        guard command.debug else {
            return
        }

        let written = try CodeSignatureDebugWriter.writeArtifacts(
            from: Data(contentsOf: machOURL)
        )
        if !command.quiet {
            print("debug=\(CodeSignatureDebugWriter.defaultDirectory().path) files=\(written.count)")
        }
    }

    /// Extracts a signed IPA just long enough to dump the last signed code path.
    ///
    /// Archive signing works in a temporary workspace owned by the library, so
    /// by the time the CLI sees the report only the output archive is stable.
    /// Re-extracting the output keeps the debug path independent from the
    /// signer internals while still matching ZSign's "dump generated slots"
    /// workflow.
    private func writeDebugArtifactsIfRequested(
        fromSignedIPA ipaURL: URL,
        signedCodePaths: [String]
    ) throws {
        guard command.debug else {
            return
        }
        guard let signedCodePath = signedCodePaths.last else {
            throw RorkSignError.invalidArchive("Signed IPA report has no signed Mach-O paths for debug output.")
        }

        let workspaceRoot = try temporaryDirectory() ?? FileManager.default.temporaryDirectory
        let workspaceURL = workspaceRoot.appendingPathComponent(
            "rorksign-debug-\(UUID().uuidString)",
            isDirectory: true
        )
        defer {
            try? FileManager.default.removeItem(at: workspaceURL)
        }

        try FileManager.default.createDirectory(at: workspaceURL, withIntermediateDirectories: true)
        do {
            _ = try IPAArchive.extract(
                at: ipaURL,
                to: workspaceURL
            )
        } catch {
            throw RorkSignError.invalidArchive("Signed IPA archive could not be extracted for debug output.")
        }

        let signedCodeURL = workspaceURL.appendingPathComponent(signedCodePath)
        guard FileManager.default.fileExists(atPath: signedCodeURL.path) else {
            throw RorkSignError.invalidArchive("Signed IPA does not contain debug Mach-O path: \(signedCodePath)")
        }
        try writeDebugArtifactsIfRequested(fromMachOAt: signedCodeURL)
    }

    /// Prints a compact signing report unless quiet mode is enabled.
    private func printReport(_ report: BundleSigningReport) {
        guard !command.quiet else {
            return
        }
        print("sealed=\(report.sealedBundles.count) signed=\(report.signedCode.count)")
        printVerboseBundleReportIfRequested(report)
    }

    /// Prints a compact archive signing report unless quiet mode is enabled.
    private func printReport(_ report: IPAArchiveSigningReport) {
        guard !command.quiet else {
            return
        }
        print("app=\(report.appBundlePath) sealed=\(report.sealedBundlePaths.count) signed=\(report.signedCodePaths.count)")
        printVerboseArchiveReportIfRequested(report)
    }

    /// Prints per-path bundle details for `-V/--verbose`.
    private func printVerboseBundleReportIfRequested(_ report: BundleSigningReport) {
        guard command.verbose else {
            return
        }
        for bundleURL in report.sealedBundles {
            print("sealedBundle=\(bundleURL.path)")
        }
        for profileURL in report.embeddedProvisioningProfiles {
            print("embeddedProfile=\(profileURL.path)")
        }
        for codeURL in report.signedCode {
            print("signedCode=\(codeURL.path)")
        }
        for codeURL in report.cachedCode {
            print("cachedCode=\(codeURL.path)")
        }
    }

    /// Prints per-path IPA details for `-V/--verbose`.
    private func printVerboseArchiveReportIfRequested(_ report: IPAArchiveSigningReport) {
        guard command.verbose else {
            return
        }
        print("outputArchive=\(report.outputArchiveURL.path)")
        print("appBundle=\(report.appBundlePath)")
        for bundlePath in report.sealedBundlePaths {
            print("sealedBundle=\(bundlePath)")
        }
        for profilePath in report.embeddedProvisioningProfilePaths {
            print("embeddedProfile=\(profilePath)")
        }
        for codePath in report.signedCodePaths {
            print("signedCode=\(codePath)")
        }
        for codePath in report.cachedCodePaths {
            print("cachedCode=\(codePath)")
        }
    }

    /// Prints signed Mach-O metadata for `-V/--verbose`.
    private func printVerboseMachOReportIfRequested(_ machOURL: URL) throws {
        guard command.verbose, !command.quiet else {
            return
        }
        let info = try RorkSigner.inspectMachO(Data(contentsOf: machOURL))
        print(
            "machO=kind:\(info.kind) architectures:\(info.architectureCount) " +
                "codeSignatureOffset:\(info.codeSignatureOffset) codeSignatureSize:\(info.codeSignatureSize)"
        )
    }

    /// Prints one certificate-check report unless quiet mode is enabled.
    private func printCertificateReport(_ report: CertificateCheckReport) {
        guard !command.quiet else {
            return
        }
        print(
            certificateFields(report)
        )
    }

    /// Prints certificate-chain check reports unless quiet mode is enabled.
    private func printCertificateReports(_ reports: [CertificateCheckReport]) {
        guard !command.quiet else {
            return
        }
        if reports.count == 1, let report = reports.first {
            printCertificateReport(report)
            return
        }
        for (index, report) in reports.enumerated() {
            print("certificateIndex=\(index) " + certificateFields(report))
        }
    }

    /// Prints local certificate-chain validation unless quiet mode is enabled.
    private func printCertificateChainValidationReport(_ report: CertificateChainValidationReport) {
        guard !command.quiet else {
            return
        }
        print(
            [
                "chainValid=\(report.isLocallyValid)",
                "chainLinksValid=\(report.linksAreLocallyValid)",
                "chainCertificates=\(report.certificates.count)",
                "chainLinks=\(report.links.count)",
                "chainRootSelfSigned=\(report.terminatesInSelfSignedCertificate)",
                "chainRootCanSign=\(report.rootCanSignCertificates)",
            ].joined(separator: " ")
        )
        guard command.verbose else {
            return
        }
        for link in report.links {
            print(
                [
                    "chainLink=\(link.certificateIndex)",
                    "issuerIndex=\(link.issuerIndex)",
                    "issuerMatches=\(link.issuerSubjectMatches)",
                    "signatureVerified=\(link.signatureVerified)",
                    "issuerCanSign=\(link.issuerCanSignCertificates)",
                    "subordinateCAs=\(link.subordinateCertificateAuthorityCount)",
                    "pathLengthValid=\(link.issuerPathLengthConstraintSatisfied)",
                    "certificateValid=\(link.certificateValidAtValidationDate)",
                ].joined(separator: " ")
            )
        }
    }

    /// Prints one online OCSP status result unless quiet mode is enabled.
    private func printOCSPStatusReport(_ report: OCSPStatusCheckReport) {
        guard !command.quiet else {
            return
        }
        let matched = report.validation.matchedResponse
        print(
            [
                "ocspStatus=\(ocspStatusField(matched.certificateStatus))",
                "ocspHTTPStatus=\(report.fetch.statusCode)",
                "ocspResponder=\(report.request.responderURL?.absoluteString ?? "")",
                "ocspAuthorization=\(ocspAuthorizationField(report.validation.responderAuthorization))",
                "ocspThisUpdate=\(formattedDate(matched.thisUpdate))",
                "ocspNextUpdate=\(formattedDate(matched.nextUpdate))",
            ].joined(separator: " ")
        )
    }

    /// Prints one provisioning-profile check report unless quiet mode is enabled.
    private func printProfileReport(_ report: ProvisioningProfileCheckReport) {
        guard !command.quiet else {
            return
        }
        print(
            "profileTeam=\(report.teamIdentifier) " +
                "profileAppID=\(report.applicationIdentifier ?? "") " +
                "profileExpiration=\(formattedDate(report.expirationDate)) " +
                "profileExpired=\(report.isExpired()) " +
                "developerCertificates=\(report.developerCertificates.count)"
        )
    }

    /// Prints one signing-credential check report unless quiet mode is enabled.
    private func printCredentialReport(_ report: SigningCredentialCheckReport) {
        guard !command.quiet else {
            return
        }
        print(
            certificateFields(report.leafCertificate) + " " +
                "additionalCertificates=\(report.additionalCertificates.count)"
        )
    }

    /// Prints embedded Mach-O signing-certificate reports unless quiet mode is enabled.
    private func printMachOCodeSignatureReports(_ reports: [MachOCodeSignatureCheckReport]) {
        guard !command.quiet else {
            return
        }
        guard !reports.isEmpty else {
            print("codeSignatures=0")
            return
        }

        for report in reports {
            let certificate = report.signingCertificate
            print(
                "codeSignatureArchitecture=\(report.architectureIndex) " +
                    "codeDirectoryHashes=\(report.codeDirectoryHashesValid) " +
                    "codeDirectories=\(report.codeDirectories.count) " +
                    "cms=\(report.hasCMS) " +
                    "cmsVerified=\(report.cmsSignatureValid) " +
                    certificateFields(certificate) + " " +
                    "additionalCertificates=\(report.additionalCertificates.count)"
            )
            guard command.verbose else {
                continue
            }
            for codeDirectory in report.codeDirectories {
                print(
                    [
                        "codeDirectorySlot=\(codeDirectory.slot)",
                        "codeDirectoryIdentifier=\(codeDirectory.identifier)",
                        "codeDirectoryHash=\(codeDirectoryHashAlgorithmField(codeDirectory.hashAlgorithm))",
                        "codeDirectoryValid=\(codeDirectory.isValid)",
                        "codeSlotsValid=\(codeDirectory.codeSlotsValid)",
                        "specialSlotsValid=\(codeDirectory.specialSlotsValid)",
                        "declaredCodeSlots=\(codeDirectory.declaredCodeSlotCount)",
                        "expectedCodeSlots=\(codeDirectory.expectedCodeSlotCount)",
                    ].joined(separator: " ")
                )
            }
        }
    }

    /// Formats a CodeDirectory hash algorithm as a stable CLI value.
    private func codeDirectoryHashAlgorithmField(_ algorithm: CodeDirectoryHashAlgorithm) -> String {
        switch algorithm {
        case .sha1:
            return "sha1"
        case .sha256:
            return "sha256"
        case .unsupported(let value):
            return "unsupported:\(value)"
        }
    }

    /// Prints profile/credential compatibility unless quiet mode is enabled.
    private func printProfileCredentialReport(_ report: ProfileCredentialCheckReport) {
        guard !command.quiet else {
            return
        }
        print(
            "profileTeam=\(report.provisioningProfile.teamIdentifier) " +
                "profileAppID=\(report.provisioningProfile.applicationIdentifier ?? "") " +
                "profileExpired=\(report.provisioningProfile.isExpired()) " +
                certificateFields(report.signingCredential.leafCertificate) + " " +
                "credentialAuthorized=true"
        )
    }

    /// Prints metadata output location unless quiet mode is enabled.
    private func printMetadataReport(_ report: AppMetadataReport, outputDirectory: URL) {
        guard !command.quiet else {
            return
        }
        print("metadata=\(outputDirectory.appendingPathComponent("metadata.json").path) app=\(report.appName) bundle=\(report.appBundleIdentifier)")
    }

    /// Formats optional dates in a stable, script-friendly representation.
    private func formattedDate(_ date: Date?) -> String {
        guard let date else {
            return ""
        }
        return ISO8601DateFormatter().string(from: date)
    }

    /// Formats an OCSP certificate status as a stable CLI field.
    private func ocspStatusField(_ status: OCSPCertificateStatus) -> String {
        switch status {
        case .good:
            return "good"
        case .revoked(let revocationTime, let reason):
            let reasonField = reason.map(String.init) ?? ""
            return "revoked:\(formattedDate(revocationTime)):\(reasonField)"
        case .unknown:
            return "unknown"
        }
    }

    /// Formats responder authorization as a stable CLI field.
    private func ocspAuthorizationField(_ authorization: OCSPResponderAuthorization?) -> String {
        switch authorization {
        case .issuerCertificate:
            return "issuer"
        case .delegatedResponder:
            return "delegated"
        case nil:
            return ""
        }
    }

    /// Formats certificate metadata as stable `key=value` fields.
    private func certificateFields(_ report: CertificateCheckReport?) -> String {
        guard let report else {
            return [
                "certificateCN=",
                "certificateType=",
                "certificateOrg=",
                "certificateIssuer=",
                "certificateOCSP=",
                "certificateCRL=",
                "certificateSerial=",
                "certificateAlgorithm=",
                "certificateCA=false",
                "certificateCanSign=false",
                "certificateKeyUsage=",
                "certificateExpiration=",
                "certificateExpired=false",
            ].joined(separator: " ")
        }

        return [
            "certificateCN=\(report.subjectCommonName)",
            "certificateType=\(report.certificateKind)",
            "certificateOrg=\(report.subjectOrganizationName)",
            "certificateIssuer=\(report.issuerCommonName)",
            "certificateOCSP=\(report.ocspResponderURLs.joined(separator: ","))",
            "certificateCRL=\(report.crlDistributionPointURLs.joined(separator: ","))",
            "certificateSerial=\(report.serialNumberHex)",
            "certificateAlgorithm=\(report.keyAlgorithm)",
            "certificateCA=\(report.isCertificateAuthority)",
            "certificateCanSign=\(report.canSignCertificates)",
            "certificateKeyUsage=\(keyUsageField(report.keyUsage, hasExtension: report.hasKeyUsageExtension))",
            "certificateExpiration=\(formattedDate(report.expirationDate))",
            "certificateExpired=\(report.isExpired())",
        ].joined(separator: " ")
    }

    /// Formats X.509 KeyUsage bits as stable comma-separated CLI values.
    private func keyUsageField(_ usage: CertificateKeyUsage, hasExtension: Bool) -> String {
        guard hasExtension else {
            return ""
        }

        var values: [String] = []
        if usage.contains(.digitalSignature) {
            values.append("digitalSignature")
        }
        if usage.contains(.contentCommitment) {
            values.append("contentCommitment")
        }
        if usage.contains(.keyEncipherment) {
            values.append("keyEncipherment")
        }
        if usage.contains(.dataEncipherment) {
            values.append("dataEncipherment")
        }
        if usage.contains(.keyAgreement) {
            values.append("keyAgreement")
        }
        if usage.contains(.keyCertSign) {
            values.append("keyCertSign")
        }
        if usage.contains(.cRLSign) {
            values.append("cRLSign")
        }
        if usage.contains(.encipherOnly) {
            values.append("encipherOnly")
        }
        if usage.contains(.decipherOnly) {
            values.append("decipherOnly")
        }
        return values.joined(separator: ",")
    }

    /// Returns true for paths treated as IPA archives.
    private func isIPAArchive(_ url: URL) -> Bool {
        let pathExtension = url.pathExtension.lowercased()
        return pathExtension == "ipa" || pathExtension == "zip"
    }

    /// Returns true when a URL points at a directory.
    private func isDirectory(_ url: URL) throws -> Bool {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
            return false
        }
        return isDirectory.boolValue
    }

    /// Returns the validated temporary directory requested by `-t`.
    private func temporaryDirectory() throws -> URL? {
        guard let path = command.temporaryFolderPath else {
            return nil
        }

        let url = fileURL(path)
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            throw ValidationError("Invalid temp folder: \(url.path)")
        }
        return url
    }
}

/// Directory input resolved for ZSign-compatible signing.
private struct DirectorySigningInput {
    /// App or extension bundle that will be rewritten and signed.
    let bundleURL: URL

    /// Extracted IPA root to re-archive, if the bundle came from `Payload`.
    let archiveRootURL: URL?
}

/// Archive root selected for directory input packaging.
private struct DirectoryArchiveRoot {
    /// Directory containing the `Payload` folder that should be zipped.
    let url: URL

    /// Whether this root was synthesized and should be removed after use.
    let removeAfterUse: Bool
}

/// Output archive selected for a signing operation.
private struct OutputArchive {
    /// IPA path to write.
    let url: URL

    /// Whether the archive should be removed after the install attempt.
    let removeAfterInstall: Bool
}
