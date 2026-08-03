#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// Builds the `_CodeSignature/CodeResources` resource seal for app-style bundles.
///
/// The resource seal records every non-code resource that should be protected by
/// the bundle signature. Apple still emits both the legacy `files` dictionary
/// and the modern `files2` dictionary, so this builder does the same:
///
/// - `files` contains SHA-1 hashes for regular files.
/// - `files2` contains SHA-256 hashes for regular files and symlink targets.
///
/// The builder is deliberately filesystem-oriented and deterministic: scanning,
/// filtering, and plist construction are separate phases so each part can be
/// tested without relying on the whole signing pipeline.
enum CodeResourcesBuilder {
    /// Returns the serialized XML CodeResources plist for `bundleURL`.
    static func build(bundleURL: URL) throws -> Data {
        let bundle = try BundleResourceBundle(url: bundleURL)
        let resources = try BundleResourceScanner.resources(in: bundle)

        var files: [String: Any] = [:]
        var files2: [String: Any] = [:]
        for resource in resources {
            if let legacyEntry = try ResourceSealEntry.legacy(for: resource) {
                files[resource.relativePath] = legacyEntry
            }
            if let modernEntry = try ResourceSealEntry.modern(for: resource) {
                files2[resource.relativePath] = modernEntry
            }
        }

        let plist: [String: Any] = [
            "files": files,
            "files2": files2,
            "rules": ResourceRules.legacy,
            "rules2": ResourceRules.modern,
        ]
        return try PropertyListWriter.data(
            from: plist,
            format: .xml
        )
    }

    /// Verifies the current bundle filesystem against its existing
    /// `_CodeSignature/CodeResources` plist.
    static func verify(bundleURL: URL) throws -> CodeResourcesVerificationReport {
        let bundle = try BundleResourceBundle(url: bundleURL)
        let codeResourcesURL = bundleURL
            .appendingPathComponent("_CodeSignature", isDirectory: true)
            .appendingPathComponent("CodeResources")
        guard FileManager.default.fileExists(atPath: codeResourcesURL.path) else {
            throw RorkSignError.resourceSealing(
                "CodeResources does not exist: \(codeResourcesURL.path)."
            )
        }

        let seal = try CodeResourcesSeal.parse(Data(contentsOf: codeResourcesURL))
        let resources = try BundleResourceScanner.resources(in: bundle)
        let expectedPaths = try Set(resources.compactMap { resource in
            let expectedEntry = try seal.expectedEntry(for: resource)
            return expectedEntry == nil ? nil : resource.relativePath
        })

        var verifiedResources: [String] = []
        var missingResources: [String] = []
        var mismatchedResources: [String] = []

        for entry in seal.entries.values.sorted(by: { $0.relativePath < $1.relativePath }) {
            let resourceURL = try BundleResourceScanner.resourceURL(
                for: entry.relativePath,
                under: bundle.url
            )
            let state = try entry.verify(at: resourceURL)
            switch state {
            case .matched:
                verifiedResources.append(entry.relativePath)
            case .missingOptional:
                continue
            case .missingRequired:
                missingResources.append(entry.relativePath)
            case .mismatched:
                mismatchedResources.append(entry.relativePath)
            }
        }

        let unsealedResources = expectedPaths
            .subtracting(seal.entries.keys)
            .sorted()

        return CodeResourcesVerificationReport(
            sealedResourceCount: seal.entries.count,
            verifiedResourceCount: verifiedResources.count,
            missingResources: missingResources.sorted(),
            mismatchedResources: mismatchedResources.sorted(),
            unsealedResources: unsealedResources
        )
    }

    /// Verifies every CodeResources seal found under a root bundle.
    ///
    /// The root bundle is reported first, followed by nested bundles in stable
    /// path order. Missing seals are skipped here because callers often use this
    /// during broad inspection and may still want executable/profile metadata
    /// from partially signed apps.
    static func verifyRecursively(bundleURL: URL) throws -> [BundleCodeResourcesVerificationReport] {
        _ = try BundleResourceBundle(url: bundleURL)
        let bundleURLs = try [bundleURL] + NestedResourceBundleScanner.nestedBundles(in: bundleURL)
        return try bundleURLs.compactMap { candidateURL in
            let codeResourcesURL = candidateURL
                .appendingPathComponent("_CodeSignature", isDirectory: true)
                .appendingPathComponent("CodeResources")
            guard FileManager.default.fileExists(atPath: codeResourcesURL.path) else {
                return nil
            }
            return BundleCodeResourcesVerificationReport(
                bundleURL: candidateURL,
                relativeBundlePath: try NestedResourceBundleScanner.relativePath(for: candidateURL, under: bundleURL),
                codeResources: try verify(bundleURL: candidateURL)
            )
        }
    }

    /// Writes `_CodeSignature/CodeResources`, creating the directory if needed.
    @discardableResult
    static func write(bundleURL: URL) throws -> URL {
        let outputDirectory = bundleURL.appendingPathComponent("_CodeSignature", isDirectory: true)
        try FileManager.default.createDirectory(
            at: outputDirectory,
            withIntermediateDirectories: true
        )

        let outputURL = outputDirectory.appendingPathComponent("CodeResources")
        let data = try build(bundleURL: bundleURL)
        try data.writeReplacingItem(at: outputURL)
        return outputURL
    }
}

/// Finds nested app-style bundles whose resource seals should be checked.
private enum NestedResourceBundleScanner {
    private static let nestedBundleExtensions: Set<String> = [
        "app",
        "appex",
        "bundle",
        "framework",
        "xctest",
        "xpc",
    ]

    static func nestedBundles(in rootURL: URL) throws -> [URL] {
        try directNestedBundles(in: rootURL).flatMap { nestedURL in
            try [nestedURL] + nestedBundles(in: nestedURL)
        }
        .sorted { $0.path < $1.path }
    }

    static func relativePath(for url: URL, under rootURL: URL) throws -> String {
        let rootPath = normalizedFileSystemPath(rootURL.standardizedFileURL.path)
        let path = normalizedFileSystemPath(url.standardizedFileURL.path)
        if path == rootPath {
            return "."
        }
        guard path.hasPrefix(rootPath + "/") else {
            throw RorkSignError.resourceSealing("Nested bundle escaped root: \(path).")
        }
        return String(path.dropFirst(rootPath.count + 1))
    }

    /// Finds only immediate nested bundles below one signing root.
    ///
    /// The caller performs recursion after each nested bundle becomes its own
    /// sealing boundary, preventing resources from being visited under both the
    /// parent and child bundle.
    private static func directNestedBundles(in rootURL: URL) throws -> [URL] {
        var bundles: [URL] = []
        try FileManager.default.enumerateDescendants(of: rootURL) { entry in
            let relativePath = try relativePath(
                for: entry.url,
                under: rootURL
            )
            if shouldSkip(relativePath: relativePath) {
                return entry.kind == .directory
                    ? .skipDescendants
                    : .visitDescendants
            }
            guard
                entry.kind == .directory,
                nestedBundleExtensions.contains(
                    entry.url.pathExtension.lowercased()
                )
            else {
                return .visitDescendants
            }
            bundles.append(entry.url)
            return .skipDescendants
        }
        return bundles.sorted { $0.path < $1.path }
    }

    private static func shouldSkip(relativePath: String) -> Bool {
        let components = relativePath.split(separator: "/").map(String.init)
        return relativePath == "_CodeSignature"
            || relativePath.hasPrefix("_CodeSignature/")
            || relativePath == "SC_Info"
            || relativePath.hasPrefix("SC_Info/")
            || components.contains(where: { $0.hasSuffix(".dSYM") })
            || components.contains(where: { $0 == "_WatchKitStub" })
    }

}

/// Parsed CodeResources entries, normalized across modern `files2` and legacy
/// `files` dictionaries.
private struct CodeResourcesSeal {
    enum Kind {
        case modern
        case legacy
    }

    let kind: Kind
    let entries: [String: CodeResourcesSealEntry]

    static func parse(_ data: Data) throws -> CodeResourcesSeal {
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = plist as? [String: Any] else {
            throw RorkSignError.resourceSealing("CodeResources is not a plist dictionary.")
        }

        if let files2 = dictionary["files2"] as? [String: Any] {
            return CodeResourcesSeal(
                kind: .modern,
                entries: try parseModernEntries(files2)
            )
        }
        guard let files = dictionary["files"] as? [String: Any] else {
            throw RorkSignError.resourceSealing("CodeResources has no files or files2 dictionary.")
        }
        return CodeResourcesSeal(
            kind: .legacy,
            entries: try parseLegacyEntries(files)
        )
    }

    func expectedEntry(for resource: BundleResource) throws -> Any? {
        switch kind {
        case .modern:
            return try ResourceSealEntry.modern(for: resource)
        case .legacy:
            return try ResourceSealEntry.legacy(for: resource)
        }
    }

    private static func parseModernEntries(_ files2: [String: Any]) throws -> [String: CodeResourcesSealEntry] {
        var entries: [String: CodeResourcesSealEntry] = [:]
        for (relativePath, value) in files2 {
            guard let dictionary = value as? [String: Any] else {
                throw RorkSignError.resourceSealing(
                    "CodeResources files2 entry is malformed: \(relativePath)."
                )
            }
            entries[relativePath] = try CodeResourcesSealEntry(
                relativePath: relativePath,
                optional: dictionary["optional"] as? Bool ?? false,
                sha1: dictionary["hash"] as? Data,
                sha256: dictionary["hash2"] as? Data,
                symlink: dictionary["symlink"] as? String
            )
        }
        return entries
    }

    private static func parseLegacyEntries(_ files: [String: Any]) throws -> [String: CodeResourcesSealEntry] {
        var entries: [String: CodeResourcesSealEntry] = [:]
        for (relativePath, value) in files {
            if let hash = value as? Data {
                entries[relativePath] = try CodeResourcesSealEntry(
                    relativePath: relativePath,
                    optional: false,
                    sha1: hash,
                    sha256: nil,
                    symlink: nil
                )
            } else if let dictionary = value as? [String: Any] {
                entries[relativePath] = try CodeResourcesSealEntry(
                    relativePath: relativePath,
                    optional: dictionary["optional"] as? Bool ?? false,
                    sha1: dictionary["hash"] as? Data,
                    sha256: nil,
                    symlink: nil
                )
            } else {
                throw RorkSignError.resourceSealing(
                    "CodeResources files entry is malformed: \(relativePath)."
                )
            }
        }
        return entries
    }
}

/// One normalized resource seal entry.
private struct CodeResourcesSealEntry {
    enum VerificationState {
        case matched
        case missingOptional
        case missingRequired
        case mismatched
    }

    let relativePath: String
    let optional: Bool
    let sha1: Data?
    let sha256: Data?
    let symlink: String?

    init(
        relativePath: String,
        optional: Bool,
        sha1: Data?,
        sha256: Data?,
        symlink: String?
    ) throws {
        guard symlink != nil || sha1 != nil || sha256 != nil else {
            throw RorkSignError.resourceSealing(
                "CodeResources entry has no seal data: \(relativePath)."
            )
        }
        self.relativePath = relativePath
        self.optional = optional
        self.sha1 = sha1
        self.sha256 = sha256
        self.symlink = symlink
    }

    func verify(at url: URL) throws -> VerificationState {
        if let symlink {
            guard let target = try? FileManager.default.destinationOfSymbolicLink(atPath: url.path) else {
                return optional ? .missingOptional : .missingRequired
            }
            return target == symlink ? .matched : .mismatched
        }

        guard FileManager.default.fileExists(atPath: url.path) else {
            return optional ? .missingOptional : .missingRequired
        }
        let data = try Data(contentsOf: url)
        if let sha1, Data(Insecure.SHA1.hash(data: data)) != sha1 {
            return .mismatched
        }
        if let sha256, Data(SHA256.hash(data: data)) != sha256 {
            return .mismatched
        }
        return .matched
    }
}

/// Bundle identity needed while deciding which files are resources rather than
/// executable code.
private struct BundleResourceBundle {
    let url: URL
    let executableName: String?

    init(url: URL) throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw RorkSignError.invalidBundle("Bundle does not exist: \(url.path).")
        }

        self.url = url
        self.executableName = try Self.readExecutableName(bundleURL: url)
    }

    /// Reads `CFBundleExecutable` without instantiating `Bundle`.
    ///
    /// These bundles are often unsigned filesystem artifacts, and Foundation's
    /// `Bundle` loader has process-level caching that is a poor fit for signer
    /// tests and temporary directories.
    private static func readExecutableName(bundleURL: URL) throws -> String? {
        let infoURL = bundleURL.appendingPathComponent("Info.plist")
        guard FileManager.default.fileExists(atPath: infoURL.path) else {
            return nil
        }

        let data = try Data(contentsOf: infoURL)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = plist as? [String: Any] else {
            throw RorkSignError.invalidBundle("Info.plist is not a dictionary.")
        }
        return dictionary["CFBundleExecutable"] as? String
    }
}

private enum BundleResourceKind: Equatable {
    case regularFile
    case symbolicLink(String)
}

private struct BundleResource: Equatable {
    let relativePath: String
    let url: URL
    let kind: BundleResourceKind
}

/// Walks the bundle once, classifies resource nodes, and returns a stable order
/// so generated plist bytes do not depend on filesystem traversal order.
private enum BundleResourceScanner {
    /// Collects resources owned by this bundle's seal.
    ///
    /// Signature artifacts, executable code, and nested bundles are excluded
    /// because they have separate signing or sealing contracts.
    static func resources(in bundle: BundleResourceBundle) throws -> [BundleResource] {
        var resources: [BundleResource] = []
        try FileManager.default.enumerateDescendants(of: bundle.url) { entry in
            let relativePath = try relativePath(
                for: entry.url,
                under: bundle.url
            )
            if shouldSkip(relativePath: relativePath, bundle: bundle) {
                return entry.kind == .directory
                    ? .skipDescendants
                    : .visitDescendants
            }

            switch entry.kind {
            case .directory:
                return .visitDescendants
            case .symbolicLink:
                let target = try FileManager.default
                    .destinationOfSymbolicLink(atPath: entry.url.path)
                resources.append(
                    BundleResource(
                        relativePath: relativePath,
                        url: entry.url,
                        kind: .symbolicLink(target)
                    )
                )
            case .regularFile:
                resources.append(
                    BundleResource(
                        relativePath: relativePath,
                        url: entry.url,
                        kind: .regularFile
                    )
                )
            }
            return .visitDescendants
        }

        return resources.sorted { $0.relativePath < $1.relativePath }
    }

    /// Converts an absolute file URL to a slash-separated path inside the bundle.
    private static func relativePath(for url: URL, under rootURL: URL) throws -> String {
        let rootPath = normalizedFileSystemPath(rootURL.standardizedFileURL.path)
        let path = normalizedFileSystemPath(url.standardizedFileURL.path)
        guard path.hasPrefix(rootPath + "/") else {
            throw RorkSignError.resourceSealing("Resource escaped bundle root: \(path).")
        }
        return String(path.dropFirst(rootPath.count + 1))
    }

    /// Resolves a CodeResources relative path under the bundle root without
    /// allowing absolute paths or `..` components to escape the bundle.
    static func resourceURL(for relativePath: String, under rootURL: URL) throws -> URL {
        guard !relativePath.isEmpty,
              !relativePath.hasPrefix("/"),
              !relativePath.contains("\\"),
              !relativePath.contains("\u{0}") else {
            throw RorkSignError.resourceSealing("CodeResources path is not relative: \(relativePath).")
        }
        let parts = relativePath.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw RorkSignError.resourceSealing("CodeResources path is not safe: \(relativePath).")
        }

        let url = parts.reduce(rootURL) { partial, component in
            partial.appendingPathComponent(String(component))
        }
        let rootPath = normalizedFileSystemPath(rootURL.standardizedFileURL.path)
        let path = normalizedFileSystemPath(url.standardizedFileURL.path)
        guard path.hasPrefix(rootPath + "/") else {
            throw RorkSignError.resourceSealing("CodeResources path escaped bundle root: \(relativePath).")
        }
        return url
    }

    /// Skips generated signature metadata, FairPlay metadata, and the main
    /// executable. Standalone Mach-O helpers are intentionally kept as resources
    /// here because the bundle signer signs them before the parent seal is made.
    private static func shouldSkip(relativePath: String, bundle: BundleResourceBundle) -> Bool {
        if relativePath == "_CodeSignature" || relativePath.hasPrefix("_CodeSignature/") {
            return true
        }
        if relativePath == "SC_Info" || relativePath.hasPrefix("SC_Info/") {
            return true
        }
        if relativePath == bundle.executableName {
            return true
        }
        return false
    }

}

/// Applies the same resource-rule decisions that are serialized into the
/// `rules` dictionaries. This keeps the generated seal coherent instead of
/// treating the rules as decorative metadata.
private enum ResourceSealEntry {
    static func legacy(for resource: BundleResource) throws -> Any? {
        guard case .regularFile = resource.kind else {
            return nil
        }
        let decision = ResourceRuleDecision.legacy(for: resource.relativePath)
        guard !decision.omit else {
            return nil
        }

        let hash = Data(Insecure.SHA1.hash(data: try Data(contentsOf: resource.url)))
        guard decision.optional else {
            return hash
        }
        return [
            "hash": hash,
            "optional": true,
        ]
    }

    static func modern(for resource: BundleResource) throws -> [String: Any]? {
        let decision = ResourceRuleDecision.modern(for: resource.relativePath)
        guard !decision.omit else {
            return nil
        }

        var entry: [String: Any]
        switch resource.kind {
        case .regularFile:
            let data = try Data(contentsOf: resource.url)
            entry = [
                "hash": Data(Insecure.SHA1.hash(data: data)),
                "hash2": Data(SHA256.hash(data: data)),
            ]
        case .symbolicLink(let target):
            entry = [
                "symlink": target,
            ]
        }

        if decision.optional {
            entry["optional"] = true
        }
        return entry
    }
}

private struct ResourceRuleDecision {
    let omit: Bool
    let optional: Bool

    static func legacy(for relativePath: String) -> ResourceRuleDecision {
        if isLocalizationVersionFile(relativePath) {
            return ResourceRuleDecision(omit: true, optional: false)
        }
        if isOptionalLocalizationResource(relativePath) {
            return ResourceRuleDecision(omit: false, optional: true)
        }
        return ResourceRuleDecision(omit: false, optional: false)
    }

    static func modern(for relativePath: String) -> ResourceRuleDecision {
        if isLocalizationVersionFile(relativePath)
            || isDSStore(relativePath)
            || relativePath == "Info.plist"
            || relativePath == "PkgInfo" {
            return ResourceRuleDecision(omit: true, optional: false)
        }
        if isOptionalLocalizationResource(relativePath) {
            return ResourceRuleDecision(omit: false, optional: true)
        }
        return ResourceRuleDecision(omit: false, optional: false)
    }

    private static func isLocalizationVersionFile(_ relativePath: String) -> Bool {
        relativePath.hasSuffix(".lproj/locversion.plist")
    }

    private static func isOptionalLocalizationResource(_ relativePath: String) -> Bool {
        relativePath.contains(".lproj/") && !relativePath.hasPrefix("Base.lproj/")
    }

    private static func isDSStore(_ relativePath: String) -> Bool {
        relativePath == ".DS_Store" || relativePath.hasSuffix("/.DS_Store")
    }
}

/// Literal rule dictionaries emitted alongside the resource hashes.
///
/// The matching logic lives in `ResourceRuleDecision`; these values are
/// serialized for compatibility with Apple's CodeResources format.
private enum ResourceRules {
    /// A fresh legacy rules graph for serialization in CodeResources.
    ///
    /// Each access returns new Foundation containers because `[String: Any]`
    /// cannot be shared safely between concurrent signing operations.
    static var legacy: [String: Any] {
        [
            "^.*": true,
            "^.*\\.lproj/": [
                "optional": true,
                "weight": 1000,
            ],
            "^.*\\.lproj/locversion.plist$": [
                "omit": true,
                "weight": 1100,
            ],
            "^Base\\.lproj/": [
                "weight": 1010,
            ],
            "^version.plist$": true,
        ]
    }

    /// A fresh modern rules graph for serialization in CodeResources.
    ///
    /// Each access returns new Foundation containers because `[String: Any]`
    /// cannot be shared safely between concurrent signing operations.
    static var modern: [String: Any] {
        [
            ".*\\.dSYM($|/)": [
                "weight": 11,
            ],
            "^.*": true,
            "^.*\\.lproj/": [
                "optional": true,
                "weight": 1000,
            ],
            "^.*\\.lproj/locversion.plist$": [
                "omit": true,
                "weight": 1100,
            ],
            "^(.*/)?\\.DS_Store$": [
                "omit": true,
                "weight": 2000,
            ],
            "^Base\\.lproj/": [
                "weight": 1010,
            ],
            "^embedded\\.mobileprovision$": [
                "weight": 20,
            ],
            "^Info\\.plist$": [
                "omit": true,
                "weight": 20,
            ],
            "^PkgInfo$": [
                "omit": true,
                "weight": 20,
            ],
            "^version\\.plist$": [
                "weight": 20,
            ],
        ]
    }
}
