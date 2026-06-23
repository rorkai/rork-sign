#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// Persistent cache configuration for bundle and IPA signing.
///
/// The cache stores complete signed Mach-O outputs keyed by the normalized
/// unsigned Mach-O bytes and every signing input that changes the final
/// signature. Existing entries are read only when `readExistingEntries` is
/// true; callers can set it to false to force a rebuild while still refreshing
/// cache contents for later runs.
public struct SigningCacheOptions: Equatable {
    /// Directory that stores cache entries.
    public var directoryURL: URL

    /// Whether existing cache entries may be reused.
    public var readExistingEntries: Bool

    /// Creates cache options for bundle-style signing.
    public init(directoryURL: URL, readExistingEntries: Bool = true) {
        self.directoryURL = directoryURL
        self.readExistingEntries = readExistingEntries
    }
}

/// Reads and writes signed Mach-O cache entries for bundle signing.
///
/// Cache entries are deliberately keyed by content, not by filesystem mtime, so
/// copied apps, temporary IPA extraction folders, and previously signed inputs
/// can reuse the same work when their signing-relevant bytes are identical.
final class BundleSignatureCache {
    private let options: SigningCacheOptions
    private let fileManager: FileManager
    private let encoder: JSONEncoder
    private let decoder = JSONDecoder()

    init(options: SigningCacheOptions, fileManager: FileManager = .default) {
        self.options = options
        self.fileManager = fileManager
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.sortedKeys]
    }

    /// Builds the stable key for one signing operation.
    func makeKey(
        input: Data,
        bundleIdentifier: String,
        entitlementsXML: String,
        infoPlist: Data,
        resourceDirectory: Data,
        signingMode: BundleCodeSigningMode,
        codeDirectoryHashingMode: CodeDirectoryHashingMode
    ) throws -> Key {
        let canonicalInput = try MachOSigner.signingCacheInput(input)
        let descriptor = Descriptor(
            formatVersion: 1,
            signerVersion: RorkSigner.version,
            canonicalMachOHash: sha256Hex(canonicalInput),
            bundleIdentifier: bundleIdentifier,
            signingMode: signingMode.cacheSigningMode,
            subjectCommonName: signingMode.cacheSubjectCommonName,
            teamIdentifier: signingMode.cacheTeamIdentifier,
            certificateHashes: signingMode.cacheCertificateHashes,
            entitlementsXMLHash: sha256Hex(Data(entitlementsXML.utf8)),
            infoPlistHash: sha256Hex(infoPlist),
            resourceDirectoryHash: sha256Hex(resourceDirectory),
            codeDirectoryHashingMode: codeDirectoryHashingMode.cacheName
        )
        let descriptorData = try encoder.encode(descriptor)
        return Key(
            digest: sha256Hex(descriptorData),
            canonicalInput: canonicalInput
        )
    }

    /// Returns a cached signed Mach-O when a valid entry exists.
    func signedMachO(for key: Key) -> Data? {
        guard options.readExistingEntries else {
            return nil
        }
        let url = entryURL(for: key)
        guard let data = try? Data(contentsOf: url),
              let entry = try? decoder.decode(Entry.self, from: data),
              entry.key == key.digest,
              let signed = Data(base64Encoded: entry.signedMachOBase64),
              let cachedCanonicalInput = try? MachOSigner.signingCacheInput(signed),
              cachedCanonicalInput == key.canonicalInput else {
            return nil
        }
        return signed
    }

    /// Stores a signed Mach-O for future runs.
    ///
    /// Cache writes are best-effort. Signing output is still valid if the cache
    /// directory cannot be created or an entry cannot be written.
    func store(_ signedMachO: Data, for key: Key) {
        do {
            try fileManager.createDirectory(at: options.directoryURL, withIntermediateDirectories: true)
            let entry = Entry(
                key: key.digest,
                signedMachOBase64: signedMachO.base64EncodedString()
            )
            let data = try encoder.encode(entry)
            try data.writeReplacingItem(at: entryURL(for: key))
        } catch {
            return
        }
    }

    private func entryURL(for key: Key) -> URL {
        options.directoryURL.appendingPathComponent(key.digest + ".json")
    }
}

extension BundleSignatureCache {
    /// Cache key plus canonical input bytes used to validate loaded entries.
    struct Key {
        let digest: String
        let canonicalInput: Data
    }

    private struct Descriptor: Encodable {
        let formatVersion: Int
        let signerVersion: String
        let canonicalMachOHash: String
        let bundleIdentifier: String
        let signingMode: String
        let subjectCommonName: String
        let teamIdentifier: String
        let certificateHashes: [String]
        let entitlementsXMLHash: String
        let infoPlistHash: String
        let resourceDirectoryHash: String
        let codeDirectoryHashingMode: String
    }

    private struct Entry: Codable {
        let key: String
        let signedMachOBase64: String
    }
}

extension BundleCodeSigningMode {
    var cacheSigningMode: String {
        switch self {
        case .adHoc:
            return "adhoc"
        case .identity:
            return "identity"
        }
    }

    var cacheSubjectCommonName: String {
        switch self {
        case .adHoc:
            return ""
        case .identity(let identity):
            return identity.subjectCommonName
        }
    }

    var cacheTeamIdentifier: String {
        switch self {
        case .adHoc:
            return ""
        case .identity(let identity):
            return identity.teamIdentifier
        }
    }

    var cacheCertificateHashes: [String] {
        switch self {
        case .adHoc:
            return []
        case .identity(let identity):
            return ([identity.certificateDER] + identity.additionalCertificatesDER).map(sha256Hex)
        }
    }
}

private extension CodeDirectoryHashingMode {
    var cacheName: String {
        switch self {
        case .compatible:
            return "compatible"
        case .sha256Only:
            return "sha256Only"
        }
    }
}

private func sha256Hex(_ data: Data) -> String {
    Data(SHA256.hash(data: data))
        .map { String(format: "%02x", $0) }
        .joined()
}
