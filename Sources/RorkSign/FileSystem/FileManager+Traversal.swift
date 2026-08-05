import Foundation

/// Returns a filesystem path normalized for archive comparisons.
///
/// The result uses archive separators on every host. macOS can expose the same
/// temporary directory through two paths, so the alias is normalized without
/// resolving the final resource itself.
package func normalizedFileSystemPath(_ path: String) -> String {
    let path = path.replacingOccurrences(of: "\\", with: "/")
    if path == "/private/var" {
        return "/var"
    }
    if path.hasPrefix("/private/var/") {
        return String(path.dropFirst("/private".count))
    }
    return path
}

/// A filesystem entry classified consistently across native and WASI hosts.
///
/// Keeping the classification beside the URL lets signing code distinguish
/// directories, regular files, and symbolic links without depending on the
/// metadata capabilities of the current Foundation implementation.
struct FileSystemEntry {
    /// The entry types relevant to bundle traversal and resource sealing.
    enum Kind: Equatable {
        /// A directory whose descendants may be visited.
        case directory

        /// A regular file whose bytes belong to the traversal.
        case regularFile

        /// A symbolic link that must never be followed by the traversal.
        case symbolicLink
    }

    /// Location of the classified entry.
    let url: URL

    /// Filesystem kind observed without following symbolic links.
    let kind: Kind
}

/// Controls filtering while enumerating a filesystem tree.
struct FileTraversalOptions: OptionSet {
    /// Raw option bits.
    let rawValue: Int

    /// Creates traversal options from raw option bits.
    init(rawValue: Int) {
        self.rawValue = rawValue
    }

    /// Omits dot-prefixed entries and native entries marked as hidden.
    static let skipsHiddenFiles = Self(rawValue: 1 << 0)
}

/// Determines whether descendant enumeration enters a visited directory.
enum FileTraversalDecision {
    /// Continues recursively through the directory's descendants.
    case visitDescendants

    /// Returns the directory without visiting its descendants.
    case skipDescendants
}

/// Provides deterministic filesystem traversal on native and browser-hosted
/// WASI platforms.
///
/// `FileManager.DirectoryEnumerator` and directory-related URL resource values
/// are not consistently implemented by browser WASI hosts. Explicit recursion
/// through `contentsOfDirectory` keeps traversal behavior predictable and lets
/// callers prevent descent into nested bundles or generated metadata.
extension FileManager {
    /// Returns the immediate children of a directory in stable path order.
    ///
    /// Symbolic links are classified before the path-based directory fallback,
    /// which prevents traversal from following a link to a directory.
    func entries(
        in directoryURL: URL,
        options: FileTraversalOptions = []
    ) throws -> [FileSystemEntry] {
        try contentsOfDirectory(atPath: directoryURL.path)
            .map { directoryURL.appendingPathComponent($0) }
            .filter {
                !options.contains(.skipsHiddenFiles) || !isHidden($0)
            }
            .map { try entry(at: $0) }
            .sorted { $0.url.path < $1.url.path }
    }

    /// Enumerates every descendant depth-first while allowing the caller to
    /// prune individual directory subtrees.
    ///
    /// The returned decision is ignored for regular files and symbolic links
    /// because neither has descendants owned by this traversal.
    func enumerateDescendants(
        of rootURL: URL,
        options: FileTraversalOptions = [],
        using body: (FileSystemEntry) throws -> FileTraversalDecision
    ) throws {
        for entry in try entries(in: rootURL, options: options) {
            let decision = try body(entry)
            guard entry.kind == .directory, decision == .visitDescendants else {
                continue
            }
            try enumerateDescendants(
                of: entry.url,
                options: options,
                using: body
            )
        }
    }

    /// Classifies a path without following symbolic links.
    func entry(at url: URL) throws -> FileSystemEntry {
        #if os(WASI)
        try classifyWASIEntry(at: url)
        #else
        try classifyNativeEntry(at: url)
        #endif
    }

    #if !os(WASI)
    /// Prefers native URL metadata, then falls back to filesystem attributes
    /// when a Foundation implementation omits individual resource values.
    private func classifyNativeEntry(at url: URL) throws -> FileSystemEntry {
        let resourceValues = try? url.resourceValues(
            forKeys: [
                .isDirectoryKey,
                .isRegularFileKey,
                .isSymbolicLinkKey,
            ]
        )
        if resourceValues?.isSymbolicLink == true {
            return FileSystemEntry(url: url, kind: .symbolicLink)
        }
        if resourceValues?.isDirectory == true {
            return FileSystemEntry(
                url: directoryURL(for: url),
                kind: .directory
            )
        }

        if resourceValues?.isRegularFile == true {
            return FileSystemEntry(
                url: url,
                kind: .regularFile
            )
        }

        let attributes = try attributesOfItem(atPath: url.path)
        switch attributes[.type] as? FileAttributeType {
        case .typeSymbolicLink:
            return FileSystemEntry(url: url, kind: .symbolicLink)
        case .typeDirectory:
            return FileSystemEntry(
                url: directoryURL(for: url),
                kind: .directory
            )
        case .typeRegular:
            return FileSystemEntry(url: url, kind: .regularFile)
        default:
            break
        }

        throw CocoaError(
            .fileReadUnknown,
            userInfo: [NSFilePathErrorKey: url.path]
        )
    }
    #else
    /// Preserves symbolic links before using path probes to distinguish the
    /// remaining entry kinds.
    private func classifyWASIEntry(at url: URL) throws -> FileSystemEntry {
        let attributes = try? attributesOfItem(atPath: url.path)
        if attributes?[.type] as? FileAttributeType == .typeSymbolicLink {
            return FileSystemEntry(url: url, kind: .symbolicLink)
        }
        if attributes?[.type] as? FileAttributeType == .typeDirectory {
            return FileSystemEntry(
                url: directoryURL(for: url),
                kind: .directory
            )
        }
        if attributes?[.type] as? FileAttributeType == .typeRegular {
            return FileSystemEntry(url: url, kind: .regularFile)
        }

        var isDirectory: ObjCBool = false
        let exists = fileExists(
            atPath: url.path,
            isDirectory: &isDirectory
        )
        guard exists else {
            throw CocoaError(
                .fileNoSuchFile,
                userInfo: [NSFilePathErrorKey: url.path]
            )
        }
        if isDirectory.boolValue {
            return FileSystemEntry(
                url: directoryURL(for: url),
                kind: .directory
            )
        }

        // Browser WASI hosts can acknowledge a path while leaving the
        // `isDirectory` out-parameter false. A directory-qualified URL lets
        // Foundation preserve that distinction while opening the entry.
        let candidateDirectoryURL = directoryURL(for: url)
        let directoryContents = try? contentsOfDirectory(
            atPath: candidateDirectoryURL.path
        )
        if directoryContents != nil {
            return FileSystemEntry(
                url: candidateDirectoryURL,
                kind: .directory
            )
        }
        return FileSystemEntry(
            url: url,
            kind: .regularFile
        )
    }
    #endif

    /// Treats dot-prefixed paths consistently while preserving the native
    /// filesystem's hidden attribute where Foundation exposes it.
    private func isHidden(_ url: URL) -> Bool {
        if url.lastPathComponent.hasPrefix(".") {
            return true
        }
        #if os(WASI)
        return false
        #else
        return (try? url.resourceValues(forKeys: [.isHiddenKey]).isHidden)
            == true
        #endif
    }

    /// Preserves directory intent for Foundation implementations that use a
    /// trailing path marker when resolving browser-hosted WASI directories.
    private func directoryURL(for url: URL) -> URL {
        URL(fileURLWithPath: url.path, isDirectory: true)
    }
}
