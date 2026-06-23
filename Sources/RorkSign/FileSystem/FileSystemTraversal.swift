import Foundation

/// A filesystem entry classified without requiring URL resource metadata.
///
/// Browser-hosted WASI filesystems support ordinary path operations but may
/// omit `URLResourceValues` such as `isDirectory`. Keeping the classification
/// beside the URL gives archive and signing code one portable contract while
/// preserving native symbolic-link handling.
struct FileSystemEntry {
    /// The entry types relevant to bundle traversal and resource sealing.
    enum Kind: Equatable {
        case directory
        case regularFile
        case symbolicLink
    }

    let url: URL
    let kind: Kind
}

/// Traverses directory trees using filesystem operations available on native
/// platforms and WASI.
///
/// `FileManager.DirectoryEnumerator` and directory-related URL resource values
/// are not consistently implemented by browser WASI hosts. Explicit recursion
/// through `contentsOfDirectory` keeps traversal behavior predictable and lets
/// callers prevent descent into nested bundles or generated metadata.
enum FileSystemTraversal {
    /// Controls filtering applied while reading each directory.
    struct Options: OptionSet {
        let rawValue: Int

        /// Omits dot-prefixed entries and native entries marked as hidden.
        static let skipsHiddenFiles = Self(rawValue: 1 << 0)
    }

    /// Determines whether traversal enters a visited directory.
    enum Action {
        case descend
        case skipDescendants
    }

    /// Returns the immediate children of a directory in stable path order.
    ///
    /// Symbolic links are classified before the path-based directory fallback,
    /// which prevents traversal from following a link to a directory.
    static func contents(
        of directoryURL: URL,
        options: Options = []
    ) throws -> [FileSystemEntry] {
        try FileManager.default.contentsOfDirectory(atPath: directoryURL.path)
            .map { directoryURL.appendingPathComponent($0) }
            .filter {
                !options.contains(.skipsHiddenFiles) || !isHidden($0)
            }
            .map(entry(at:))
            .sorted { $0.url.path < $1.url.path }
    }

    /// Visits every descendant depth-first and allows callers to prune
    /// individual directory subtrees.
    ///
    /// The visitor's action is ignored for regular files and symbolic links
    /// because neither has descendants owned by this traversal.
    static func walk(
        descendantsOf rootURL: URL,
        options: Options = [],
        _ visit: (FileSystemEntry) throws -> Action
    ) throws {
        for entry in try contents(of: rootURL, options: options) {
            let action = try visit(entry)
            guard entry.kind == .directory, action == .descend else {
                continue
            }
            try walk(
                descendantsOf: entry.url,
                options: options,
                visit
            )
        }
    }

    /// Classifies an entry using the metadata APIs supported by the platform.
    static func entry(at url: URL) throws -> FileSystemEntry {
        #if os(WASI)
        try wasiEntry(at: url)
        #else
        try nativeEntry(at: url)
        #endif
    }

    #if !os(WASI)
    /// Uses native URL metadata so symbolic links are never followed.
    private static func nativeEntry(at url: URL) throws -> FileSystemEntry {
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

        let attributes = try FileManager.default.attributesOfItem(
            atPath: url.path
        )
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
    /// Uses path operations because browser WASI omits URL resource metadata.
    private static func wasiEntry(at url: URL) throws -> FileSystemEntry {
        let attributes = try? FileManager.default.attributesOfItem(
            atPath: url.path
        )
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
        let exists = FileManager.default.fileExists(
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
        let directoryContents = try? FileManager.default.contentsOfDirectory(
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

    /// Combines portable dot-file detection with native hidden metadata.
    private static func isHidden(_ url: URL) -> Bool {
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

    /// Reconstructs a file URL with the directory path marker required by
    /// browser WASI Foundation.
    private static func directoryURL(for url: URL) -> URL {
        URL(fileURLWithPath: url.path, isDirectory: true)
    }
}
