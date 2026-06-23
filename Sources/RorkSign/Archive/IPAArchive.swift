import Foundation
import ZipArchive

/// Extracts and rebuilds IPA archives across native and WASI environments.
///
/// Native tools use file-backed ZIP storage to bound memory use, while the
/// browser product uses memory-backed storage supported by its WASI runtime.
/// Both paths share path validation and metadata handling so signing produces
/// the same archive structure on every supported platform.
package enum IPAArchive {
    /// Filesystem shape encoded by one ZIP entry.
    ///
    /// Preserved metadata remains valid only while the extracted entry keeps
    /// this shape; reusing symlink or directory mode bits for a replacement
    /// file would make the rebuilt archive describe the wrong object.
    fileprivate enum ItemKind {
        case directory
        case regularFile
        case symbolicLink
    }

    /// Original metadata paired with the entry shape that produced it.
    fileprivate struct PreservedEntry {
        let metadata: Zip.EntryMetadata
        let kind: ItemKind
    }

    /// Controls whether ZIP metadata is restored on extracted files.
    ///
    /// Browser WASI filesystems do not reliably preserve POSIX metadata, so
    /// signing keeps the original archive values separately and reapplies them
    /// when the IPA is rebuilt.
    package enum ExtractedMetadataBehavior {
        case preserveInArchive
        case restoreToFileSystem

        /// Uses the filesystem only when it can reliably preserve ZIP metadata.
        package static var platformDefault: Self {
            #if os(WASI)
            .preserveInArchive
            #else
            .restoreToFileSystem
            #endif
        }
    }

    /// Metadata captured while extracting an archive.
    package struct Contents {
        fileprivate let entriesByPath: [String: PreservedEntry]

        /// Represents a directory tree that was not extracted from an archive.
        package static let empty = Self(entriesByPath: [:])
    }

    /// Extracts an IPA and records metadata needed when it is rebuilt.
    package static func extract(
        at archiveURL: URL,
        to rootURL: URL,
        metadataBehavior: ExtractedMetadataBehavior = .platformDefault
    ) throws -> Contents {
        #if os(WASI)
        let data = try Data(contentsOf: archiveURL)
        let reader = try ZipArchiveReader(buffer: [UInt8](data))
        return try extract(
            using: reader,
            to: rootURL,
            metadataBehavior: metadataBehavior
        )
        #else
        return try ZipArchiveReader<ZipFileStorage>.withFile(
            archiveURL.path
        ) { reader in
            try extract(
                using: reader,
                to: rootURL,
                metadataBehavior: metadataBehavior
            )
        }
        #endif
    }

    /// Extracts entries from one reader after its storage has been selected.
    private static func extract<Storage: ZipReadableStorage>(
        using reader: ZipArchiveReader<Storage>,
        to rootURL: URL,
        metadataBehavior: ExtractedMetadataBehavior
    ) throws -> Contents {
        let entries = try reader.readDirectory()
        var entriesByPath: [String: PreservedEntry] = [:]
        var directoriesToRestore: [(entry: Zip.FileHeader, url: URL)] = []

        for entry in entries {
            let relativePath = try validatedArchivePath(entry.filename.string)
            guard !relativePath.isEmpty else {
                continue
            }

            entriesByPath[relativePath] = PreservedEntry(
                metadata: Zip.EntryMetadata(
                    modificationDate: entry.fileModification,
                    externalAttributes: entry.externalAttributes,
                    comment: entry.comment
                ),
                kind: itemKind(for: entry)
            )

            let destinationURL = try destinationURL(
                for: relativePath,
                under: rootURL,
                isDirectory: entry.isDirectory
            )
            if entry.isDirectory {
                try createDirectory(at: destinationURL)
                directoriesToRestore.append((entry, destinationURL))
                continue
            }

            try FileManager.default.createDirectory(
                at: destinationURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let bytes = try reader.readFile(entry)
            if entry.externalAttributes.unixAttributes.contains(.isSymbolicLink) {
                try createSymbolicLink(
                    at: destinationURL,
                    archivePath: relativePath,
                    bytes: bytes
                )
            } else {
                try Data(bytes).write(to: destinationURL)
                try restoreFileMetadata(
                    from: entry,
                    to: destinationURL,
                    metadataBehavior: metadataBehavior
                )
            }
        }

        // Children must be created while every ancestor remains writable.
        // Reversing the list also restores nested timestamps before parents.
        for directory in directoriesToRestore.reversed() {
            try restoreFileMetadata(
                from: directory.entry,
                to: directory.url,
                metadataBehavior: metadataBehavior
            )
        }

        return Contents(entriesByPath: entriesByPath)
    }

    /// Rebuilds an IPA while preserving metadata for entries that already existed.
    package static func write(
        contentsOf rootURL: URL,
        to archiveURL: URL,
        compressionMode: ArchiveCompressionMode,
        preserving originalContents: Contents = .empty
    ) throws {
        let fileManager = FileManager.default
        try validateArchiveDestination(
            archiveURL,
            outside: rootURL,
            fileManager: fileManager
        )
        if fileManager.fileExists(atPath: archiveURL.path) {
            try fileManager.removeItem(at: archiveURL)
        }
        try fileManager.createDirectory(
            at: archiveURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        let items = try archivedItems(under: rootURL)
        #if os(WASI)
        let writer = ZipArchiveWriter(
            configuration: compressionMode.writerConfiguration
        )
        try write(
            items,
            preserving: originalContents,
            using: writer
        )
        let bytes = try writer.finalizeBuffer()
        try Data(bytes).write(to: archiveURL)
        #else
        try ZipArchiveWriter<ZipFileStorage>.withFile(
            archiveURL.path,
            options: .create,
            configuration: compressionMode.writerConfiguration
        ) { writer in
            try write(
                items,
                preserving: originalContents,
                using: writer
            )
        }
        #endif
    }

    /// Writes entries after the destination storage has been selected.
    private static func write<Storage: ZipWriteableStorage>(
        _ items: [ArchivedItem],
        preserving originalContents: Contents,
        using writer: ZipArchiveWriter<Storage>
    ) throws {
        for item in items {
            let originalEntry = originalContents.entriesByPath[
                item.relativePath
            ]
            let metadata: Zip.EntryMetadata
            if let originalEntry, originalEntry.kind == item.kind {
                metadata = originalEntry.metadata
            } else {
                metadata = item.metadata
            }
            try writer.writeFile(
                filename: item.relativePath,
                contents: try item.contents(),
                metadata: metadata
            )
        }
    }

    private struct ArchivedItem {
        let relativePath: String
        let source: Source
        let metadata: Zip.EntryMetadata
        let kind: ItemKind

        enum Source {
            case bytes([UInt8])
            case file(URL)
        }

        /// Loads one entry at a time so native archive writes stay bounded.
        func contents() throws -> [UInt8] {
            switch source {
            case let .bytes(bytes):
                return bytes
            case let .file(url):
                return Array(try Data(contentsOf: url))
            }
        }
    }

    /// Returns archive entries in a stable order without following symlinks.
    private static func archivedItems(under rootURL: URL) throws -> [ArchivedItem] {
        var items: [ArchivedItem] = []
        try appendArchivedItems(
            in: rootURL,
            rootURL: rootURL,
            to: &items
        )
        return items.sorted { $0.relativePath < $1.relativePath }
    }

    /// Walks one directory without relying on Foundation's unavailable WASI
    /// directory enumerator.
    ///
    /// Explicit recursion also keeps symlink handling local: a link is archived
    /// as a link and is never traversed as though it were a directory.
    private static func appendArchivedItems(
        in directoryURL: URL,
        rootURL: URL,
        to items: inout [ArchivedItem]
    ) throws {
        for entry in try FileManager.default.entries(in: directoryURL) {
            let relativePath = try relativePath(
                for: entry.url,
                under: rootURL
            )
            let modificationDate = (
                try? FileManager.default.attributesOfItem(
                    atPath: entry.url.path
                )[.modificationDate]
            ) as? Date

            switch entry.kind {
            case .symbolicLink:
                let target = try FileManager.default.destinationOfSymbolicLink(
                    atPath: entry.url.path
                )
                items.append(
                    ArchivedItem(
                        relativePath: relativePath,
                        source: .bytes(Array(target.utf8)),
                        metadata: metadata(
                            for: entry.url,
                            modificationDate: modificationDate,
                            kind: .symbolicLink
                        ),
                        kind: .symbolicLink
                    )
                )
            case .directory:
                items.append(
                    ArchivedItem(
                        relativePath: relativePath,
                        source: .bytes([]),
                        metadata: metadata(
                            for: entry.url,
                            modificationDate: modificationDate,
                            kind: .directory
                        ),
                        kind: .directory
                    )
                )
                try appendArchivedItems(
                    in: entry.url,
                    rootURL: rootURL,
                    to: &items
                )
            case .regularFile:
                items.append(
                    ArchivedItem(
                        relativePath: relativePath,
                        source: .file(entry.url),
                        metadata: metadata(
                            for: entry.url,
                            modificationDate: modificationDate,
                            kind: .regularFile
                        ),
                        kind: .regularFile
                    )
                )
            }
        }
    }

    /// Creates metadata for files introduced by the signing pass.
    private static func metadata(
        for url: URL,
        modificationDate: Date?,
        kind: ItemKind
    ) -> Zip.EntryMetadata {
        let attributes = try? FileManager.default.attributesOfItem(
            atPath: url.path
        )
        let permissions = (attributes?[.posixPermissions] as? NSNumber)?.intValue

        let externalAttributes: Zip.ExternalAttributes
        switch kind {
        case .directory:
            externalAttributes = .unix([
                .isDirectory,
                .permissions([
                    .ownerReadWriteExecute,
                    .groupReadExecute,
                    .otherReadExecute,
                ]),
            ])
        case .regularFile:
            let isExecutable = permissions.map { $0 & 0o111 != 0 } ?? false
            externalAttributes = .unix([
                .isRegularFile,
                .permissions(
                    isExecutable
                        ? [
                            .ownerReadWriteExecute,
                            .groupReadExecute,
                            .otherReadExecute,
                        ]
                        : [
                            .ownerReadWrite,
                            .groupRead,
                            .otherRead,
                        ]
                ),
            ])
        case .symbolicLink:
            externalAttributes = .unix([
                .isSymbolicLink,
                .permissions([
                    .ownerReadWriteExecute,
                    .groupReadExecute,
                    .otherReadExecute,
                ]),
            ])
        }

        return Zip.EntryMetadata(
            modificationDate: modificationDate ?? .now,
            externalAttributes: externalAttributes
        )
    }

    /// Creates one extracted directory while leaving it writable for children.
    ///
    /// Original permissions and timestamps are restored only after extraction
    /// completes so read-only archive directories cannot block their contents.
    private static func createDirectory(at url: URL) throws {
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )
    }

    /// Returns the entry shape encoded in Unix attributes and ZIP directory flags.
    private static func itemKind(for entry: Zip.FileHeader) -> ItemKind {
        let fileType =
            entry.externalAttributes.unixAttributes.rawValue & 0o170000
        switch fileType {
        case Zip.UnixAttributes.isDirectory.rawValue:
            return .directory
        case Zip.UnixAttributes.isSymbolicLink.rawValue:
            return .symbolicLink
        case Zip.UnixAttributes.isRegularFile.rawValue:
            return .regularFile
        default:
            return entry.isDirectory ? .directory : .regularFile
        }
    }

    /// Rejects destinations that could remove source content or a directory.
    ///
    /// Archive output is caller-controlled. Preflighting before `removeItem`
    /// keeps an existing in-tree file or directory intact when the request is
    /// invalid, including when an ancestor resolves through a symbolic link.
    private static func validateArchiveDestination(
        _ archiveURL: URL,
        outside rootURL: URL,
        fileManager: FileManager
    ) throws {
        let sourceURL = rootURL.standardizedFileURL
        let outputURL = archiveURL.standardizedFileURL
        let resolvedSourceURL = sourceURL.resolvingSymlinksInPath()
        let resolvedOutputURL = outputURL
            .deletingLastPathComponent()
            .resolvingSymlinksInPath()
            .appendingPathComponent(outputURL.lastPathComponent)

        guard
            !isSameOrDescendant(outputURL, of: sourceURL),
            !isSameOrDescendant(resolvedOutputURL, of: resolvedSourceURL)
        else {
            throw RorkSignError.invalidArchive(
                "IPA archive output must be outside its source directory: \(archiveURL.path)."
            )
        }

        var isDirectory: ObjCBool = false
        guard
            !fileManager.fileExists(
                atPath: archiveURL.path,
                isDirectory: &isDirectory
            ) || !isDirectory.boolValue
        else {
            throw RorkSignError.invalidArchive(
                "IPA archive output path is a directory: \(archiveURL.path)."
            )
        }
    }

    /// Reports whether `candidateURL` is equal to or below `rootURL`.
    private static func isSameOrDescendant(
        _ candidateURL: URL,
        of rootURL: URL
    ) -> Bool {
        candidateURL.pathComponents.starts(with: rootURL.pathComponents)
    }

    /// Writes one archive symlink after proving that its target stays in bounds.
    private static func createSymbolicLink(
        at url: URL,
        archivePath: String,
        bytes: [UInt8]
    ) throws {
        guard let target = String(bytes: bytes, encoding: .utf8) else {
            throw RorkSignError.invalidArchive(
                "IPA archive contains a symbolic link with a non-UTF-8 target: \(archivePath)."
            )
        }
        try validateSymbolicLinkTarget(
            target,
            fromArchivePath: archivePath
        )
        try FileManager.default.createSymbolicLink(
            atPath: url.path,
            withDestinationPath: target
        )
    }

    /// Restores permissions and timestamps when the workspace supports them.
    private static func restoreFileMetadata(
        from entry: Zip.FileHeader,
        to url: URL,
        metadataBehavior: ExtractedMetadataBehavior
    ) throws {
        guard metadataBehavior == .restoreToFileSystem else {
            return
        }

        let rawPermissions =
            entry.externalAttributes.unixAttributes.filePermissions.rawValue
        var attributes: [FileAttributeKey: Any] = [
            .modificationDate: entry.fileModification
        ]
        if rawPermissions != 0 {
            attributes[.posixPermissions] = NSNumber(
                value: Int(rawPermissions)
            )
        }
        try FileManager.default.setAttributes(
            attributes,
            ofItemAtPath: url.path
        )
    }

    /// Rejects absolute paths, traversal components, and ambiguous empty parts.
    private static func validatedArchivePath(_ path: String) throws -> String {
        guard !path.isEmpty, !path.hasPrefix("/"), !path.contains("\0") else {
            throw RorkSignError.invalidArchive(
                "IPA archive contains an invalid entry path: \(path)."
            )
        }

        var components = path.split(
            separator: "/",
            omittingEmptySubsequences: false
        )
        if components.last?.isEmpty == true {
            components.removeLast()
        }
        guard
            !components.isEmpty,
            components.allSatisfy({
                !$0.isEmpty && $0 != "." && $0 != ".."
            })
        else {
            throw RorkSignError.invalidArchive(
                "IPA archive contains an unsafe entry path: \(path)."
            )
        }
        return components.joined(separator: "/")
    }

    /// Resolves an archive path and verifies that it remains below the root.
    private static func destinationURL(
        for relativePath: String,
        under rootURL: URL,
        isDirectory: Bool
    ) throws -> URL {
        let destinationURL = rootURL
            .appendingPathComponent(
                relativePath,
                isDirectory: isDirectory
            )
            .standardizedFileURL
        let rootPath = rootURL.standardizedFileURL.path
        guard destinationURL.path.hasPrefix(rootPath + "/") else {
            throw RorkSignError.invalidArchive(
                "IPA archive entry escaped the extraction directory: \(relativePath)."
            )
        }
        return destinationURL
    }

    /// Allows relative symlinks only when lexical resolution stays in the IPA.
    private static func validateSymbolicLinkTarget(
        _ target: String,
        fromArchivePath archivePath: String
    ) throws {
        guard
            !target.isEmpty,
            !target.hasPrefix("/"),
            !target.contains("\0")
        else {
            throw RorkSignError.invalidArchive(
                "IPA archive contains an unsafe symbolic link: \(archivePath)."
            )
        }

        var resolvedComponents = archivePath
            .split(separator: "/")
            .dropLast()
            .map(String.init)
        for component in target.split(
            separator: "/",
            omittingEmptySubsequences: false
        ) {
            switch component {
            case "", ".":
                continue
            case "..":
                guard !resolvedComponents.isEmpty else {
                    throw RorkSignError.invalidArchive(
                        "IPA archive symbolic link escapes the archive root: \(archivePath)."
                    )
                }
                resolvedComponents.removeLast()
            default:
                resolvedComponents.append(String(component))
            }
        }
    }

    /// Returns an archive-root-relative path and rejects filesystem escapes.
    private static func relativePath(
        for url: URL,
        under rootURL: URL
    ) throws -> String {
        let rootPath = rootURL.standardizedFileURL.path
        let path = url.standardizedFileURL.path
        guard path.hasPrefix(rootPath + "/") else {
            throw RorkSignError.invalidArchive(
                "Signed IPA path escaped its workspace: \(path)."
            )
        }
        return String(path.dropFirst(rootPath.count + 1))
    }
}

private extension ArchiveCompressionMode {
    /// ZIP writer settings corresponding to the public compression choice.
    var writerConfiguration: ZipArchiveWriterConfiguration {
        switch self {
        case .stored:
            return ZipArchiveWriterConfiguration(
                compression: NoZipCompression.noCompression
            )
        case .deflated:
            return ZipArchiveWriterConfiguration(
                compression: ZlibDeflateCompression()
            )
        }
    }
}
