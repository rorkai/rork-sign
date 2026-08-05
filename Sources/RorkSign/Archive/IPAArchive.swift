import Foundation
import ZipArchive

/// Extracts and rebuilds IPA archives across native and WASI environments.
///
/// Native tools use file-backed ZIP storage to bound memory use, while the
/// browser product uses memory-backed storage supported by its WASI runtime.
/// Both paths share path validation and metadata handling so signing produces
/// the same archive structure on every supported platform.
package enum IPAArchive {
    /// Filesystem layout expected after extracting one supported input archive.
    private enum ArchiveLayout {
        case ipa
        case appBundle

        /// User-facing archive name used in validation errors.
        var name: String {
            switch self {
            case .ipa:
                return "IPA"
            case .appBundle:
                return "App"
            }
        }

        /// Directory that receives the input archive's top-level entries.
        func extractionRoot(in archiveRootURL: URL) -> URL {
            switch self {
            case .ipa:
                return archiveRootURL
            case .appBundle:
                return archiveRootURL.appendingPathComponent(
                    "Payload",
                    isDirectory: true
                )
            }
        }

        /// Reconciles input paths with their location in the final IPA.
        func archiveMetadata(from extraction: Extraction) -> Extraction {
            switch self {
            case .ipa:
                return extraction
            case .appBundle:
                return extraction.prefixingPaths(with: "Payload")
            }
        }
    }

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

    /// ZIP entry whose lexical path and filesystem shape are safe to inspect.
    ///
    /// Extraction validates the complete entry hierarchy before creating files
    /// so archive order cannot redirect a later write through a symbolic link.
    private struct ValidatedArchiveEntry {
        let header: Zip.FileHeader
        let relativePath: String
        let kind: ItemKind
    }

    /// Controls whether ZIP metadata is restored on extracted files.
    ///
    /// Browser WASI filesystems do not reliably preserve POSIX metadata, so
    /// signing keeps the original archive values separately and reapplies them
    /// when the IPA is rebuilt.
    package enum MetadataRestoration {
        /// Keeps workspace-default metadata on extracted files.
        ///
        /// Original archive metadata remains available in ``Extraction`` for
        /// repacking even when it is not applied to the temporary filesystem.
        case skip

        /// Applies archived permissions and modification dates after extraction.
        case restore

        /// Uses the filesystem only when it can reliably preserve POSIX metadata.
        #if os(WASI) || os(Windows)
        package static let platformDefault: Self = .skip
        #else
        package static let platformDefault: Self = .restore
        #endif
    }

    /// Archive metadata captured during extraction and reusable when repacking.
    package struct Extraction {
        fileprivate let entriesByPath: [String: PreservedEntry]

        /// Represents a directory tree that was not extracted from an archive.
        package static let empty = Self(entriesByPath: [:])

        /// Returns metadata adjusted for entries moved below one new directory.
        ///
        /// App-bundle ZIPs store `App.app` at their root, while an IPA requires
        /// the same tree below `Payload`. Rebasing the preserved paths keeps
        /// executable and symbolic-link metadata attached to the corresponding
        /// entries when the final IPA is written.
        fileprivate func prefixingPaths(
            with pathComponent: String
        ) -> Self {
            Self(
                entriesByPath: Dictionary(
                    uniqueKeysWithValues: entriesByPath.map { path, entry in
                        ("\(pathComponent)/\(path)", entry)
                    }
                )
            )
        }
    }

    /// Extracts an IPA and records metadata needed when it is rebuilt.
    package static func extract(
        at archiveURL: URL,
        to rootURL: URL,
        metadataRestoration: MetadataRestoration = .platformDefault
    ) throws -> Extraction {
        #if os(WASI)
        let data = try Data(contentsOf: archiveURL)
        let reader = try ZipArchiveReader(buffer: [UInt8](data))
        return try extract(
            using: reader,
            to: rootURL,
            metadataRestoration: metadataRestoration
        )
        #else
        return try ZipArchiveReader<ZipFileStorage>.withFile(
            archiveURL.path
        ) { reader in
            try extract(
                using: reader,
                to: rootURL,
                metadataRestoration: metadataRestoration
            )
        }
        #endif
    }

    /// Paths and archive metadata valid for the lifetime of one IPA workspace.
    package struct PayloadExtraction {
        /// Root directory containing every extracted IPA entry.
        package let archiveRootURL: URL

        /// The single top-level app bundle found inside `Payload`.
        package let appBundleURL: URL

        /// Original ZIP metadata available when the archive is rebuilt.
        package let archiveMetadata: Extraction
    }

    /// Extracts one IPA, finds its payload app, and removes the workspace after
    /// `body` returns.
    ///
    /// Centralizing the lifecycle keeps signing and metadata inspection aligned
    /// on archive validation, payload selection, and cleanup behavior.
    package static func withExtractedPayloadApp<Result>(
        from archiveURL: URL,
        temporaryDirectory: URL?,
        _ body: (PayloadExtraction) throws -> Result
    ) throws -> Result {
        try withExtractedPayloadApp(
            from: archiveURL,
            layout: .ipa,
            temporaryDirectory: temporaryDirectory,
            body
        )
    }

    /// Extracts an app-bundle ZIP into an IPA workspace and removes the
    /// workspace after `body` returns.
    ///
    /// Published app archives place one `.app` directory at their root. The
    /// temporary workspace introduces the required `Payload` directory before
    /// signing so the resulting archive is a valid IPA without an intermediate
    /// repacking pass.
    package static func withExtractedAppArchive<Result>(
        from archiveURL: URL,
        temporaryDirectory: URL?,
        _ body: (PayloadExtraction) throws -> Result
    ) throws -> Result {
        try withExtractedPayloadApp(
            from: archiveURL,
            layout: .appBundle,
            temporaryDirectory: temporaryDirectory,
            body
        )
    }

    /// Extracts one supported archive layout into a scoped IPA workspace.
    private static func withExtractedPayloadApp<Result>(
        from archiveURL: URL,
        layout: ArchiveLayout,
        temporaryDirectory: URL?,
        _ body: (PayloadExtraction) throws -> Result
    ) throws -> Result {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: archiveURL.path) else {
            throw RorkSignError.invalidArchive(
                "\(layout.name) archive does not exist: \(archiveURL.path)."
            )
        }

        let workspaceRoot = try workspaceRootDirectory(temporaryDirectory)
        let workspaceURL = workspaceRoot.appendingPathComponent(
            "rork-sign-ipa-\(UUID().uuidString)",
            isDirectory: true
        )
        let archiveRootURL = workspaceURL.appendingPathComponent(
            "ArchiveRoot",
            isDirectory: true
        )
        let extractionRootURL = layout.extractionRoot(
            in: archiveRootURL
        )
        defer {
            try? fileManager.removeItem(at: workspaceURL)
        }

        let extraction: Extraction
        do {
            try fileManager.createDirectory(
                at: extractionRootURL,
                withIntermediateDirectories: true
            )
            extraction = try extract(
                at: archiveURL,
                to: extractionRootURL
            )
        } catch let error as RorkSignError {
            throw error
        } catch {
            throw RorkSignError.invalidArchive(
                "\(layout.name) archive could not be extracted: \(error.localizedDescription)"
            )
        }

        let appBundleURL = try appBundleURL(
            in: archiveRootURL,
            extractedAt: extractionRootURL,
            layout: layout,
            using: fileManager
        )

        return try body(
            PayloadExtraction(
                archiveRootURL: archiveRootURL,
                appBundleURL: appBundleURL,
                archiveMetadata: layout.archiveMetadata(from: extraction)
            )
        )
    }

    /// Resolves the app while enforcing the selected input archive's contract.
    ///
    /// IPA files may contain other top-level directories outside `Payload`.
    /// Published app archives are narrower: accepting siblings beside the app
    /// would copy unrelated files into the final IPA's `Payload` directory.
    private static func appBundleURL(
        in archiveRootURL: URL,
        extractedAt extractionRootURL: URL,
        layout: ArchiveLayout,
        using fileManager: FileManager
    ) throws -> URL {
        switch layout {
        case .ipa:
            return try payloadAppBundle(in: archiveRootURL)
        case .appBundle:
            let entries = try fileManager.entries(in: extractionRootURL)
            guard
                entries.count == 1,
                let appBundle = entries.first,
                appBundle.kind == .directory,
                appBundle.url.pathExtension.lowercased() == "app"
            else {
                throw RorkSignError.invalidArchive(
                    "App archive must contain exactly one top-level .app directory."
                )
            }
            return appBundle.url
        }
    }

    /// Extracts entries from one reader after its storage has been selected.
    private static func extract<Storage: ZipReadableStorage>(
        using reader: ZipArchiveReader<Storage>,
        to rootURL: URL,
        metadataRestoration: MetadataRestoration
    ) throws -> Extraction {
        let entries = try validatedEntries(
            from: reader.readDirectory()
        )
        var entriesByPath: [String: PreservedEntry] = [:]
        var directoriesToRestore: [(entry: Zip.FileHeader, url: URL)] = []

        for entry in entries {
            entriesByPath[entry.relativePath] = PreservedEntry(
                metadata: Zip.EntryMetadata(
                    modificationDate: entry.header.fileModification,
                    externalAttributes: entry.header.externalAttributes,
                    comment: entry.header.comment
                ),
                kind: entry.kind
            )

            let destinationURL = try destinationURL(
                for: entry.relativePath,
                under: rootURL,
                isDirectory: entry.kind == .directory
            )
            if entry.kind == .directory {
                try createDirectory(at: destinationURL)
                directoriesToRestore.append((entry.header, destinationURL))
                continue
            }

            try FileManager.default.createDirectory(
                at: destinationURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            if entry.kind == .symbolicLink {
                try createSymbolicLink(
                    at: destinationURL,
                    archivePath: entry.relativePath,
                    bytes: try reader.readFile(entry.header)
                )
            } else {
                try writeRegularFile(
                    entry.header,
                    to: destinationURL,
                    using: reader
                )
                try restoreFileMetadata(
                    from: entry.header,
                    to: destinationURL,
                    metadataRestoration: metadataRestoration
                )
            }
        }

        // Children must be created while every ancestor remains writable.
        // Reversing the list also restores nested timestamps before parents.
        for directory in directoriesToRestore.reversed() {
            try restoreFileMetadata(
                from: directory.entry,
                to: directory.url,
                metadataRestoration: metadataRestoration
            )
        }

        return Extraction(entriesByPath: entriesByPath)
    }

    /// Streams one regular ZIP entry to disk with bounded memory use.
    ///
    /// Browser-hosted app archives may contain large executables and assets.
    /// Writing decompressed chunks directly to the workspace avoids retaining a
    /// second complete copy of each entry in WASM linear memory.
    private static func writeRegularFile<Storage: ZipReadableStorage>(
        _ entry: Zip.FileHeader,
        to destinationURL: URL,
        using reader: ZipArchiveReader<Storage>
    ) throws {
        let fileManager = FileManager.default
        guard fileManager.createFile(
            atPath: destinationURL.path,
            contents: nil
        ) else {
            throw RorkSignError.invalidArchive(
                "Archive entry could not be created: \(destinationURL.path)."
            )
        }

        let fileHandle = try FileHandle(forWritingTo: destinationURL)
        do {
            try reader.readFile(
                entry,
                bufferSize: ZipArchiveExtractionOptions.defaultBufferSize
            ) { bytes in
                try fileHandle.write(contentsOf: Data(bytes))
            }
            try fileHandle.close()
        } catch {
            try? fileHandle.close()
            try? fileManager.removeItem(at: destinationURL)
            throw error
        }
    }

    /// Validates archive paths and their hierarchy before extraction mutates disk.
    ///
    /// ZIP paths are compared case-insensitively because common signing hosts
    /// use case-insensitive filesystems. Rejecting duplicate paths and entries
    /// below archive symlinks keeps extraction behavior independent of the host
    /// filesystem and central-directory order.
    private static func validatedEntries(
        from headers: [Zip.FileHeader]
    ) throws -> [ValidatedArchiveEntry] {
        let entries = try headers.map { header in
            ValidatedArchiveEntry(
                header: header,
                relativePath: try validatedArchivePath(
                    header.pathInArchive
                ),
                kind: itemKind(for: header)
            )
        }

        var paths: Set<String> = []
        var symbolicLinkPaths: Set<String> = []
        for entry in entries {
            let path = extractionComparisonPath(entry.relativePath)
            guard paths.insert(path).inserted else {
                throw RorkSignError.invalidArchive(
                    "IPA archive contains a duplicate entry path: \(entry.relativePath)."
                )
            }
            if entry.kind == .symbolicLink {
                symbolicLinkPaths.insert(path)
            }
        }

        for entry in entries {
            var ancestorComponents: [Substring] = []
            for component in entry.relativePath.split(separator: "/").dropLast() {
                ancestorComponents.append(component)
                let ancestorPath = extractionComparisonPath(
                    ancestorComponents.joined(separator: "/")
                )
                guard !symbolicLinkPaths.contains(ancestorPath) else {
                    throw RorkSignError.invalidArchive(
                        "IPA archive entry traverses a symbolic link: \(entry.relativePath)."
                    )
                }
            }
        }
        return entries
    }

    /// Normalizes one archive path for comparisons on extraction filesystems.
    private static func extractionComparisonPath<S: StringProtocol>(
        _ path: S
    ) -> String {
        path.lowercased()
    }

    /// Rebuilds an IPA while retaining compatible metadata captured during extraction.
    ///
    /// Metadata is reused only when an entry still has the same path and kind,
    /// preventing a replacement file from inheriting attributes that belonged
    /// to a symbolic link or directory. The destination is replaced only after
    /// the new archive has been fully serialized.
    package static func write(
        contentsOf rootURL: URL,
        to archiveURL: URL,
        compressionMode: ArchiveCompressionMode,
        preservingMetadataFrom extraction: Extraction = .empty
    ) throws {
        let fileManager = FileManager.default
        try validateArchiveDestination(
            archiveURL,
            outside: rootURL,
            fileManager: fileManager
        )
        try fileManager.createDirectory(
            at: archiveURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        let items = try archivedItems(under: rootURL)
        try writeArchive(
            to: archiveURL,
            fileManager: fileManager
        ) { stagedArchiveURL in
            #if os(WASI)
            let writer = ZipArchiveWriter(
                configuration: compressionMode.writerConfiguration
            )
            try writeEntries(
                items,
                to: writer,
                preservingMetadataFrom: extraction
            )
            let bytes = try writer.finalizeBuffer()
            try Data(bytes).write(to: stagedArchiveURL)
            #else
            try ZipArchiveWriter<ZipFileStorage>.withFile(
                stagedArchiveURL.path,
                options: .create,
                configuration: compressionMode.writerConfiguration
            ) { writer in
                try writeEntries(
                    items,
                    to: writer,
                    preservingMetadataFrom: extraction
                )
            }
            #endif
        }
    }

    /// Writes a complete archive to a sibling staging file before committing it.
    ///
    /// Staging protects a caller-owned destination from serialization failures.
    /// The temporary sibling is removed regardless of whether serialization or
    /// the final replacement succeeds.
    static func writeArchive(
        to archiveURL: URL,
        fileManager: FileManager = .default,
        _ writeStagedArchive: (URL) throws -> Void
    ) throws {
        let stagedArchiveURL = archiveURL
            .deletingLastPathComponent()
            .appendingPathComponent(
                ".\(archiveURL.lastPathComponent).\(UUID().uuidString).tmp"
            )
        defer {
            try? fileManager.removeItem(at: stagedArchiveURL)
        }

        try writeStagedArchive(stagedArchiveURL)
        try replaceArchive(
            at: archiveURL,
            with: stagedArchiveURL,
            fileManager: fileManager
        )
    }

    /// Writes normalized entries while retaining metadata only for unchanged kinds.
    ///
    /// Checking both path and kind prevents stale ZIP attributes from crossing
    /// a structural change, such as replacing a symbolic link with a regular file.
    private static func writeEntries<Storage: ZipWriteableStorage>(
        _ items: [ArchivedItem],
        to writer: ZipArchiveWriter<Storage>,
        preservingMetadataFrom extraction: Extraction
    ) throws {
        for item in items {
            let originalEntry = extraction.entriesByPath[
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

    /// One normalized ZIP entry whose file contents can remain lazily loaded.
    ///
    /// Keeping regular files file-backed bounds native memory use, while
    /// directories and symbolic-link targets are small enough to retain inline.
    private struct ArchivedItem {
        let relativePath: String
        let source: Source
        let metadata: Zip.EntryMetadata
        let kind: ItemKind

        /// Storage used until the ZIP writer requests the entry contents.
        ///
        /// Inline bytes represent structure-only entries; file URLs defer the
        /// potentially large regular-file read until serialization.
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

            // Mach-O code remains executable when the host cannot expose a
            // POSIX mode for the source file.
            #if os(Windows)
            let isExecutable = (try? MachOFile.isMachO(at: url)) == true
            #else
            let isExecutable = permissions.map { $0 & 0o111 != 0 }
                ?? ((try? MachOFile.isMachO(at: url)) == true)
            #endif
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
    /// Archive output is caller-controlled. Rejecting in-tree destinations and
    /// directories before staging prevents replacement from mutating source
    /// content, including when an ancestor resolves through a symbolic link.
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

    /// Commits a fully serialized sibling archive without exposing partial data.
    ///
    /// Some Foundation implementations cannot replace an item directly.
    ///
    /// The fallback keeps the previous archive under a temporary sibling name
    /// until the new archive occupies the destination.
    private static func replaceArchive(
        at archiveURL: URL,
        with stagedArchiveURL: URL,
        fileManager: FileManager
    ) throws {
        guard fileManager.fileExists(atPath: archiveURL.path) else {
            try fileManager.moveItem(
                at: stagedArchiveURL,
                to: archiveURL
            )
            return
        }

        #if os(WASI) || os(Windows)
        let backupURL = archiveURL
            .deletingLastPathComponent()
            .appendingPathComponent(
                ".\(archiveURL.lastPathComponent).\(UUID().uuidString).backup"
            )
        try replaceArchive(
            at: archiveURL,
            with: stagedArchiveURL,
            backingUpOriginalTo: backupURL,
            moveItem: { sourceURL, destinationURL in
                try fileManager.moveItem(
                    at: sourceURL,
                    to: destinationURL
                )
            },
            removeItem: { url in
                try fileManager.removeItem(at: url)
            }
        )
        #else
        _ = try fileManager.replaceItemAt(
            archiveURL,
            withItemAt: stagedArchiveURL
        )
        #endif
    }

    /// Replaces an archive on filesystems without direct item replacement.
    ///
    /// The original remains at `backupURL` until the staged archive reaches its
    /// destination. A failed commit restores that backup; if restoration also
    /// fails, the resulting error reports both failures and the retained backup
    /// location. Injecting the file operations keeps this rollback path
    /// independently verifiable without depending on filesystem permissions.
    static func replaceArchive(
        at archiveURL: URL,
        with stagedArchiveURL: URL,
        backingUpOriginalTo backupURL: URL,
        moveItem: (URL, URL) throws -> Void,
        removeItem: (URL) throws -> Void
    ) throws {
        try moveItem(archiveURL, backupURL)
        do {
            try moveItem(stagedArchiveURL, archiveURL)
        } catch let commitError {
            do {
                try moveItem(backupURL, archiveURL)
            } catch let restorationError {
                throw RorkSignError.invalidArchive(
                    "Archive replacement failed: \(commitError.localizedDescription). "
                        + "The previous archive could not be restored from "
                        + "\(backupURL.path): \(restorationError.localizedDescription)"
                )
            }
            throw commitError
        }
        try? removeItem(backupURL)
    }

    /// Validates or creates the parent for an isolated extraction workspace.
    ///
    /// A caller-provided file path is rejected before extraction starts, while a
    /// missing directory is created to preserve the CLI's temporary-path
    /// behavior.
    private static func workspaceRootDirectory(
        _ temporaryDirectory: URL?
    ) throws -> URL {
        let fileManager = FileManager.default
        let rootURL = temporaryDirectory ?? fileManager.temporaryDirectory
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(
            atPath: rootURL.path,
            isDirectory: &isDirectory
        ) {
            guard isDirectory.boolValue else {
                throw RorkSignError.invalidArchive(
                    "Temporary path is not a directory: \(rootURL.path)."
                )
            }
        } else {
            do {
                try fileManager.createDirectory(
                    at: rootURL,
                    withIntermediateDirectories: true
                )
            } catch {
                throw RorkSignError.invalidArchive(
                    "Temporary directory could not be created: \(error.localizedDescription)"
                )
            }
        }
        return rootURL
    }

    /// Returns the only top-level app bundle inside `Payload`.
    ///
    /// Signing and metadata extraction reject ambiguous payloads rather than
    /// silently selecting one app from an invalid multi-app archive.
    private static func payloadAppBundle(in archiveRootURL: URL) throws -> URL {
        let fileManager = FileManager.default
        let payloadURL = archiveRootURL.appendingPathComponent(
            "Payload",
            isDirectory: true
        )
        guard (try? fileManager.entry(at: payloadURL).kind) == .directory else {
            throw RorkSignError.invalidArchive(
                "IPA archive is missing a Payload directory."
            )
        }

        let appBundles = try fileManager.entries(
            in: payloadURL,
            options: .skipsHiddenFiles
        )
            .filter { entry in
                entry.kind == .directory
                    && entry.url.pathExtension.lowercased() == "app"
            }
            .map(\.url)
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        guard let appURL = appBundles.first else {
            throw RorkSignError.invalidArchive(
                "IPA archive has no app bundle in Payload."
            )
        }
        guard appBundles.count == 1 else {
            throw RorkSignError.invalidArchive(
                "IPA archive contains multiple app bundles in Payload."
            )
        }
        return appURL
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
        metadataRestoration: MetadataRestoration
    ) throws {
        guard metadataRestoration == .restore else {
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
        guard
            !path.isEmpty,
            !path.hasPrefix("/"),
            !path.contains("\\"),
            !path.contains("\0")
        else {
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
        let rootPath = normalizedFileSystemPath(
            rootURL.standardizedFileURL.path
        )
        let destinationPath = normalizedFileSystemPath(
            destinationURL.path
        )
        guard destinationPath.hasPrefix(rootPath + "/") else {
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
            !target.contains("\\"),
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
        let rootPath = normalizedFileSystemPath(
            rootURL.standardizedFileURL.path
        )
        let path = normalizedFileSystemPath(
            url.standardizedFileURL.path
        )
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
