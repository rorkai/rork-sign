import Foundation
@testable import RorkSign
import XCTest
import ZipArchive

extension FileManager {
    /// Creates an IPA fixture through RorkSign's production archive boundary.
    ///
    /// Using the same implementation as the CLI prevents tests from silently
    /// relying on behavior supplied only by a separate ZIP library.
    func createIPAArchive(
        contentsOf rootURL: URL,
        at archiveURL: URL,
        compressionMode: ArchiveCompressionMode = .stored
    ) throws {
        try IPAArchive.write(
            contentsOf: rootURL,
            to: archiveURL,
            compressionMode: compressionMode
        )
    }

    /// Extracts an IPA fixture through RorkSign's production validation path.
    ///
    /// Tests use this path when inspecting command output so path and symbolic
    /// link validation remain part of the exercised behavior.
    func extractIPAArchive(
        at archiveURL: URL,
        to rootURL: URL
    ) throws {
        _ = try IPAArchive.extract(at: archiveURL, to: rootURL)
    }
}

/// Reports whether an entry is compressed in the serialized ZIP archive.
///
/// Compression is archive metadata rather than a filesystem operation, so this
/// query intentionally remains separate from the `FileManager` extension.
func isArchiveEntryCompressed(
    _ path: String,
    in archiveURL: URL
) throws -> Bool {
    try ZipArchiveReader<ZipFileStorage>.withFile(archiveURL.path) { reader in
        let entry = try XCTUnwrap(
            try reader.readDirectory().first {
                $0.pathInArchive == path
            }
        )
        return entry.compressionMethod != .noCompression
    }
}
