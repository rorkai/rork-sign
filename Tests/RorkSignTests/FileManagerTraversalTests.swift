import Foundation
@testable import RorkSign
import XCTest

final class FileManagerTraversalTests: XCTestCase {
    /// Exercises the entry model used by both native metadata lookup and the
    /// browser WASI fallback.
    func testEntriesClassifyDirectoriesAndRegularFiles() throws {
        let rootURL = try makeTemporaryDirectory()
        defer {
            try? FileManager.default.removeItem(at: rootURL)
        }

        let directoryURL = rootURL.appendingPathComponent(
            "Frameworks",
            isDirectory: true
        )
        let fileURL = rootURL.appendingPathComponent("Info.plist")
        try FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true
        )
        try Data("plist".utf8).write(to: fileURL)

        let entries = try FileManager.default.entries(in: rootURL)
        XCTAssertEqual(
            Dictionary(
                uniqueKeysWithValues: entries.map {
                    ($0.url.lastPathComponent, $0.kind)
                }
            ),
            [
                "Frameworks": .directory,
                "Info.plist": .regularFile,
            ]
        )
    }

    /// Protects subtree pruning used to keep nested bundles in their own
    /// independent signing pass.
    func testEnumerationCanSkipDirectoryDescendants() throws {
        let rootURL = try makeTemporaryDirectory()
        defer {
            try? FileManager.default.removeItem(at: rootURL)
        }

        let frameworkURL = rootURL.appendingPathComponent(
            "Nested.framework",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: frameworkURL,
            withIntermediateDirectories: true
        )
        try Data("nested".utf8).write(
            to: frameworkURL.appendingPathComponent("Nested")
        )
        try Data("root".utf8).write(
            to: rootURL.appendingPathComponent("Root")
        )

        var visitedPaths: [String] = []
        try FileManager.default.enumerateDescendants(of: rootURL) { entry in
            visitedPaths.append(entry.url.lastPathComponent)
            return entry.url.lastPathComponent == "Nested.framework"
                ? .skipDescendants
                : .visitDescendants
        }

        XCTAssertEqual(visitedPaths, ["Nested.framework", "Root"])
    }

    /// Ensures a link to a directory remains a leaf so traversal cannot escape
    /// its caller-provided root.
    func testEnumerationDoesNotDescendThroughSymbolicLinks() throws {
        let rootURL = try makeTemporaryDirectory()
        let targetURL = try makeTemporaryDirectory()
        defer {
            try? FileManager.default.removeItem(at: rootURL)
            try? FileManager.default.removeItem(at: targetURL)
        }

        try Data("target".utf8).write(
            to: targetURL.appendingPathComponent("File")
        )
        let linkURL = rootURL.appendingPathComponent("Link")
        try FileManager.default.createSymbolicLink(
            at: linkURL,
            withDestinationURL: targetURL
        )

        var entries: [String: FileSystemEntry.Kind] = [:]
        try FileManager.default.enumerateDescendants(of: rootURL) { entry in
            entries[entry.url.lastPathComponent] = entry.kind
            return .visitDescendants
        }

        XCTAssertEqual(entries["Link"], .symbolicLink)
        XCTAssertNil(entries["File"])
    }

    /// Creates an isolated real filesystem root.
    ///
    /// Traversal behavior depends on actual directory and symlink metadata, so
    /// an in-memory fixture would not exercise the production contract.
    private func makeTemporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )
        return url
    }
}
