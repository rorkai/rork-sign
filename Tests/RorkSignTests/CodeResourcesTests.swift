import Foundation
import RorkSign
import XCTest

final class CodeResourcesTests: XCTestCase {
    func testBuildsCodeResourcesForRegularFilesAndSymlinks() throws {
        let bundleURL = try makeResourceFixtureBundle()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let data = try RorkSigner.buildCodeResources(forBundleAt: bundleURL)
        let plist = try parseCodeResources(data)
        let files = try XCTUnwrap(plist["files"] as? [String: Any])
        let files2 = try XCTUnwrap(plist["files2"] as? [String: [String: Any]])

        XCTAssertEqual(files["asset.txt"] as? Data, sha1("asset"))
        XCTAssertEqual(
            files["Info.plist"] as? Data,
            try sha1File(bundleURL.appendingPathComponent("Info.plist"))
        )
        XCTAssertEqual(files[".DS_Store"] as? Data, sha1("junk"))
        let localizedEntry = try XCTUnwrap(files["en.lproj/Localizable.strings"] as? [String: Any])
        XCTAssertEqual(localizedEntry["hash"] as? Data, sha1("strings"))
        XCTAssertEqual(localizedEntry["optional"] as? Bool, true)
        XCTAssertNil(files["Test"])
        XCTAssertNil(files["en.lproj/locversion.plist"])
        XCTAssertNil(files["_CodeSignature/CodeResources"])

        let assetEntry = try XCTUnwrap(files2["asset.txt"])
        XCTAssertEqual(assetEntry["hash"] as? Data, sha1("asset"))
        XCTAssertEqual(assetEntry["hash2"] as? Data, sha256("asset"))
        let localizedEntry2 = try XCTUnwrap(files2["en.lproj/Localizable.strings"])
        XCTAssertEqual(localizedEntry2["hash"] as? Data, sha1("strings"))
        XCTAssertEqual(localizedEntry2["hash2"] as? Data, sha256("strings"))
        XCTAssertEqual(localizedEntry2["optional"] as? Bool, true)
        XCTAssertEqual(files2["link.txt"]?["symlink"] as? String, "asset.txt")
        XCTAssertNil(files2["Info.plist"])
        XCTAssertNil(files2["Test"])
        XCTAssertNil(files2["SC_Info/metadata"])
        XCTAssertNil(files2[".DS_Store"])
        XCTAssertNil(files2["en.lproj/locversion.plist"])

        let rules2 = try XCTUnwrap(plist["rules2"] as? [String: Any])
        let infoRule = try XCTUnwrap(rules2["^Info\\.plist$"] as? [String: Any])
        XCTAssertEqual(infoRule["omit"] as? Bool, true)
        XCTAssertEqual(infoRule["weight"] as? Int, 20)
        let mobileProvisionRule = try XCTUnwrap(rules2["^embedded\\.mobileprovision$"] as? [String: Any])
        XCTAssertEqual(mobileProvisionRule["weight"] as? Int, 20)
        XCTAssertNil(rules2["^embedded\\.provisionprofile$"])
    }

    func testSealBundleResourcesWritesCodeSignatureFile() throws {
        let bundleURL = try makeResourceFixtureBundle()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let outputURL = try RorkSigner.sealBundleResources(at: bundleURL)

        XCTAssertEqual(outputURL.lastPathComponent, "CodeResources")
        XCTAssertTrue(FileManager.default.fileExists(atPath: outputURL.path))
        _ = try parseCodeResources(Data(contentsOf: outputURL))
    }

    func testVerifyCodeResourcesAcceptsCurrentBundle() throws {
        let bundleURL = try makeResourceFixtureBundle()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try RorkSigner.sealBundleResources(at: bundleURL)

        let report = try RorkSigner.verifyCodeResources(forBundleAt: bundleURL)

        XCTAssertTrue(report.isValid)
        XCTAssertEqual(report.sealedResourceCount, 3)
        XCTAssertEqual(report.verifiedResourceCount, 3)
        XCTAssertEqual(report.missingResources, [])
        XCTAssertEqual(report.mismatchedResources, [])
        XCTAssertEqual(report.unsealedResources, [])
    }

    func testVerifyCodeResourcesAllowsMissingOptionalLocalizationResource() throws {
        let bundleURL = try makeResourceFixtureBundle()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try RorkSigner.sealBundleResources(at: bundleURL)
        try FileManager.default.removeItem(
            at: bundleURL.appendingPathComponent("en.lproj/Localizable.strings")
        )

        let report = try RorkSigner.verifyCodeResources(forBundleAt: bundleURL)

        XCTAssertTrue(report.isValid)
        XCTAssertEqual(report.sealedResourceCount, 3)
        XCTAssertEqual(report.verifiedResourceCount, 2)
        XCTAssertEqual(report.missingResources, [])
        XCTAssertEqual(report.mismatchedResources, [])
        XCTAssertEqual(report.unsealedResources, [])
    }

    func testVerifyCodeResourcesReportsTamperedResource() throws {
        let bundleURL = try makeResourceFixtureBundle()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try RorkSigner.sealBundleResources(at: bundleURL)
        try Data("changed".utf8).write(to: bundleURL.appendingPathComponent("asset.txt"))

        let report = try RorkSigner.verifyCodeResources(forBundleAt: bundleURL)

        XCTAssertFalse(report.isValid)
        XCTAssertEqual(report.missingResources, [])
        XCTAssertEqual(report.mismatchedResources, ["asset.txt"])
        XCTAssertEqual(report.unsealedResources, [])
    }

    func testVerifyCodeResourcesReportsMissingRequiredResource() throws {
        let bundleURL = try makeResourceFixtureBundle()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try RorkSigner.sealBundleResources(at: bundleURL)
        try FileManager.default.removeItem(at: bundleURL.appendingPathComponent("asset.txt"))

        let report = try RorkSigner.verifyCodeResources(forBundleAt: bundleURL)

        XCTAssertFalse(report.isValid)
        XCTAssertEqual(report.missingResources, ["asset.txt"])
        XCTAssertEqual(report.mismatchedResources, [])
        XCTAssertEqual(report.unsealedResources, [])
    }

    func testVerifyCodeResourcesReportsUnsealedResource() throws {
        let bundleURL = try makeResourceFixtureBundle()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try RorkSigner.sealBundleResources(at: bundleURL)
        try Data("new".utf8).write(to: bundleURL.appendingPathComponent("new-resource.txt"))

        let report = try RorkSigner.verifyCodeResources(forBundleAt: bundleURL)

        XCTAssertFalse(report.isValid)
        XCTAssertEqual(report.missingResources, [])
        XCTAssertEqual(report.mismatchedResources, [])
        XCTAssertEqual(report.unsealedResources, ["new-resource.txt"])
    }

    func testVerifyCodeResourcesRecursivelyReportsNestedBundles() throws {
        let bundleURL = try makeNestedResourceFixtureBundle()
        let nestedURL = bundleURL.appendingPathComponent("Frameworks/Nested.framework", isDirectory: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try RorkSigner.sealBundleResources(at: nestedURL)
        try RorkSigner.sealBundleResources(at: bundleURL)
        try Data("changed nested asset".utf8).write(to: nestedURL.appendingPathComponent("asset.txt"))

        let reports = try RorkSigner.verifyCodeResourcesRecursively(forBundleAt: bundleURL)

        XCTAssertEqual(reports.map(\.relativeBundlePath), [".", "Frameworks/Nested.framework"])
        XCTAssertEqual(reports.map(\.isValid), [false, false])
        XCTAssertEqual(reports[0].mismatchedPaths, ["Frameworks/Nested.framework/asset.txt"])
        XCTAssertEqual(reports[1].mismatchedPaths, ["asset.txt"])
    }
}

private func makeResourceFixtureBundle() throws -> URL {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let bundleURL = rootURL.appendingPathComponent("Fixture.app", isDirectory: true)
    try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)

    let infoPlist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict><key>CFBundleIdentifier</key><string>app.rork.fixture</string><key>CFBundleExecutable</key><string>Test</string></dict></plist>
    """
    try Data(infoPlist.utf8).write(to: bundleURL.appendingPathComponent("Info.plist"))
    try Data("executable".utf8).write(to: bundleURL.appendingPathComponent("Test"))
    try Data("asset".utf8).write(to: bundleURL.appendingPathComponent("asset.txt"))
    try Data("junk".utf8).write(to: bundleURL.appendingPathComponent(".DS_Store"))
    let localizationURL = bundleURL.appendingPathComponent("en.lproj", isDirectory: true)
    try FileManager.default.createDirectory(at: localizationURL, withIntermediateDirectories: true)
    try Data("strings".utf8).write(to: localizationURL.appendingPathComponent("Localizable.strings"))
    try Data("loc".utf8).write(to: localizationURL.appendingPathComponent("locversion.plist"))

    let codeSignatureURL = bundleURL.appendingPathComponent("_CodeSignature", isDirectory: true)
    try FileManager.default.createDirectory(at: codeSignatureURL, withIntermediateDirectories: true)
    try Data("old".utf8).write(to: codeSignatureURL.appendingPathComponent("CodeResources"))

    let scInfoURL = bundleURL.appendingPathComponent("SC_Info", isDirectory: true)
    try FileManager.default.createDirectory(at: scInfoURL, withIntermediateDirectories: true)
    try Data("metadata".utf8).write(to: scInfoURL.appendingPathComponent("metadata"))

    try FileManager.default.createSymbolicLink(
        atPath: bundleURL.appendingPathComponent("link.txt").path,
        withDestinationPath: "asset.txt"
    )
    return bundleURL
}

private func makeNestedResourceFixtureBundle() throws -> URL {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let bundleURL = rootURL.appendingPathComponent("Host.app", isDirectory: true)
    let nestedURL = bundleURL.appendingPathComponent("Frameworks/Nested.framework", isDirectory: true)
    try FileManager.default.createDirectory(at: nestedURL, withIntermediateDirectories: true)

    try Data(resourceInfoPlist(bundleIdentifier: "app.rork.resources", executableName: "Host").utf8)
        .write(to: bundleURL.appendingPathComponent("Info.plist"))
    try Data(resourceInfoPlist(bundleIdentifier: "app.rork.resources.nested", executableName: "Nested").utf8)
        .write(to: nestedURL.appendingPathComponent("Info.plist"))
    try Data("host executable".utf8).write(to: bundleURL.appendingPathComponent("Host"))
    try Data("nested executable".utf8).write(to: nestedURL.appendingPathComponent("Nested"))
    try Data("host asset".utf8).write(to: bundleURL.appendingPathComponent("asset.txt"))
    try Data("nested asset".utf8).write(to: nestedURL.appendingPathComponent("asset.txt"))
    return bundleURL
}

private func resourceInfoPlist(bundleIdentifier: String, executableName: String) -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict><key>CFBundleIdentifier</key><string>\(bundleIdentifier)</string><key>CFBundleExecutable</key><string>\(executableName)</string></dict></plist>
    """
}

private extension BundleCodeResourcesVerificationReport {
    var mismatchedPaths: [String] {
        codeResources.mismatchedResources
    }
}
