import Foundation
@testable import RorkSign
import XCTest

final class BundleSignerMetadataTests: XCTestCase {
    /// Treats WASI's zero permission sentinel as unavailable metadata while
    /// preserving real executable modes on capable filesystems.
    func testRestorablePOSIXPermissionsIgnoreUnavailableMetadata() {
        XCTAssertNil(
            BundleSigner.restorablePOSIXPermissions(
                in: [.posixPermissions: NSNumber(value: 0)]
            )
        )
        XCTAssertEqual(
            BundleSigner.restorablePOSIXPermissions(
                in: [.posixPermissions: NSNumber(value: 0o755)]
            )?.intValue,
            0o755
        )
    }
}
