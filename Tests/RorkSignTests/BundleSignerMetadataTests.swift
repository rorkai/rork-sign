import Foundation
@testable import RorkSign
import XCTest

final class BundleSignerMetadataTests: XCTestCase {
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
