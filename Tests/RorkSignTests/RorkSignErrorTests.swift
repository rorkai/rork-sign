import Foundation
import XCTest

@testable import RorkSign

final class RorkSignErrorTests: XCTestCase {
    /// Protects the actionable message when Swift errors cross NSError, CLI,
    /// and browser interop boundaries.
    func testLocalizedDescriptionPreservesAssociatedMessage() {
        let message = "Signed IPA archive could not be enumerated."
        let error = RorkSignError.invalidArchive(message)

        XCTAssertEqual(error.localizedDescription, message)
    }
}
