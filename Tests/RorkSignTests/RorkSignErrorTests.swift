import Foundation
import XCTest

@testable import RorkSign

final class RorkSignErrorTests: XCTestCase {
    func testLocalizedDescriptionPreservesAssociatedMessage() {
        let message = "Signed IPA archive could not be enumerated."
        let error = RorkSignError.invalidArchive(message)

        XCTAssertEqual(error.localizedDescription, message)
    }
}
