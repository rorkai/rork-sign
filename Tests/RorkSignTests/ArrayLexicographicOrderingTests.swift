@testable import RorkSign
import XCTest

/// Verifies the package-wide ordering operation used by canonical encoders.
final class ArrayLexicographicOrderingTests: XCTestCase {
    func testComparableSequencesAreSortedLexicographically() {
        let values = ["beta", "alphabet", "alpha"]

        XCTAssertEqual(
            values.sortedLexicographically(),
            ["alpha", "alphabet", "beta"]
        )
    }
}
