import Foundation
@testable import RorkSign
import XCTest

final class XMLPropertyListEncoderTests: XCTestCase {
    /// Round-trips every supported composite value through Foundation's decoder
    /// so the WASI writer remains compatible with native plist consumers.
    func testEncodesNestedPropertyListValues() throws {
        let date = Date(timeIntervalSince1970: 1_800_000_000)
        let propertyList: [String: Any] = [
            "array": [
                "value",
                7,
                [
                    "enabled": true,
                ],
            ],
            "data": Data([0x01, 0x02, 0x03]),
            "date": date,
            "real": 1.25,
        ]

        let data = try XMLPropertyListEncoder.encode(propertyList)
        let decoded = try XCTUnwrap(
            PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            ) as? [String: Any]
        )
        let array = try XCTUnwrap(decoded["array"] as? [Any])
        let nested = try XCTUnwrap(array[2] as? [String: Any])

        XCTAssertEqual(array[0] as? String, "value")
        XCTAssertEqual((array[1] as? NSNumber)?.intValue, 7)
        XCTAssertEqual(nested["enabled"] as? Bool, true)
        XCTAssertEqual(decoded["data"] as? Data, Data([0x01, 0x02, 0x03]))
        XCTAssertEqual(decoded["date"] as? Date, date)
        XCTAssertEqual((decoded["real"] as? NSNumber)?.doubleValue, 1.25)
    }

    /// Protects stable dictionary ordering and lossless XML escaping, both of
    /// which affect reproducibility of signed bundle resources.
    func testProducesDeterministicEscapedXML() throws {
        let data = try XMLPropertyListEncoder.encode([
            "z": "last",
            "a": "<value> & \"text\"",
        ])
        let xml = try XCTUnwrap(String(data: data, encoding: .utf8))

        XCTAssertLessThan(
            try XCTUnwrap(xml.range(of: "<key>a</key>")?.lowerBound),
            try XCTUnwrap(xml.range(of: "<key>z</key>")?.lowerBound)
        )
        XCTAssertTrue(xml.contains("<string>&lt;value&gt; &amp; \"text\"</string>"))
    }

    /// Ensures unsupported runtime values fail explicitly instead of producing
    /// a plist whose decoded type differs from the caller's input.
    func testRejectsUnsupportedValues() {
        XCTAssertThrowsError(
            try XMLPropertyListEncoder.encode([
                "url": URL(string: "https://rork.com")!,
            ])
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .unsupported(
                    "Property lists cannot encode values of type URL."
                )
            )
        }
    }
}
