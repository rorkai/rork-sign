import Foundation
@testable import RorkSign
import XCTest

final class PropertyListWriterTests: XCTestCase {
    /// Round-trips every supported composite value through Foundation's decoder
    /// so browser-generated resources remain compatible with native consumers.
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

        let data = try PropertyListWriter.data(
            from: propertyList,
            format: .xml
        )
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
        let data = try PropertyListWriter.data(
            from: [
                "z": "last",
                "a": "<value> & \"text\"",
            ],
            format: .xml
        )
        let xml = try XCTUnwrap(String(data: data, encoding: .utf8))

        XCTAssertLessThan(
            try XCTUnwrap(xml.range(of: "<key>a</key>")?.lowerBound),
            try XCTUnwrap(xml.range(of: "<key>z</key>")?.lowerBound)
        )
        XCTAssertTrue(xml.contains("<string>&lt;value&gt; &amp; \"text\"</string>"))
    }

    /// Preserves binary output for signing structures that require the compact
    /// representation instead of silently substituting XML on WASI.
    func testProducesRequestedBinaryFormat() throws {
        let data = try PropertyListWriter.data(
            from: [
                "enabled": true,
            ],
            format: .binary
        )

        XCTAssertEqual(data.prefix(8), Data("bplist00".utf8))
        XCTAssertEqual(
            try PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            ) as? [String: Bool],
            [
                "enabled": true,
            ]
        )
    }

    /// Protects decoded integer values from `NSNumber`'s permissive Boolean
    /// bridge, which also accepts the numeric values zero and one.
    func testPreservesIntegerNSNumberKind() throws {
        let data = try PropertyListWriter.data(
            from: [
                "boolean": NSNumber(value: true),
                "integer": NSNumber(value: 1),
                "smallInteger": NSNumber(value: Int8(1)),
            ],
            format: .xml
        )
        let decoded = try XCTUnwrap(
            PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            ) as? [String: Any]
        )
        let boolean = try XCTUnwrap(decoded["boolean"] as? NSNumber)
        let integer = try XCTUnwrap(decoded["integer"] as? NSNumber)
        let smallInteger = try XCTUnwrap(decoded["smallInteger"] as? NSNumber)
        let booleanNumberType = ObjectIdentifier(
            type(of: NSNumber(value: true))
        )

        XCTAssertTrue(boolean.boolValue)
        XCTAssertEqual(ObjectIdentifier(type(of: boolean)), booleanNumberType)
        XCTAssertNotEqual(
            ObjectIdentifier(type(of: integer)),
            booleanNumberType
        )
        XCTAssertNotEqual(
            ObjectIdentifier(type(of: smallInteger)),
            booleanNumberType
        )
        XCTAssertEqual(integer.intValue, 1)
        XCTAssertEqual(smallInteger.int8Value, 1)
    }

    /// Ensures unsupported runtime values fail explicitly instead of producing
    /// a plist whose decoded type differs from the caller's input.
    func testRejectsUnsupportedValues() {
        XCTAssertThrowsError(
            try PropertyListWriter.data(
                from: [
                    "url": URL(string: "https://rork.com")!,
                ],
                format: .xml
            )
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
