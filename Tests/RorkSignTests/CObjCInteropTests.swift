import Foundation
import RorkSign
import RorkSignC
import RorkSignObjC
import XCTest

final class CObjCInteropTests: XCTestCase {
    func testCBridgeReturnsVersionPropertyList() throws {
        var valueBytes: UnsafeMutableRawPointer?
        var valueLength = 0
        var errorBytes: UnsafeMutablePointer<CChar>?
        var errorLength = 0

        XCTAssertTrue(RorkSignCExecute(
            RorkSignCOperationVersion,
            nil,
            0,
            &valueBytes,
            &valueLength,
            &errorBytes,
            &errorLength
        ))
        defer {
            RorkSignCFree(valueBytes)
            RorkSignCFree(errorBytes)
        }

        let value = try XCTUnwrap(valueBytes)
        let data = Data(bytes: value, count: valueLength)
        let response = try XCTUnwrap(PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any])
        XCTAssertEqual(response["version"] as? String, RorkSigner.version)
    }

    func testObjCFacadeInspectsMachOData() throws {
        let response = try RorkSignSigner.perform(
            .inspectMachO,
            request: ["data": Fixtures.machO64WithCodeSignature()]
        )

        let report = try XCTUnwrap(response["report"] as? [String: Any])
        XCTAssertEqual(report["kind"] as? String, "machO64")
        XCTAssertEqual(report["hasCodeSignature"] as? Bool, true)
    }

    func testObjCFacadeReturnsErrorForInvalidOperationInput() throws {
        XCTAssertThrowsError(try RorkSignSigner.perform(.inspectMachO, request: [:])) { error in
            let error = error as NSError
            XCTAssertEqual(error.domain, RorkSignObjCErrorDomain)
            XCTAssertTrue(error.localizedDescription.contains("Missing data field"))
        }
    }
}
