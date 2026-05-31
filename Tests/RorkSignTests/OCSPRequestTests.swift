import Foundation
import RorkSign
import XCTest

final class OCSPRequestTests: XCTestCase {
    func testBuildsOCSPRequestMatchingOpenSSLWithoutNonce() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let request = try RorkSigner.makeOCSPRequest(
            certificateAt: fixture.certificateURL,
            issuerCertificateAt: fixture.certificateURL
        )
        let opensslRequestURL = fixture.directory.appendingPathComponent("openssl-ocsp-request.der")
        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: [
                "ocsp",
                "-issuer", fixture.certificateURL.path,
                "-cert", fixture.certificateURL.path,
                "-no_nonce",
                "-reqout", opensslRequestURL.path,
            ]
        )

        XCTAssertEqual(request.derRepresentation, try Data(contentsOf: opensslRequestURL))
        XCTAssertNil(request.responderURL)
        XCTAssertEqual(request.issuerNameHash.count, 20)
        XCTAssertEqual(request.issuerKeyHash.count, 20)
        XCTAssertFalse(request.serialNumberHex.isEmpty)
    }

    func testOCSPRequestUsesAIAResponderURL() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let certificate = try fixture.selfSignedCertificate(
            commonName: "RorkSignOCSPRequest",
            ocspResponderURL: "http://ocsp.example.test/status"
        )

        let request = try RorkSigner.makeOCSPRequest(
            certificateData: certificate.der,
            issuerCertificateData: certificate.der
        )

        XCTAssertEqual(request.responderURL?.absoluteString, "http://ocsp.example.test/status")
    }

    func testOCSPRequestUsesAppleWWDRFallbackWhenAIAIsMissing() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let certificate = try fixture.selfSignedCertificate(
            commonName: "Apple Worldwide Developer Relations Certification Authority G6"
        )

        let request = try RorkSigner.makeOCSPRequest(
            certificateData: certificate.der,
            issuerCertificateData: certificate.der
        )

        XCTAssertEqual(request.responderURL?.absoluteString, "http://ocsp.apple.com/ocsp03-wwdrg6")
    }

    func testBuildsOCSPHTTPPostRequest() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let request = try makeRequestWithResponderURL(fixture: fixture)

        let urlRequest = try RorkSigner.makeOCSPURLRequest(
            request,
            options: OCSPHTTPOptions(
                timeout: 7,
                userAgent: "RorkSignTests",
                additionalHeaders: ["X-Test": "fixture"]
            )
        )

        XCTAssertEqual(urlRequest.url?.absoluteString, "http://ocsp.example.test/status")
        XCTAssertEqual(urlRequest.httpMethod, "POST")
        XCTAssertEqual(urlRequest.timeoutInterval, 7)
        XCTAssertEqual(urlRequest.httpBody, request.derRepresentation)
        XCTAssertEqual(urlRequest.value(forHTTPHeaderField: "Content-Type"), "application/ocsp-request")
        XCTAssertEqual(urlRequest.value(forHTTPHeaderField: "Accept"), "application/ocsp-response")
        XCTAssertEqual(urlRequest.value(forHTTPHeaderField: "Content-Length"), String(request.derRepresentation.count))
        XCTAssertEqual(urlRequest.value(forHTTPHeaderField: "User-Agent"), "RorkSignTests")
        XCTAssertEqual(urlRequest.value(forHTTPHeaderField: "X-Test"), "fixture")
    }

    func testRejectsOCSPHTTPRequestWithoutResponderURL() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let request = try RorkSigner.makeOCSPRequest(
            certificateAt: fixture.certificateURL,
            issuerCertificateAt: fixture.certificateURL
        )
        XCTAssertNil(request.responderURL)

        XCTAssertThrowsError(
            try RorkSigner.makeOCSPURLRequest(request)
        ) { error in
            XCTAssertEqual(error as? RorkSignError, .ocsp("OCSP request has no responder URL."))
        }
    }

    func testFetchesOCSPResponseOverHTTP() async throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let request = try makeRequestWithResponderURL(fixture: fixture)
        let responseDER = Data([0x30, 0x03, 0x0a, 0x01, 0x00])
        let session = mockOCSPSession()
        defer {
            OCSPMockURLProtocol.requestHandler = nil
            session.invalidateAndCancel()
        }
        OCSPMockURLProtocol.requestHandler = { urlRequest in
            XCTAssertEqual(urlRequest.url?.absoluteString, "http://ocsp.example.test/status")
            XCTAssertEqual(urlRequest.httpMethod, "POST")
            XCTAssertEqual(urlRequest.value(forHTTPHeaderField: "Content-Type"), "application/ocsp-request")
            return (
                HTTPURLResponse(
                    url: try XCTUnwrap(urlRequest.url),
                    statusCode: 200,
                    httpVersion: "HTTP/1.1",
                    headerFields: ["Content-Type": "application/ocsp-response"]
                )!,
                responseDER
            )
        }

        let report = try await RorkSigner.fetchOCSPResponse(
            request,
            options: OCSPHTTPOptions(userAgent: nil),
            session: session
        )

        XCTAssertEqual(report.request, request)
        XCTAssertEqual(report.responseDER, responseDER)
        XCTAssertEqual(report.statusCode, 200)
        XCTAssertEqual(report.contentType, "application/ocsp-response")
    }

    func testRejectsOCSPHTTPErrorStatus() async throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let request = try makeRequestWithResponderURL(fixture: fixture)
        let session = mockOCSPSession()
        defer {
            OCSPMockURLProtocol.requestHandler = nil
            session.invalidateAndCancel()
        }
        OCSPMockURLProtocol.requestHandler = { urlRequest in
            (
                HTTPURLResponse(
                    url: try XCTUnwrap(urlRequest.url),
                    statusCode: 500,
                    httpVersion: "HTTP/1.1",
                    headerFields: nil
                )!,
                Data([0x01])
            )
        }

        do {
            _ = try await RorkSigner.fetchOCSPResponse(request, session: session)
            XCTFail("Expected OCSP HTTP status failure.")
        } catch {
            XCTAssertEqual(error as? RorkSignError, .ocsp("OCSP responder returned HTTP status 500."))
        }
    }
}

private func makeRequestWithResponderURL(fixture: OpenSSLFixture) throws -> OCSPRequest {
    let certificate = try fixture.selfSignedCertificate(
        commonName: "RorkSignOCSPHTTP",
        ocspResponderURL: "http://ocsp.example.test/status"
    )
    return try RorkSigner.makeOCSPRequest(
        certificateData: certificate.der,
        issuerCertificateData: certificate.der
    )
}

private func mockOCSPSession() -> URLSession {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [OCSPMockURLProtocol.self]
    return URLSession(configuration: configuration)
}

private final class OCSPMockURLProtocol: URLProtocol {
    static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let requestHandler = Self.requestHandler else {
            client?.urlProtocol(
                self,
                didFailWithError: RorkSignError.cmsSigning("Missing OCSP URLProtocol handler.")
            )
            return
        }

        do {
            let (response, data) = try requestHandler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
