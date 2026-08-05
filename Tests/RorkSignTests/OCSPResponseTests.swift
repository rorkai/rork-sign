import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import RorkSign
import XCTest

final class OCSPResponseTests: XCTestCase {
    func testParsesSuccessfulGoodOCSPResponse() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(fixture: fixture, status: .good)
        let request = try RorkSigner.makeOCSPRequest(
            certificateAt: fixture.certificateURL,
            issuerCertificateAt: fixture.certificateURL
        )

        let report = try RorkSigner.parseOCSPResponse(at: response.url)

        XCTAssertEqual(report.responseStatus, .successful)
        XCTAssertEqual(report.responseTypeOID, "1.3.6.1.5.5.7.48.1.1")
        XCTAssertNotNil(report.producedAt)
        XCTAssertEqual(report.singleResponses.count, 1)
        XCTAssertEqual(report.singleResponses[0].certificateStatus, .good)
        XCTAssertEqual(report.singleResponses[0].serialNumberHex, response.serialNumberHex)
        XCTAssertEqual(report.singleResponses[0].issuerNameHash, request.issuerNameHash)
        XCTAssertEqual(report.singleResponses[0].issuerKeyHash, request.issuerKeyHash)
        XCTAssertNotNil(report.singleResponses[0].nextUpdate)
        XCTAssertNotNil(report.signedResponseData)
        XCTAssertEqual(report.signatureAlgorithmOID, "1.2.840.113549.1.1.11")
        XCTAssertNotNil(report.signature)
        XCTAssertTrue(report.responderCertificatesDER.isEmpty)
    }

    func testParsesSuccessfulRevokedOCSPResponse() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let revocationDate = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970) - 3600)
        let response = try makeOCSPResponse(fixture: fixture, status: .revoked(revocationDate))

        let report = try RorkSigner.parseOCSPResponse(Data(contentsOf: response.url))

        XCTAssertEqual(report.responseStatus, .successful)
        XCTAssertEqual(report.singleResponses.count, 1)
        guard case .revoked(let parsedDate, let reason) = report.singleResponses[0].certificateStatus else {
            return XCTFail("Expected revoked OCSP certificate status.")
        }
        XCTAssertEqual(parsedDate.timeIntervalSince1970, revocationDate.timeIntervalSince1970, accuracy: 1)
        XCTAssertNil(reason)
    }

    func testVerifiesOCSPResponseSignatureWithSuppliedResponderCertificate() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(fixture: fixture, status: .good)

        let verification = try RorkSigner.verifyOCSPResponseSignature(
            at: response.url,
            responderCertificateAt: fixture.certificateURL
        )

        XCTAssertEqual(verification.response.responseStatus, .successful)
        XCTAssertEqual(verification.responderCertificate.subjectCommonName, "RorkSignTest")
        XCTAssertFalse(verification.usedEmbeddedResponderCertificate)
    }

    func testVerifiesOCSPResponseRSASHA1AndSHA512SignatureAlgorithms() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let signedResponseData = Data("ocsp response data".utf8)
        let certificateDER = try XCTUnwrap(
            SigningIdentity.certificateChainDER(from: Data(contentsOf: fixture.certificateURL)).first
        )

        for (digest, algorithmOID) in [
            ("sha1", "1.2.840.113549.1.1.5"),
            ("sha512", "1.2.840.113549.1.1.13"),
        ] {
            let signature = try openSSLSignature(
                digest: digest,
                privateKeyURL: fixture.privateKeyURL,
                data: signedResponseData,
                directory: fixture.directory
            )

            try OCSPSignatureVerifier.verifySignature(
                signature,
                algorithmOID: algorithmOID,
                certificateDER: certificateDER,
                signedResponseData: signedResponseData
            )
        }
    }

    func testVerifiesOCSPResponseECDSASHA384SignatureAlgorithm() throws {
        let fixture = try OpenSSLECFixture(curve: .p384)
        defer {
            fixture.remove()
        }
        let signedResponseData = Data("ocsp response data".utf8)
        let certificateDER = try XCTUnwrap(
            SigningIdentity.certificateChainDER(from: Data(contentsOf: fixture.certificateURL)).first
        )
        let signature = try openSSLSignature(
            digest: "sha384",
            privateKeyURL: fixture.privateKeyURL,
            data: signedResponseData,
            directory: fixture.directory
        )

        try OCSPSignatureVerifier.verifySignature(
            signature,
            algorithmOID: "1.2.840.10045.4.3.3",
            certificateDER: certificateDER,
            signedResponseData: signedResponseData
        )
    }

    func testValidatesOCSPResponseForMatchingRequestAndFreshnessPolicy() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(fixture: fixture, status: .good)
        let request = try RorkSigner.makeOCSPRequest(
            certificateAt: fixture.certificateURL,
            issuerCertificateAt: fixture.certificateURL
        )

        let validation = try RorkSigner.validateOCSPResponse(
            at: response.url,
            matching: request,
            responderCertificateAt: fixture.certificateURL,
            issuerCertificateAt: fixture.certificateURL,
            policy: OCSPResponseValidationPolicy(maximumAge: 3600, requiresNextUpdate: true)
        )

        XCTAssertEqual(validation.matchedResponse.serialNumberHex, response.serialNumberHex)
        XCTAssertEqual(validation.matchedResponse.certificateStatus, .good)
        XCTAssertEqual(validation.signatureVerification.responderCertificate.subjectCommonName, "RorkSignTest")
        XCTAssertEqual(validation.responderAuthorization, .issuerCertificate)
    }

    func testChecksOCSPStatusOverHTTPAndValidatesFetchedResponse() async throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(fixture: fixture, status: .good)
        let responderURL = try XCTUnwrap(URL(string: "http://ocsp.example.test/status"))
        let session = ocspStatusMockSession()
        defer {
            session.invalidateAndCancel()
        }
        let responseDER = try Data(contentsOf: response.url)

        let report = try await RorkSigner.checkOCSPStatus(
            certificateData: Data(contentsOf: fixture.certificateURL),
            issuerCertificateData: Data(contentsOf: fixture.certificateURL),
            responderURL: responderURL,
            policy: OCSPResponseValidationPolicy(maximumAge: 3600, requiresNextUpdate: true),
            httpOptions: OCSPHTTPOptions(
                additionalHeaders: [
                    "X-RorkSign-Test-Body": responseDER.base64EncodedString(),
                ]
            ),
            session: session
        )

        XCTAssertEqual(report.request.responderURL, responderURL)
        XCTAssertEqual(report.fetch.statusCode, 200)
        XCTAssertEqual(report.certificateStatus, .good)
        XCTAssertEqual(report.validation.matchedResponse.serialNumberHex, response.serialNumberHex)
        XCTAssertEqual(report.validation.responderAuthorization, .issuerCertificate)
    }

    func testValidatesDelegatedOCSPResponderAuthorization() throws {
        let fixture = try DelegatedOCSPFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(
            directory: fixture.directory,
            certificateURL: fixture.leafCertificateURL,
            privateKeyURL: fixture.leafPrivateKeyURL,
            issuerCertificateURL: fixture.issuerCertificateURL,
            responderCertificateURL: fixture.responderCertificateURL,
            responderPrivateKeyURL: fixture.responderPrivateKeyURL,
            status: .good
        )
        let request = try RorkSigner.makeOCSPRequest(
            certificateAt: fixture.leafCertificateURL,
            issuerCertificateAt: fixture.issuerCertificateURL
        )

        let validation = try RorkSigner.validateOCSPResponse(
            at: response.url,
            matching: request,
            responderCertificateAt: fixture.responderCertificateURL,
            issuerCertificateAt: fixture.issuerCertificateURL
        )

        XCTAssertEqual(validation.matchedResponse.serialNumberHex, response.serialNumberHex)
        XCTAssertEqual(validation.responderAuthorization, .delegatedResponder)
        XCTAssertEqual(validation.signatureVerification.responderCertificate.subjectCommonName, "RorkSignOCSPResponder")
    }

    func testRejectsDelegatedOCSPResponderWithoutOCSPEKU() throws {
        let fixture = try DelegatedOCSPFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(
            directory: fixture.directory,
            certificateURL: fixture.leafCertificateURL,
            privateKeyURL: fixture.leafPrivateKeyURL,
            issuerCertificateURL: fixture.issuerCertificateURL,
            responderCertificateURL: fixture.unauthorizedResponderCertificateURL,
            responderPrivateKeyURL: fixture.unauthorizedResponderPrivateKeyURL,
            status: .good
        )
        let request = try RorkSigner.makeOCSPRequest(
            certificateAt: fixture.leafCertificateURL,
            issuerCertificateAt: fixture.issuerCertificateURL
        )

        XCTAssertThrowsError(
            try RorkSigner.validateOCSPResponse(
                at: response.url,
                matching: request,
                responderCertificateAt: fixture.unauthorizedResponderCertificateURL,
                issuerCertificateAt: fixture.issuerCertificateURL
            )
        ) { error in
            XCTAssertEqual(error as? RorkSignError, .cmsSigning("OCSP responder certificate is missing id-kp-OCSPSigning."))
        }
    }

    func testRejectsOCSPResponseThatDoesNotMatchRequestCertID() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(fixture: fixture, status: .good)
        let otherCertificate = try fixture.selfSignedCertificate(commonName: "RorkSignOtherOCSPSubject")
        let otherRequest = try RorkSigner.makeOCSPRequest(
            certificateData: otherCertificate.der,
            issuerCertificateData: otherCertificate.der
        )

        XCTAssertThrowsError(
            try RorkSigner.validateOCSPResponse(
                at: response.url,
                matching: otherRequest,
                responderCertificateAt: fixture.certificateURL
            )
        ) { error in
            XCTAssertEqual(error as? RorkSignError, .cmsSigning("OCSP response does not match the request CertID."))
        }
    }

    func testRejectsExpiredOCSPResponseNextUpdate() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(fixture: fixture, status: .good)
        let request = try RorkSigner.makeOCSPRequest(
            certificateAt: fixture.certificateURL,
            issuerCertificateAt: fixture.certificateURL
        )
        let parsed = try RorkSigner.parseOCSPResponse(at: response.url)
        let nextUpdate = try XCTUnwrap(parsed.singleResponses[0].nextUpdate)

        XCTAssertThrowsError(
            try RorkSigner.validateOCSPResponse(
                at: response.url,
                matching: request,
                responderCertificateAt: fixture.certificateURL,
                policy: OCSPResponseValidationPolicy(
                    validationDate: nextUpdate.addingTimeInterval(60),
                    allowedClockSkew: 0
                )
            )
        ) { error in
            XCTAssertEqual(error as? RorkSignError, .cmsSigning("OCSP response nextUpdate is expired."))
        }
    }

    func testRejectsOCSPResponseWithoutRequiredNextUpdate() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(fixture: fixture, status: .good, nextUpdateDays: nil)
        let request = try RorkSigner.makeOCSPRequest(
            certificateAt: fixture.certificateURL,
            issuerCertificateAt: fixture.certificateURL
        )
        XCTAssertNil(try RorkSigner.parseOCSPResponse(at: response.url).singleResponses[0].nextUpdate)

        XCTAssertThrowsError(
            try RorkSigner.validateOCSPResponse(
                at: response.url,
                matching: request,
                responderCertificateAt: fixture.certificateURL,
                policy: OCSPResponseValidationPolicy(requiresNextUpdate: true)
            )
        ) { error in
            XCTAssertEqual(error as? RorkSignError, .cmsSigning("OCSP response does not contain nextUpdate."))
        }
    }

    func testRejectsOCSPResponseOlderThanMaximumAge() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(fixture: fixture, status: .good)
        let request = try RorkSigner.makeOCSPRequest(
            certificateAt: fixture.certificateURL,
            issuerCertificateAt: fixture.certificateURL
        )
        let thisUpdate = try RorkSigner.parseOCSPResponse(at: response.url).singleResponses[0].thisUpdate

        XCTAssertThrowsError(
            try RorkSigner.validateOCSPResponse(
                at: response.url,
                matching: request,
                responderCertificateAt: fixture.certificateURL,
                policy: OCSPResponseValidationPolicy(
                    validationDate: thisUpdate.addingTimeInterval(3600),
                    allowedClockSkew: 0,
                    maximumAge: 60
                )
            )
        ) { error in
            XCTAssertEqual(error as? RorkSignError, .cmsSigning("OCSP response is older than maximumAge."))
        }
    }

    func testVerifiesOCSPResponseSignatureWithEmbeddedResponderCertificate() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(
            fixture: fixture,
            status: .good,
            embedResponderCertificate: true
        )

        let verification = try RorkSigner.verifyOCSPResponseSignature(at: response.url)

        XCTAssertEqual(verification.response.responderCertificatesDER.count, 1)
        XCTAssertEqual(verification.responderCertificate.subjectCommonName, "RorkSignTest")
        XCTAssertTrue(verification.usedEmbeddedResponderCertificate)
    }

    func testRejectsTamperedOCSPResponseSignature() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let response = try makeOCSPResponse(fixture: fixture, status: .good)
        var data = try Data(contentsOf: response.url)
        data[data.count - 1] ^= 0x01

        XCTAssertThrowsError(
            try RorkSigner.verifyOCSPResponseSignature(
                data,
                responderCertificateData: try Data(contentsOf: fixture.certificateURL)
            )
        ) { error in
            XCTAssertEqual(error as? RorkSignError, .cmsSigning("OCSP RSA signature is invalid."))
        }
    }

    func testParsesNonSuccessfulOCSPResponseStatus() throws {
        let malformedRequest = Data([0x30, 0x03, 0x0a, 0x01, 0x01])

        let report = try RorkSigner.parseOCSPResponse(malformedRequest)

        XCTAssertEqual(report.responseStatus, .malformedRequest)
        XCTAssertNil(report.responseTypeOID)
        XCTAssertNil(report.producedAt)
        XCTAssertTrue(report.singleResponses.isEmpty)
    }
}

private enum TestOCSPCertificateStatus {
    case good
    case revoked(Date)
}

private func makeOCSPResponse(
    fixture: OpenSSLFixture,
    status: TestOCSPCertificateStatus,
    embedResponderCertificate: Bool = false,
    nextUpdateDays: Int? = 1
) throws -> (url: URL, serialNumberHex: String) {
    try makeOCSPResponse(
        directory: fixture.directory,
        certificateURL: fixture.certificateURL,
        privateKeyURL: fixture.privateKeyURL,
        status: status,
        embedResponderCertificate: embedResponderCertificate,
        nextUpdateDays: nextUpdateDays
    )
}

private func makeOCSPResponse(
    directory: URL,
    certificateURL: URL,
    privateKeyURL: URL,
    issuerCertificateURL: URL? = nil,
    responderCertificateURL: URL? = nil,
    responderPrivateKeyURL: URL? = nil,
    status: TestOCSPCertificateStatus,
    embedResponderCertificate: Bool = false,
    nextUpdateDays: Int? = 1
) throws -> (url: URL, serialNumberHex: String) {
    let issuerCertificateURL = issuerCertificateURL ?? certificateURL
    let responderCertificateURL = responderCertificateURL ?? certificateURL
    let responderPrivateKeyURL = responderPrivateKeyURL ?? privateKeyURL
    let certificateReport = try RorkSigner.checkCertificate(at: certificateURL)
    let serialNumber = certificateReport.serialNumberHex.replacingOccurrences(of: ":", with: "")
    let expirationDate = certificateReport.expirationDate
    let indexURL = directory.appendingPathComponent(UUID().uuidString + "-index.txt")
    let responseURL = directory.appendingPathComponent(UUID().uuidString + "-ocsp-response.der")
    let subject = "/CN=\(certificateReport.subjectCommonName)"

    let indexLine: String
    switch status {
    case .good:
        indexLine = "V\t\(ocspIndexDate(expirationDate))\t\t\(serialNumber)\tunknown\t\(subject)\n"
    case .revoked(let revocationDate):
        indexLine = "R\t\(ocspIndexDate(expirationDate))\t\(ocspIndexDate(revocationDate))\t\(serialNumber)\tunknown\t\(subject)\n"
    }
    try Data(indexLine.utf8).write(to: indexURL)

    var arguments = [
        "ocsp",
        "-index", indexURL.path,
        "-issuer", issuerCertificateURL.path,
        "-cert", certificateURL.path,
        "-rsigner", responderCertificateURL.path,
        "-rkey", responderPrivateKeyURL.path,
        "-CA", issuerCertificateURL.path,
        "-respout", responseURL.path,
        "-noverify",
    ]
    if let nextUpdateDays {
        arguments.append(contentsOf: ["-ndays", String(nextUpdateDays)])
    }
    if !embedResponderCertificate {
        arguments.append("-resp_no_certs")
    }
    try runCommand(URL(fileURLWithPath: "/usr/bin/openssl"), arguments: arguments)

    return (responseURL, certificateReport.serialNumberHex)
}

private struct DelegatedOCSPFixture {
    let directory: URL
    let issuerCertificateURL: URL
    let issuerPrivateKeyURL: URL
    let leafCertificateURL: URL
    let leafPrivateKeyURL: URL
    let responderCertificateURL: URL
    let responderPrivateKeyURL: URL
    let unauthorizedResponderCertificateURL: URL
    let unauthorizedResponderPrivateKeyURL: URL

    init() throws {
        let openssl = URL(fileURLWithPath: "/usr/bin/openssl")
        guard FileManager.default.fileExists(atPath: openssl.path) else {
            throw XCTSkip("OpenSSL is required for OCSP fixtures.")
        }
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        issuerPrivateKeyURL = directory.appendingPathComponent("issuer-key.pem")
        issuerCertificateURL = directory.appendingPathComponent("issuer-cert.pem")
        try runCommand(
            openssl,
            arguments: [
                "req",
                "-x509",
                "-newkey", "rsa:2048",
                "-keyout", issuerPrivateKeyURL.path,
                "-out", issuerCertificateURL.path,
                "-nodes",
                "-subj", "/CN=RorkSignOCSPIssuer/O=Rork Sign Tests",
                "-days", "1",
                "-sha256",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            ]
        )

        let leaf = try Self.issueCertificate(
            directory: directory,
            openssl: openssl,
            issuerCertificateURL: issuerCertificateURL,
            issuerPrivateKeyURL: issuerPrivateKeyURL,
            basename: "leaf",
            commonName: "RorkSignOCSPLeaf",
            serial: "1001",
            extensions: [
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature",
            ]
        )
        leafCertificateURL = leaf.certificateURL
        leafPrivateKeyURL = leaf.privateKeyURL

        let responder = try Self.issueCertificate(
            directory: directory,
            openssl: openssl,
            issuerCertificateURL: issuerCertificateURL,
            issuerPrivateKeyURL: issuerPrivateKeyURL,
            basename: "responder",
            commonName: "RorkSignOCSPResponder",
            serial: "1002",
            extensions: [
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature",
                "extendedKeyUsage=OCSPSigning",
            ]
        )
        responderCertificateURL = responder.certificateURL
        responderPrivateKeyURL = responder.privateKeyURL

        let unauthorizedResponder = try Self.issueCertificate(
            directory: directory,
            openssl: openssl,
            issuerCertificateURL: issuerCertificateURL,
            issuerPrivateKeyURL: issuerPrivateKeyURL,
            basename: "unauthorized-responder",
            commonName: "RorkSignUnauthorizedResponder",
            serial: "1003",
            extensions: [
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature",
                "extendedKeyUsage=serverAuth",
            ]
        )
        unauthorizedResponderCertificateURL = unauthorizedResponder.certificateURL
        unauthorizedResponderPrivateKeyURL = unauthorizedResponder.privateKeyURL
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }

    private static func issueCertificate(
        directory: URL,
        openssl: URL,
        issuerCertificateURL: URL,
        issuerPrivateKeyURL: URL,
        basename: String,
        commonName: String,
        serial: String,
        extensions: [String]
    ) throws -> (certificateURL: URL, privateKeyURL: URL) {
        let privateKeyURL = directory.appendingPathComponent("\(basename)-key.pem")
        let csrURL = directory.appendingPathComponent("\(basename).csr")
        let certificateURL = directory.appendingPathComponent("\(basename)-cert.pem")
        let extensionURL = directory.appendingPathComponent("\(basename)-ext.cnf")
        try Data((extensions.joined(separator: "\n") + "\n").utf8).write(to: extensionURL)

        try runCommand(
            openssl,
            arguments: [
                "req",
                "-newkey", "rsa:2048",
                "-keyout", privateKeyURL.path,
                "-out", csrURL.path,
                "-nodes",
                "-subj", "/CN=\(commonName)/O=Rork Sign Tests",
                "-sha256",
            ]
        )
        try runCommand(
            openssl,
            arguments: [
                "x509",
                "-req",
                "-in", csrURL.path,
                "-CA", issuerCertificateURL.path,
                "-CAkey", issuerPrivateKeyURL.path,
                "-set_serial", serial,
                "-out", certificateURL.path,
                "-days", "1",
                "-sha256",
                "-extfile", extensionURL.path,
            ]
        )
        return (certificateURL, privateKeyURL)
    }
}

private func openSSLSignature(
    digest: String,
    privateKeyURL: URL,
    data: Data,
    directory: URL
) throws -> Data {
    let inputURL = directory.appendingPathComponent(UUID().uuidString + "-signature-input")
    let signatureURL = directory.appendingPathComponent(UUID().uuidString + "-signature.der")
    try data.write(to: inputURL)
    try runCommand(
        URL(fileURLWithPath: "/usr/bin/openssl"),
        arguments: [
            "dgst",
            "-\(digest)",
            "-sign", privateKeyURL.path,
            "-out", signatureURL.path,
            inputURL.path,
        ]
    )
    return try Data(contentsOf: signatureURL)
}

private func ocspIndexDate(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "yyMMddHHmmss'Z'"
    return formatter.string(from: date)
}

private func ocspStatusMockSession() -> URLSession {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [OCSPStatusMockURLProtocol.self]
    return URLSession(configuration: configuration)
}

/// Serves one OCSP status response described by request-local test headers,
/// avoiding mutable URLProtocol type state across concurrent tests.
private final class OCSPStatusMockURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard request.url?.absoluteString == "http://ocsp.example.test/status",
              request.httpMethod == "POST",
              request.value(forHTTPHeaderField: "Content-Type") == "application/ocsp-request",
              let url = request.url,
              let bodyValue = request.value(forHTTPHeaderField: "X-RorkSign-Test-Body"),
              let body = Data(base64Encoded: bodyValue),
              let response = HTTPURLResponse(
                  url: url,
                  statusCode: 200,
                  httpVersion: "HTTP/1.1",
                  headerFields: ["Content-Type": "application/ocsp-response"]
              ) else {
            failLoading("OCSP status mock received an invalid request.")
            return
        }

        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private func failLoading(_ message: String) {
        client?.urlProtocol(
            self,
            didFailWithError: RorkSignError.cmsSigning(message)
        )
    }
}
