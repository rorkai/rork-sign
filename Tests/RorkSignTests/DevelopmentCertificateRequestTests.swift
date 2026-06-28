import Foundation
#if canImport(Security)
import Security
#endif
@testable import RorkSign
import XCTest

/// Exercises the complete browser-owned certificate identity lifecycle.
///
/// OpenSSL provides an independent implementation for validating the emitted
/// PKCS#10 request, issuing a matching certificate, and importing the final
/// PKCS#12 container.
final class DevelopmentCertificateRequestTests: XCTestCase {
    func testCertificateSigningRequestIsValidPKCS10() throws {
        let request = try DevelopmentCertificateRequest(
            commonName: "Browser Development"
        )
        let directory = try makeTemporaryDirectory()
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let requestURL = directory.appendingPathComponent("request.pem")
        try request.pemRepresentation.write(
            to: requestURL,
            atomically: true,
            encoding: .utf8
        )

        let openssl = URL(fileURLWithPath: "/usr/bin/openssl")
        guard FileManager.default.fileExists(atPath: openssl.path) else {
            throw XCTSkip("OpenSSL is required for certificate-request tests.")
        }

        try runCommand(
            openssl,
            arguments: [
                "req",
                "-in", requestURL.path,
                "-noout",
                "-verify",
            ]
        )
    }

    func testRestoresCertificateRequestFromExportedPrivateKey() throws {
        let request = try DevelopmentCertificateRequest(
            commonName: "Browser Development"
        )

        let restoredRequest = try DevelopmentCertificateRequest(
            commonName: "Browser Development",
            privateKeyPKCS8: request.privateKeyPKCS8
        )

        XCTAssertEqual(
            restoredRequest.pemRepresentation,
            request.pemRepresentation
        )
        XCTAssertEqual(
            restoredRequest.publicKeyFingerprint,
            request.publicKeyFingerprint
        )
    }

    func testRestoredCertificateRequestCompletesSigningIdentity() throws {
        let request = try DevelopmentCertificateRequest(
            commonName: "Browser Development"
        )
        let certificateDER = try issueCertificate(for: request)
        let restoredRequest = try DevelopmentCertificateRequest(
            commonName: "Browser Development",
            privateKeyPKCS8: request.privateKeyPKCS8
        )

        let identity = try restoredRequest.makeSigningIdentity(
            certificateDER: certificateDER
        )

        XCTAssertEqual(identity.certificateDER, certificateDER)
        XCTAssertEqual(identity.subjectCommonName, "Browser Development")
    }

    func testMatchingCertificateCompletesSigningIdentity() throws {
        let request = try DevelopmentCertificateRequest(
            commonName: "Browser Development"
        )
        let certificateDER = try issueCertificate(for: request)

        let identity = try request.makeSigningIdentity(
            certificateDER: certificateDER
        )

        XCTAssertEqual(identity.certificateDER, certificateDER)
        XCTAssertEqual(identity.subjectCommonName, "Browser Development")
    }

    func testCertificateForDifferentRequestIsRejected() throws {
        let request = try DevelopmentCertificateRequest(
            commonName: "Browser Development"
        )
        let otherRequest = try DevelopmentCertificateRequest(
            commonName: "Other Browser"
        )
        let certificateDER = try issueCertificate(for: otherRequest)

        XCTAssertThrowsError(
            try request.makeSigningIdentity(certificateDER: certificateDER)
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidSigningIdentity(
                    "Certificate public key does not match private key."
                )
            )
        }
    }

    func testCompletedIdentityExportsPasswordProtectedPKCS12() throws {
        let request = try DevelopmentCertificateRequest(
            commonName: "Browser Development"
        )
        let certificateDER = try issueCertificate(for: request)
        let identity = try request.makeSigningIdentity(
            certificateDER: certificateDER
        )

        let pkcs12 = try identity.pkcs12Representation(
            password: "browser-secret"
        )
        let imported = try SigningIdentity(
            pkcs12Data: pkcs12,
            password: "browser-secret"
        )

        XCTAssertEqual(imported.certificateDER, certificateDER)
        XCTAssertThrowsError(
            try SigningIdentity(
                pkcs12Data: pkcs12,
                password: "wrong-password"
            )
        )
    }

    func testExportedPKCS12IsAcceptedByOpenSSL() throws {
        let request = try DevelopmentCertificateRequest(
            commonName: "Browser Development"
        )
        let identity = try request.makeSigningIdentity(
            certificateDER: issueCertificate(for: request)
        )
        let directory = try makeTemporaryDirectory()
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let pkcs12URL = directory.appendingPathComponent("identity.p12")
        try identity.pkcs12Representation(password: "browser-secret")
            .write(to: pkcs12URL)

        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: [
                "pkcs12",
                "-in", pkcs12URL.path,
                "-passin", "pass:browser-secret",
                "-info",
                "-noout",
            ]
        )
    }

#if canImport(Security)
    /// Guards the iOS import path where a valid P12 must become a SecIdentity.
    func testExportedPKCS12IsAcceptedBySecurityFramework() throws {
        let request = try DevelopmentCertificateRequest(
            commonName: "Browser Development"
        )
        let identity = try request.makeSigningIdentity(
            certificateDER: issueCertificate(for: request)
        )
        let pkcs12 = try identity.pkcs12Representation(
            password: "browser-secret"
        )

        var importedItems: CFArray?
        let status = SecPKCS12Import(
            pkcs12 as CFData,
            [kSecImportExportPassphrase as String: "browser-secret"]
                as CFDictionary,
            &importedItems
        )
        let items = importedItems as? [[String: Any]]
        let importedIdentity = items?.first?[kSecImportItemIdentity as String]

        XCTAssertEqual(status, errSecSuccess)
        XCTAssertNotNil(importedIdentity)
        XCTAssertEqual(
            importedIdentity.map { CFGetTypeID($0 as CFTypeRef) },
            SecIdentityGetTypeID()
        )
    }
#endif

    /// Issues a short-lived certificate so tests exercise a real PKCS#10 flow.
    private func issueCertificate(
        for request: DevelopmentCertificateRequest
    ) throws -> Data {
        let directory = try makeTemporaryDirectory()
        defer {
            try? FileManager.default.removeItem(at: directory)
        }

        let requestURL = directory.appendingPathComponent("request.pem")
        let authorityKeyURL = directory.appendingPathComponent("authority-key.pem")
        let authorityCertificateURL = directory.appendingPathComponent("authority-certificate.pem")
        let certificateURL = directory.appendingPathComponent("certificate.pem")
        let certificateDERURL = directory.appendingPathComponent("certificate.der")
        try request.pemRepresentation.write(
            to: requestURL,
            atomically: true,
            encoding: .utf8
        )

        let openssl = URL(fileURLWithPath: "/usr/bin/openssl")
        guard FileManager.default.fileExists(atPath: openssl.path) else {
            throw XCTSkip("OpenSSL is required for certificate-request tests.")
        }
        try runCommand(
            openssl,
            arguments: [
                "req",
                "-x509",
                "-newkey", "rsa:2048",
                "-keyout", authorityKeyURL.path,
                "-out", authorityCertificateURL.path,
                "-nodes",
                "-subj", "/CN=RorkSign Test Authority",
                "-days", "1",
                "-sha256",
            ]
        )
        try runCommand(
            openssl,
            arguments: [
                "x509",
                "-req",
                "-in", requestURL.path,
                "-CA", authorityCertificateURL.path,
                "-CAkey", authorityKeyURL.path,
                "-CAcreateserial",
                "-out", certificateURL.path,
                "-days", "1",
                "-sha256",
            ]
        )
        try runCommand(
            openssl,
            arguments: [
                "x509",
                "-in", certificateURL.path,
                "-outform", "DER",
                "-out", certificateDERURL.path,
            ]
        )
        return try Data(contentsOf: certificateDERURL)
    }

    /// Creates an isolated workspace for OpenSSL inputs and outputs.
    private func makeTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return directory
    }
}
