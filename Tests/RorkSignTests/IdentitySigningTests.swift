#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
@testable import RorkSign
import XCTest

final class IdentitySigningTests: XCTestCase {
    func testSigningIdentityExposesSubjectAndExpirationDate() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        XCTAssertEqual(fixture.identity.subjectCommonName, "RorkSignTest")
        XCTAssertEqual(fixture.identity.teamIdentifier, "")
        XCTAssertGreaterThan(fixture.identity.certificateExpirationDate, Date())
        XCTAssertLessThan(
            fixture.identity.certificateExpirationDate,
            Date().addingTimeInterval(2 * 24 * 60 * 60)
        )
    }

    func testSigningIdentityCanBeBoundToTeamIdentifier() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let identity = try fixture.identity.withTeamIdentifier(" TEAMID1234\n")

        XCTAssertEqual(identity.teamIdentifier, "TEAMID1234")
        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.subjectCommonName, fixture.identity.subjectCommonName)
        XCTAssertEqual(try identity.withTeamIdentifier("TEAMID1234").teamIdentifier, "TEAMID1234")
        XCTAssertEqual(try identity.withTeamIdentifier(" ").teamIdentifier, "TEAMID1234")
        XCTAssertThrowsError(try identity.withTeamIdentifier("OTHERTEAM")) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidSigningIdentity(
                    "Signing identity team identifier TEAMID1234 does not match provisioning profile team OTHERTEAM."
                )
            )
        }
    }

    func testCertificateCheckReportsCertificateMetadata() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let report = try RorkSigner.checkCertificate(Data(fixture.certificatePEM.utf8))

        XCTAssertEqual(report.subjectCommonName, "RorkSignTest")
        XCTAssertEqual(report.subjectOrganizationName, "Rork Sign Tests")
        XCTAssertEqual(report.issuerCommonName, "RorkSignTest")
        XCTAssertEqual(report.keyAlgorithm, "RSA 2048-bit")
        XCTAssertEqual(report.certificateKind, "Certificate")
        XCTAssertFalse(report.serialNumberHex.isEmpty)
        XCTAssertEqual(report.ocspResponderURLs, [])
        XCTAssertEqual(report.crlDistributionPointURLs, [])
        XCTAssertGreaterThan(report.expirationDate, Date())
        XCTAssertFalse(report.isExpired())
    }

    func testAppleCertificateChainAddsMatchingWWDRIssuerAndRoot() throws {
        let intermediateDER = AppleCertificateChain.developerRelationsIntermediatesDER[1]
        let intermediate = try CertificateInfo.parse(intermediateDER)
        let leafLikeCertificate = CertificateInfo(
            tbsCertificateDER: Data(),
            issuerDER: intermediate.subjectDER,
            subjectDER: Data(),
            serialNumberDER: Data(),
            serialNumberHex: "",
            subjectCommonName: "Apple Development: Test",
            subjectOrganizationName: "Example",
            issuerCommonName: intermediate.subjectCommonName,
            ocspResponderURLs: [],
            crlDistributionPointURLs: [],
            extendedKeyUsageOIDs: [],
            isCertificateAuthority: false,
            pathLengthConstraint: nil,
            hasKeyUsageExtension: false,
            keyUsage: [],
            notBefore: Date(),
            notAfter: Date(),
            subjectPublicKeyInfoDER: Data(),
            keyAlgorithm: "RSA 2048-bit",
            signatureAlgorithmOID: "",
            signature: Data()
        )

        let chain = AppleCertificateChain.additionalCertificates(
            for: leafLikeCertificate,
            existing: []
        )

        XCTAssertEqual(chain.count, 2)
        XCTAssertEqual(chain.first, intermediateDER)
    }

    func testCertificateCheckReportsOCSPResponderURLs() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let certificate = try fixture.selfSignedCertificate(
            commonName: "RorkSignOCSP",
            ocspResponderURL: "http://ocsp.example.test"
        )

        let report = try RorkSigner.checkCertificate(try Data(contentsOf: certificate.url))

        XCTAssertEqual(report.subjectCommonName, "RorkSignOCSP")
        XCTAssertEqual(report.ocspResponderURLs, ["http://ocsp.example.test"])
    }

    func testCertificateCheckReportsCRLDistributionPointURLs() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let certificate = try fixture.selfSignedCertificate(
            commonName: "RorkSignCRL",
            ocspResponderURL: "http://ocsp.example.test",
            crlDistributionPointURL: "http://crl.example.test/root.crl"
        )

        let report = try RorkSigner.checkCertificate(try Data(contentsOf: certificate.url))

        XCTAssertEqual(report.subjectCommonName, "RorkSignCRL")
        XCTAssertEqual(report.ocspResponderURLs, ["http://ocsp.example.test"])
        XCTAssertEqual(report.crlDistributionPointURLs, ["http://crl.example.test/root.crl"])
    }

    func testCertificateCheckReportsP256CertificateMetadata() throws {
        let fixture = try OpenSSLECFixture()
        defer {
            fixture.remove()
        }

        let report = try RorkSigner.checkCertificate(Data(fixture.certificatePEM.utf8))

        XCTAssertEqual(report.subjectCommonName, "RorkSignECTestP256")
        XCTAssertEqual(report.subjectOrganizationName, "Rork Sign Tests")
        XCTAssertEqual(report.keyAlgorithm, "EC P-256")
        XCTAssertEqual(report.certificateKind, "Certificate")
        XCTAssertFalse(report.serialNumberHex.isEmpty)
    }

    func testCertificateCheckReportsP384AndP521CertificateMetadata() throws {
        for curve in [OpenSSLECCurve.p384, .p521] {
            let fixture = try OpenSSLECFixture(curve: curve)
            defer {
                fixture.remove()
            }

            let report = try RorkSigner.checkCertificate(Data(fixture.certificatePEM.utf8))

            XCTAssertEqual(report.subjectCommonName, curve.commonName)
            XCTAssertEqual(report.subjectOrganizationName, "Rork Sign Tests")
            XCTAssertEqual(report.keyAlgorithm, curve.keyAlgorithm)
            XCTAssertEqual(report.certificateKind, "Certificate")
            XCTAssertFalse(report.serialNumberHex.isEmpty)
        }
    }

    func testCertificateChainCheckReportsAllPEMCertificates() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let additionalCertificate = try fixture.selfSignedCertificate(commonName: "RorkSignChainIntermediate")
        let certificateChainPEM = fixture.certificatePEM
            + "\n"
            + (try String(contentsOf: additionalCertificate.url, encoding: .utf8))

        let reports = try RorkSigner.checkCertificateChain(Data(certificateChainPEM.utf8))

        XCTAssertEqual(reports.map(\.subjectCommonName), ["RorkSignTest", "RorkSignChainIntermediate"])
        XCTAssertEqual(reports[0].keyAlgorithm, "RSA 2048-bit")
        XCTAssertEqual(reports[1].certificateKind, "Certificate")
    }

    func testCertificateChainValidationAcceptsLeafFirstSignedChain() throws {
        let fixture = try OpenSSLCertificateChainFixture()
        defer {
            fixture.remove()
        }

        let report = try RorkSigner.validateCertificateChain(Data(fixture.chainPEM.utf8))

        XCTAssertTrue(report.isLocallyValid)
        XCTAssertTrue(report.linksAreLocallyValid)
        XCTAssertTrue(report.terminatesInSelfSignedCertificate)
        XCTAssertTrue(report.allCertificatesValidAtValidationDate)
        XCTAssertEqual(report.certificates.map(\.subjectCommonName), ["RorkSignChainLeaf", "RorkSignChainRoot"])
        XCTAssertEqual(report.links.count, 1)
        XCTAssertEqual(report.links[0].certificateIndex, 0)
        XCTAssertEqual(report.links[0].issuerIndex, 1)
        XCTAssertTrue(report.links[0].issuerSubjectMatches)
        XCTAssertTrue(report.links[0].signatureVerified)
        XCTAssertTrue(report.links[0].issuerCanSignCertificates)
        XCTAssertEqual(report.links[0].subordinateCertificateAuthorityCount, 0)
        XCTAssertTrue(report.links[0].issuerPathLengthConstraintSatisfied)
        XCTAssertTrue(report.links[0].certificateValidAtValidationDate)
        XCTAssertFalse(report.certificates[0].isCertificateAuthority)
        XCTAssertFalse(report.certificates[0].canSignCertificates)
        XCTAssertTrue(report.certificates[0].hasKeyUsageExtension)
        XCTAssertTrue(report.certificates[0].keyUsage.contains(.digitalSignature))
        XCTAssertFalse(report.certificates[0].keyUsage.contains(.keyCertSign))
        XCTAssertTrue(report.certificates[1].isCertificateAuthority)
        XCTAssertTrue(report.certificates[1].canSignCertificates)
        XCTAssertFalse(report.certificates[0].isNotYetValid())
        XCTAssertTrue(report.certificates[0].isValid())
    }

    func testCertificateChainValidationReportsBrokenIssuerLink() throws {
        let chainFixture = try OpenSSLCertificateChainFixture()
        defer {
            chainFixture.remove()
        }
        let selfSignedFixture = try OpenSSLFixture()
        defer {
            selfSignedFixture.remove()
        }
        let wrongRoot = try selfSignedFixture.selfSignedCertificate(commonName: "RorkSignWrongRoot")
        let brokenChainPEM = try String(contentsOf: chainFixture.leafCertificateURL, encoding: .utf8)
            + "\n"
            + String(contentsOf: wrongRoot.url, encoding: .utf8)

        let report = try RorkSigner.validateCertificateChain(Data(brokenChainPEM.utf8))

        XCTAssertFalse(report.isLocallyValid)
        XCTAssertFalse(report.linksAreLocallyValid)
        XCTAssertTrue(report.terminatesInSelfSignedCertificate)
        XCTAssertTrue(report.allCertificatesValidAtValidationDate)
        XCTAssertEqual(report.links.count, 1)
        XCTAssertFalse(report.links[0].issuerSubjectMatches)
        XCTAssertFalse(report.links[0].signatureVerified)
        XCTAssertFalse(report.links[0].issuerCanSignCertificates)
        XCTAssertTrue(report.links[0].issuerPathLengthConstraintSatisfied)
        XCTAssertTrue(report.links[0].certificateValidAtValidationDate)
    }

    func testCertificateChainValidationRejectsIssuerWithoutCABasicConstraints() throws {
        let fixture = try OpenSSLCertificateChainFixture(
            issuerExtensions: [
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,keyCertSign,cRLSign",
            ]
        )
        defer {
            fixture.remove()
        }

        let report = try RorkSigner.validateCertificateChain(Data(fixture.chainPEM.utf8))

        XCTAssertFalse(report.isLocallyValid)
        XCTAssertFalse(report.linksAreLocallyValid)
        XCTAssertFalse(report.rootCanSignCertificates)
        XCTAssertEqual(report.links.count, 1)
        XCTAssertTrue(report.links[0].issuerSubjectMatches)
        XCTAssertTrue(report.links[0].signatureVerified)
        XCTAssertFalse(report.links[0].issuerCanSignCertificates)
        XCTAssertTrue(report.links[0].issuerPathLengthConstraintSatisfied)
        XCTAssertFalse(report.certificates[1].isCertificateAuthority)
        XCTAssertFalse(report.certificates[1].canSignCertificates)
        XCTAssertTrue(report.certificates[1].keyUsage.contains(.keyCertSign))
    }

    func testCertificateChainValidationRejectsIssuerKeyUsageWithoutCertificateSigning() throws {
        let fixture = try OpenSSLCertificateChainFixture(
            issuerExtensions: [
                "basicConstraints=critical,CA:TRUE",
                "keyUsage=critical,digitalSignature",
            ]
        )
        defer {
            fixture.remove()
        }

        let report = try RorkSigner.validateCertificateChain(Data(fixture.chainPEM.utf8))

        XCTAssertFalse(report.isLocallyValid)
        XCTAssertFalse(report.linksAreLocallyValid)
        XCTAssertFalse(report.rootCanSignCertificates)
        XCTAssertEqual(report.links.count, 1)
        XCTAssertTrue(report.links[0].issuerSubjectMatches)
        XCTAssertTrue(report.links[0].signatureVerified)
        XCTAssertFalse(report.links[0].issuerCanSignCertificates)
        XCTAssertTrue(report.links[0].issuerPathLengthConstraintSatisfied)
        XCTAssertTrue(report.certificates[1].isCertificateAuthority)
        XCTAssertFalse(report.certificates[1].canSignCertificates)
        XCTAssertTrue(report.certificates[1].hasKeyUsageExtension)
        XCTAssertTrue(report.certificates[1].keyUsage.contains(.digitalSignature))
        XCTAssertFalse(report.certificates[1].keyUsage.contains(.keyCertSign))
    }

    func testCertificateChainValidationAcceptsThreeLevelPathLength() throws {
        let fixture = try OpenSSLThreeLevelCertificateChainFixture()
        defer {
            fixture.remove()
        }

        let report = try RorkSigner.validateCertificateChain(Data(fixture.chainPEM.utf8))

        XCTAssertTrue(report.isLocallyValid)
        XCTAssertTrue(report.linksAreLocallyValid)
        XCTAssertEqual(
            report.certificates.map(\.subjectCommonName),
            ["RorkSignPathLeaf", "RorkSignPathIntermediate", "RorkSignPathRoot"]
        )
        XCTAssertEqual(report.links.count, 2)
        XCTAssertEqual(report.links[0].certificateIndex, 0)
        XCTAssertEqual(report.links[0].issuerIndex, 1)
        XCTAssertEqual(report.links[0].subordinateCertificateAuthorityCount, 0)
        XCTAssertTrue(report.links[0].issuerPathLengthConstraintSatisfied)
        XCTAssertEqual(report.links[1].certificateIndex, 1)
        XCTAssertEqual(report.links[1].issuerIndex, 2)
        XCTAssertEqual(report.links[1].subordinateCertificateAuthorityCount, 1)
        XCTAssertTrue(report.links[1].issuerPathLengthConstraintSatisfied)
        XCTAssertEqual(report.certificates[1].pathLengthConstraint, 0)
        XCTAssertEqual(report.certificates[2].pathLengthConstraint, 1)
    }

    func testCertificateChainValidationRejectsRootPathLengthExceeded() throws {
        let fixture = try OpenSSLThreeLevelCertificateChainFixture(
            rootExtensions: [
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "keyUsage=critical,keyCertSign,cRLSign",
            ]
        )
        defer {
            fixture.remove()
        }

        let report = try RorkSigner.validateCertificateChain(Data(fixture.chainPEM.utf8))

        XCTAssertFalse(report.isLocallyValid)
        XCTAssertFalse(report.linksAreLocallyValid)
        XCTAssertEqual(report.links.count, 2)
        XCTAssertTrue(report.links[0].issuerPathLengthConstraintSatisfied)
        XCTAssertFalse(report.links[1].issuerPathLengthConstraintSatisfied)
        XCTAssertEqual(report.links[1].subordinateCertificateAuthorityCount, 1)
        XCTAssertEqual(report.certificates[2].pathLengthConstraint, 0)
    }

    func testSigningIdentityCheckReportsPEMCertificateChain() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let additionalCertificate = try fixture.selfSignedCertificate(commonName: "RorkSignCheckIntermediate")
        let certificateChainPEM = fixture.certificatePEM
            + "\n"
            + (try String(contentsOf: additionalCertificate.url, encoding: .utf8))

        let report = try RorkSigner.checkSigningIdentity(
            certificateData: Data(certificateChainPEM.utf8),
            privateKeyData: Data(fixture.privateKeyPEM.utf8)
        )

        XCTAssertEqual(report.leafCertificate.subjectCommonName, "RorkSignTest")
        XCTAssertEqual(report.additionalCertificates.map(\.subjectCommonName), ["RorkSignCheckIntermediate"])
    }

    func testProfileCredentialCheckValidatesCredentialAgainstProfile() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let profileData = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.check",
            certificateDER: fixture.identity.certificateDER
        )

        let report = try RorkSigner.checkProfileCredential(
            provisioningProfileData: profileData,
            credentialData: Data(fixture.privateKeyPEM.utf8)
        )

        XCTAssertEqual(report.provisioningProfile.teamIdentifier, "TEAMID1234")
        XCTAssertEqual(report.provisioningProfile.applicationIdentifier, "TEAMID1234.app.rork.identity.check")
        XCTAssertEqual(report.provisioningProfile.developerCertificates.count, 1)
        XCTAssertEqual(report.signingCredential.leafCertificate.subjectCommonName, "RorkSignTest")
        XCTAssertFalse(report.signingCredential.leafCertificate.isExpired())
    }

    func testPKCS12CheckReportsAdditionalCertificates() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let additionalCertificate = try fixture.selfSignedCertificate(commonName: "Intermediate")
        let pkcs12 = try fixture.pkcs12(
            password: "secret",
            useAES: true,
            additionalCertificateURL: additionalCertificate.url
        )

        let report = try RorkSigner.checkPKCS12Identity(pkcs12, password: "secret")

        XCTAssertEqual(report.leafCertificate.subjectCommonName, "RorkSignTest")
        XCTAssertEqual(report.additionalCertificates.map(\.subjectCommonName), ["Intermediate"])
    }

    func testLoadsP256PKCS12Identity() throws {
        let fixture = try OpenSSLECFixture()
        defer {
            fixture.remove()
        }

        let pkcs12 = try fixture.pkcs12(password: "secret")
        let identity = try SigningIdentity(pkcs12Data: pkcs12, password: "secret")
        let content = Data("P-256 PKCS12 CMS content".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(for: content, identity: identity)

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        try fixture.verifyDetachedCMS(cms, content: content)
        let report = try RorkSigner.verifyDetachedCMSSignature(cms, content: content)
        XCTAssertEqual(report.signingCertificate.keyAlgorithm, "EC P-256")
    }

    func testLoadsP384PKCS12Identity() throws {
        let fixture = try OpenSSLECFixture(curve: .p384)
        defer {
            fixture.remove()
        }

        let pkcs12 = try fixture.pkcs12(password: "secret")
        let identity = try SigningIdentity(pkcs12Data: pkcs12, password: "secret")
        let content = Data("P-384 PKCS12 CMS content".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(for: content, identity: identity)

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        try fixture.verifyDetachedCMS(cms, content: content)
        let report = try RorkSigner.verifyDetachedCMSSignature(cms, content: content)
        XCTAssertEqual(report.signingCertificate.keyAlgorithm, "EC P-384")
    }

    func testRejectsMismatchedCertificateAndPrivateKey() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let otherKeyURL = fixture.directory.appendingPathComponent("other-key.pem")
        try runCommand(
            URL(fileURLWithPath: "/usr/bin/openssl"),
            arguments: ["genrsa", "-out", otherKeyURL.path, "2048"]
        )

        XCTAssertThrowsError(
            try SigningIdentity(
                certificatePEM: fixture.certificatePEM,
                privateKeyPEM: String(contentsOf: otherKeyURL, encoding: .utf8)
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidSigningIdentity("Certificate public key does not match private key.")
            )
        }
    }

    func testValidatedTeamIdentifierReturnsProfileTeamAfterCredentialMatch() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let profileData = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.team",
            certificateDER: fixture.identity.certificateDER
        )

        let teamIdentifier = try RorkSigner.validatedTeamIdentifier(
            provisioningProfileData: profileData,
            credentialData: Data(fixture.privateKeyPEM.utf8)
        )

        XCTAssertEqual(teamIdentifier, "TEAMID1234")
    }

    func testValidatedTeamIdentifierAcceptsPKCS12Credential() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let profileData = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.team-p12",
            certificateDER: fixture.identity.certificateDER
        )
        let pkcs12 = try fixture.pkcs12(password: "secret", useAES: true)

        let teamIdentifier = try RorkSigner.validatedTeamIdentifier(
            provisioningProfileData: profileData,
            credentialData: pkcs12,
            password: "secret"
        )

        XCTAssertEqual(teamIdentifier, "TEAMID1234")
    }

    func testValidatedTeamIdentifierRejectsMismatchedCredential() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let otherFixture = try OpenSSLFixture()
        defer {
            otherFixture.remove()
        }
        let profileData = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.team-mismatch",
            certificateDER: otherFixture.identity.certificateDER
        )

        XCTAssertThrowsError(
            try RorkSigner.validatedTeamIdentifier(
                provisioningProfileData: profileData,
                credentialData: Data(fixture.privateKeyPEM.utf8)
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidSigningIdentity(
                    "No provisioning-profile certificate matches the supplied private key."
                )
            )
        }
    }

    func testLoadsPBES2AESCBCPKCS12Identity() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let pkcs12 = try fixture.pkcs12(password: "secret", useAES: true)
        let identity = try SigningIdentity(pkcs12Data: pkcs12, password: "secret")

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.additionalCertificatesDER, [])

        let content = Data("PKCS12 CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: identity
        )
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testPKCS12IdentityPreservesAdditionalCertificatesInCMS() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let additionalCertificate = try fixture.selfSignedCertificate(commonName: "RorkSignIntermediate")
        let pkcs12 = try fixture.pkcs12(
            password: "secret",
            useAES: true,
            additionalCertificateURL: additionalCertificate.url
        )

        let identity = try SigningIdentity(pkcs12Data: pkcs12, password: "secret")
        let content = Data("PKCS12 CodeDirectory bytes with chain".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: identity
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertTrue(identity.additionalCertificatesDER.contains(additionalCertificate.der))
        XCTAssertNotNil(cms.range(of: fixture.identity.certificateDER))
        XCTAssertNotNil(cms.range(of: additionalCertificate.der))
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testPEMIdentityPreservesCertificateChainInCMS() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let additionalCertificate = try fixture.selfSignedCertificate(commonName: "RorkSignPEMIntermediate")
        let certificateChainPEM = fixture.certificatePEM
            + "\n"
            + (try String(contentsOf: additionalCertificate.url, encoding: .utf8))

        let identity = try SigningIdentity(
            certificatePEM: certificateChainPEM,
            privateKeyPEM: fixture.privateKeyPEM
        )
        let content = Data("PEM certificate chain CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: identity
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.additionalCertificatesDER, [additionalCertificate.der])
        XCTAssertNotNil(cms.range(of: fixture.identity.certificateDER))
        XCTAssertNotNil(cms.range(of: additionalCertificate.der))
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsMixedPEMCertificateChainAndEncryptedDERPrivateKey() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let additionalCertificate = try fixture.selfSignedCertificate(commonName: "RorkSignMixedInputIntermediate")
        let certificateChainPEM = fixture.certificatePEM
            + "\n"
            + (try String(contentsOf: additionalCertificate.url, encoding: .utf8))
        let encryptedPrivateKeyDER = try fixture.encryptedPrivateKeyDER(password: "secret")

        let identity = try SigningIdentity(
            certificateData: Data(certificateChainPEM.utf8),
            privateKeyData: encryptedPrivateKeyDER,
            privateKeyPassword: "secret"
        )
        let content = Data("Mixed PEM certificate DER key CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(for: content, identity: identity)

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.additionalCertificatesDER, [additionalCertificate.der])
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsMixedDERCertificateAndPEMPrivateKey() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let identity = try SigningIdentity(
            certificateData: fixture.identity.certificateDER,
            privateKeyData: Data(fixture.privateKeyPEM.utf8)
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.additionalCertificatesDER, [])
    }

    func testLoadsCertificateChainAndPKCS12Credential() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let additionalCertificate = try fixture.selfSignedCertificate(
            commonName: "RorkSignCertificateP12Intermediate"
        )
        let certificateChainPEM = fixture.certificatePEM
            + "\n"
            + (try String(contentsOf: additionalCertificate.url, encoding: .utf8))
        let pkcs12 = try fixture.pkcs12(
            password: "secret",
            useAES: true,
            additionalCertificateURL: additionalCertificate.url
        )

        let identity = try SigningIdentity(
            certificateData: Data(certificateChainPEM.utf8),
            privateKeyData: pkcs12,
            privateKeyPassword: "secret"
        )
        let content = Data("Certificate chain with PKCS#12 credential".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(for: content, identity: identity)

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.additionalCertificatesDER, [additionalCertificate.der])
        XCTAssertNotNil(cms.range(of: additionalCertificate.der))
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testRejectsPBES2AESCBCPKCS12WithWrongPassword() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let pkcs12 = try fixture.pkcs12(password: "secret", useAES: true)

        XCTAssertThrowsError(try SigningIdentity(pkcs12Data: pkcs12, password: "wrong")) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidSigningIdentity("PKCS#12 MAC verification failed.")
            )
        }
    }

    func testLoadsLegacyPKCS12PBEIdentity() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let pkcs12 = try fixture.pkcs12(password: "secret", useAES: false)
        let identity = try SigningIdentity(pkcs12Data: pkcs12, password: "secret")

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.additionalCertificatesDER, [])

        let content = Data("Legacy PKCS12 CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: identity
        )
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsLegacyPKCS12PBEWithTwoKeyTripleDESPrivateKey() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let pkcs12 = try fixture.pkcs12(password: "secret", keyPBE: "PBE-SHA1-2DES")
        let identity = try SigningIdentity(pkcs12Data: pkcs12, password: "secret")

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        let content = Data("Legacy PKCS12 two-key 3DES private key".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: identity
        )
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsLegacyPKCS12PBEWithDESPrivateKey() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let pkcs12 = try fixture.pkcs12(password: "secret", keyPBE: "PBE-SHA1-DES")
        let identity = try SigningIdentity(pkcs12Data: pkcs12, password: "secret")

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        let content = Data("Legacy PKCS12 DES private key".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: identity
        )
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsLegacyPKCS12PBEWithMD5DESPrivateKey() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let pkcs12 = try fixture.pkcs12(
            password: "secret",
            keyPBE: "PBE-MD5-DES",
            certPBE: "PBE-MD5-DES"
        )
        let identity = try SigningIdentity(pkcs12Data: pkcs12, password: "secret")

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        let content = Data("Legacy PKCS12 MD5 DES private key".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: identity
        )
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsLegacyPKCS12PBEWithRC4PrivateKeyAndCertificates() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let openssl = try legacyCapableOpenSSLURL()
        for pbe in ["PBE-SHA1-RC4-128", "PBE-SHA1-RC4-40"] {
            let pkcs12 = try fixture.pkcs12(
                password: "secret",
                keyPBE: pbe,
                certPBE: pbe,
                legacyProvider: true,
                opensslURL: openssl
            )
            let identity = try SigningIdentity(pkcs12Data: pkcs12, password: "secret")

            XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
            let content = Data("Legacy PKCS12 \(pbe) private key".utf8)
            let cms = try RorkSigner.makeDetachedCMSSignature(
                for: content,
                identity: identity
            )
            try fixture.verifyDetachedCMS(cms, content: content)
        }
    }

    func testRejectsLegacyPKCS12PBEWithWrongPasswordAtMAC() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let pkcs12 = try fixture.pkcs12(password: "secret", useAES: false)

        XCTAssertThrowsError(try SigningIdentity(pkcs12Data: pkcs12, password: "wrong")) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidSigningIdentity("PKCS#12 MAC verification failed.")
            )
        }
    }

    func testLoadsEncryptedPKCS8PrivateKeyPEM() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let encryptedPrivateKey = try fixture.encryptedPrivateKeyPEM(password: "secret")

        let identity = try SigningIdentity(
            certificatePEM: fixture.certificatePEM,
            privateKeyPEM: encryptedPrivateKey,
            privateKeyPassword: "secret"
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        let content = Data("Encrypted PKCS8 PEM CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(for: content, identity: identity)
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsEncryptedPKCS8PrivateKeyDER() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let encryptedPrivateKey = try fixture.encryptedPrivateKeyDER(password: "secret")

        let identity = try SigningIdentity(
            certificateDER: fixture.identity.certificateDER,
            privateKeyDER: encryptedPrivateKey,
            privateKeyPassword: "secret"
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        let content = Data("Encrypted PKCS8 DER CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(for: content, identity: identity)
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsTraditionalEncryptedRSAPrivateKeyPEMWithAES256CBC() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let encryptedPrivateKey = try fixture.traditionalEncryptedPrivateKeyPEM(
            password: "secret",
            cipher: .aes256CBC
        )

        let identity = try SigningIdentity(
            certificatePEM: fixture.certificatePEM,
            privateKeyPEM: encryptedPrivateKey,
            privateKeyPassword: "secret"
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        let content = Data("Traditional AES encrypted RSA key CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(for: content, identity: identity)
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsTraditionalEncryptedRSAPrivateKeyPEMWithTripleDESCBC() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let encryptedPrivateKey = try fixture.traditionalEncryptedPrivateKeyPEM(
            password: "secret",
            cipher: .tripleDESCBC
        )

        let identity = try SigningIdentity(
            certificatePEM: fixture.certificatePEM,
            privateKeyPEM: encryptedPrivateKey,
            privateKeyPassword: "secret"
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        let content = Data("Traditional 3DES encrypted RSA key CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(for: content, identity: identity)
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testLoadsTraditionalEncryptedRSAPrivateKeyPEMWithDESCBC() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let encryptedPrivateKey = try fixture.traditionalEncryptedPrivateKeyPEM(
            password: "secret",
            cipher: .desCBC
        )

        let identity = try SigningIdentity(
            certificatePEM: fixture.certificatePEM,
            privateKeyPEM: encryptedPrivateKey,
            privateKeyPassword: "secret"
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        let content = Data("Traditional DES encrypted RSA key CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(for: content, identity: identity)
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testRejectsTraditionalEncryptedRSAPrivateKeyPEMWithWrongPassword() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let encryptedPrivateKey = try fixture.traditionalEncryptedPrivateKeyPEM(
            password: "secret",
            cipher: .aes256CBC
        )

        XCTAssertThrowsError(
            try SigningIdentity(
                certificatePEM: fixture.certificatePEM,
                privateKeyPEM: encryptedPrivateKey,
                privateKeyPassword: "wrong"
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidSigningIdentity("Encrypted RSA private key decryption failed.")
            )
        }
    }

    func testBuildsIdentityFromProvisioningProfileAndPrivateKeyPEM() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let profileData = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.profile-key",
            certificateDER: fixture.identity.certificateDER
        )
        let profile = try RorkSigner.decodeProvisioningProfile(profileData)

        let identity = try SigningIdentity(
            provisioningProfile: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8)
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.teamIdentifier, "TEAMID1234")

        let content = Data("Provisioning profile selected certificate".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: identity
        )
        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testBuildsProfileIdentityFromEncryptedPKCS8PrivateKeyPEM() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let profileData = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.profile-encrypted-key",
            certificateDER: fixture.identity.certificateDER
        )
        let encryptedPrivateKey = try fixture.encryptedPrivateKeyPEM(password: "secret")

        let identity = try SigningIdentity(
            provisioningProfileData: profileData,
            credentialData: Data(encryptedPrivateKey.utf8),
            password: "secret"
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.teamIdentifier, "TEAMID1234")
    }

    func testBuildsIdentityFromProvisioningProfileDataAndPKCS12Credential() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let profileData = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.profile-p12",
            certificateDER: fixture.identity.certificateDER
        )
        let additionalCertificate = try fixture.selfSignedCertificate(commonName: "RorkSignProfileIntermediate")
        let pkcs12 = try fixture.pkcs12(
            password: "secret",
            useAES: true,
            additionalCertificateURL: additionalCertificate.url
        )

        let identity = try SigningIdentity(
            provisioningProfileData: profileData,
            credentialData: pkcs12,
            password: "secret"
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
        XCTAssertEqual(identity.teamIdentifier, "TEAMID1234")
        XCTAssertTrue(identity.additionalCertificatesDER.contains(additionalCertificate.der))
    }

    func testProfileIdentitySkipsInvalidAndMismatchedCertificates() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let otherFixture = try OpenSSLFixture()
        defer {
            otherFixture.remove()
        }
        let profileData = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.profile-multiple",
            certificatesDER: [
                Data([0x01, 0x02, 0x03]),
                otherFixture.identity.certificateDER,
                fixture.identity.certificateDER,
            ]
        )

        let identity = try SigningIdentity(
            provisioningProfileData: profileData,
            credentialData: Data(fixture.privateKeyPEM.utf8)
        )

        XCTAssertEqual(identity.certificateDER, fixture.identity.certificateDER)
    }

    func testProfileIdentityRejectsWhenNoCertificateMatchesPrivateKey() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let otherFixture = try OpenSSLFixture()
        defer {
            otherFixture.remove()
        }
        let profileData = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.profile-mismatch",
            certificateDER: otherFixture.identity.certificateDER
        )

        XCTAssertThrowsError(
            try SigningIdentity(
                provisioningProfileData: profileData,
                credentialData: Data(fixture.privateKeyPEM.utf8)
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidSigningIdentity(
                    "No provisioning-profile certificate matches the supplied private key."
                )
            )
        }
    }

    func testGeneratesDetachedCMSSignatureVerifiableByOpenSSL() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let content = Data("CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: fixture.identity
        )

        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testVerifiesDetachedCMSSignatureInSwift() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let content = Data("CodeDirectory bytes verified in Swift".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: fixture.identity
        )

        let report = try RorkSigner.verifyDetachedCMSSignature(cms, content: content)

        XCTAssertEqual(report.signingCertificate.subjectCommonName, "RorkSignTest")
        XCTAssertEqual(report.signingCertificate.keyAlgorithm, "RSA 2048-bit")
        XCTAssertEqual(report.additionalCertificates, [])
    }

    func testGeneratesP256DetachedCMSSignatureVerifiableByOpenSSLAndSwift() throws {
        let fixture = try OpenSSLECFixture()
        defer {
            fixture.remove()
        }

        let content = Data("P-256 CodeDirectory bytes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: fixture.identity
        )

        try fixture.verifyDetachedCMS(cms, content: content)
        let report = try RorkSigner.verifyDetachedCMSSignature(cms, content: content)
        XCTAssertEqual(report.signingCertificate.subjectCommonName, "RorkSignECTestP256")
        XCTAssertEqual(report.signingCertificate.keyAlgorithm, "EC P-256")
    }

    func testGeneratesP384AndP521DetachedCMSSignaturesVerifiableByOpenSSLAndSwift() throws {
        for curve in [OpenSSLECCurve.p384, .p521] {
            let fixture = try OpenSSLECFixture(curve: curve)
            defer {
                fixture.remove()
            }

            let content = Data("\(curve.keyAlgorithm) CodeDirectory bytes".utf8)
            let cms = try RorkSigner.makeDetachedCMSSignature(
                for: content,
                identity: fixture.identity
            )

            try fixture.verifyDetachedCMS(cms, content: content)
            let report = try RorkSigner.verifyDetachedCMSSignature(cms, content: content)
            XCTAssertEqual(report.signingCertificate.subjectCommonName, curve.commonName)
            XCTAssertEqual(report.signingCertificate.keyAlgorithm, curve.keyAlgorithm)
        }
    }

    func testRejectsDetachedCMSWhenContentIsTampered() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let content = Data("CodeDirectory bytes before tampering".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: fixture.identity
        )

        XCTAssertThrowsError(
            try RorkSigner.verifyDetachedCMSSignature(
                cms,
                content: Data("different CodeDirectory bytes".utf8)
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .cmsSigning("Detached CMS messageDigest does not match content.")
            )
        }
    }

    func testRejectsDetachedCMSWhenSignatureIsTampered() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let content = Data("CodeDirectory bytes with tampered CMS signature".utf8)
        var cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: fixture.identity
        )
        cms[cms.count - 1] ^= 0x01

        XCTAssertThrowsError(
            try RorkSigner.verifyDetachedCMSSignature(cms, content: content)
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .cmsSigning("Detached CMS RSA signature is invalid.")
            )
        }
    }

    func testGeneratedCMSIncludesAppleCDHashAttributes() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let content = Data("CodeDirectory bytes with Apple attributes".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: content,
            identity: fixture.identity
        )
        let codeDirectorySHA256 = Data(SHA256.hash(data: content))
        let cdHashBase64 = Data(codeDirectorySHA256.prefix(20)).base64EncodedString()
        let cdHashSequence = derSequence(
            derObjectIdentifier("2.16.840.1.101.3.4.2.1")
                + derOctetString(codeDirectorySHA256)
        )

        XCTAssertNotNil(cms.range(of: derObjectIdentifier("1.2.840.113635.100.9.1")))
        XCTAssertNotNil(cms.range(of: derObjectIdentifier("1.2.840.113635.100.9.2")))
        XCTAssertNotNil(cms.range(of: derObjectIdentifier("1.2.840.113549.1.9.5")))
        XCTAssertNotNil(cms.range(of: Data("cdhashes".utf8)))
        XCTAssertNotNil(cms.range(of: Data(cdHashBase64.utf8)))
        XCTAssertNotNil(cms.range(of: cdHashSequence))
        XCTAssertGreaterThanOrEqual(cms.nonOverlappingOccurrences(of: codeDirectorySHA256), 2)

        try fixture.verifyDetachedCMS(cms, content: content)
    }

    func testGeneratedCMSUsesOpenSSLDigestAlgorithmShape() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: Data("CodeDirectory bytes with OpenSSL digest shape".utf8),
            identity: fixture.identity
        )
        let sha256AlgorithmWithNull = Data([0x30, 0x0d])
            + derObjectIdentifier("2.16.840.1.101.3.4.2.1")
            + Data([0x05, 0x00])

        XCTAssertNil(cms.range(of: sha256AlgorithmWithNull))
    }

    func testGeneratedCMSIncludesPrimaryAndAlternateCDHashes() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let primaryCodeDirectory = Data("SHA-1 primary CodeDirectory".utf8)
        let alternateCodeDirectory = Data("SHA-256 alternate CodeDirectory".utf8)
        let cms = try RorkSigner.makeDetachedCMSSignature(
            for: primaryCodeDirectory,
            alternateCodeDirectory: alternateCodeDirectory,
            identity: fixture.identity
        )
        let primaryCDHash = Data(Insecure.SHA1.hash(data: primaryCodeDirectory))
        let alternateCDHash = Data(SHA256.hash(data: alternateCodeDirectory)).prefix(20)
        let alternateDigest = Data(SHA256.hash(data: alternateCodeDirectory))
        let primarySequence = derSequence(
            derObjectIdentifier("1.3.14.3.2.26")
                + derOctetString(primaryCDHash)
        )
        let alternateSequence = derSequence(
            derObjectIdentifier("2.16.840.1.101.3.4.2.1")
                + derOctetString(alternateDigest)
        )

        XCTAssertNotNil(cms.range(of: Data(primaryCDHash.base64EncodedString().utf8)))
        XCTAssertNotNil(cms.range(of: Data(Data(alternateCDHash).base64EncodedString().utf8)))
        XCTAssertNotNil(cms.range(of: primarySequence))
        XCTAssertNotNil(cms.range(of: alternateSequence))

        try fixture.verifyDetachedCMS(cms, content: primaryCodeDirectory)
    }

    /// Verifies compatible CMS output with Apple's native code-signature integrity checker.
    func testCompatibleIdentitySignaturePassesAppleCodesignIntegrityValidation() throws {
        let codesignURL = URL(fileURLWithPath: "/usr/bin/codesign")
        let executableURL = URL(fileURLWithPath: "/bin/echo")
        guard FileManager.default.isExecutableFile(atPath: codesignURL.path),
              FileManager.default.isExecutableFile(atPath: executableURL.path)
        else {
            throw XCTSkip("Apple codesign verification requires macOS.")
        }

        let fixture = try OpenSSLFixture(codeSigning: true)
        defer {
            fixture.remove()
        }

        let signed = try RorkSigner.signMachOWithIdentity(
            Data(contentsOf: executableURL),
            bundleIdentifier: "app.rork.sign.codesign-compatible",
            identity: fixture.identity,
            codeDirectoryHashingMode: .compatible
        )
        let signedURL = fixture.directory.appendingPathComponent("codesign-compatible")
        try signed.write(to: signedURL)

        let process = Process()
        process.executableURL = codesignURL
        // Isolate signature integrity from the self-signed fixture's Apple-anchored designated requirement.
        process.arguments = [
            "--verify",
            "--strict",
            "--test-requirement",
            "=true",
            signedURL.path,
        ]
        var environment = ProcessInfo.processInfo.environment
        environment["LC_ALL"] = "C"
        process.environment = environment

        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()

        let message = String(
            decoding: output.fileHandleForReading.readDataToEndOfFile(),
            as: UTF8.self
        )
        XCTAssertEqual(process.terminationStatus, 0, message)
        XCTAssertFalse(message.localizedCaseInsensitiveContains("invalid signature"), message)
    }

    func testSignsMachOWithIdentityAndEmbedsVerifiableCMSBlob() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let signed = try RorkSigner.signMachOWithIdentity(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.identity",
            identity: fixture.identity
        )
        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let alternateCodeDirectory = try XCTUnwrap(blobs[0x1000])
        let cmsBlob = try XCTUnwrap(blobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
        let cmsPayload = cmsBlob.subdata(in: 8..<cmsLength)
        let prepared = try RorkSigner.prepareMachOCMSCodeDirectories(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.identity",
            subjectCommonName: "RorkSignTest",
            cmsSignatureLengthHints: [cmsPayload.count]
        )
        let requirements = try XCTUnwrap(blobs[2])

        XCTAssertEqual(codeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(codeDirectory[37], 1)
        XCTAssertEqual(alternateCodeDirectory.readUInt32BE(at: 12), 0)
        XCTAssertEqual(alternateCodeDirectory[37], 2)
        XCTAssertEqual(cmsBlob.readUInt32BE(at: 0), 0xfade0b01)
        XCTAssertEqual(prepared[0].codeDirectory, codeDirectory)
        XCTAssertEqual(prepared[0].alternateCodeDirectory, alternateCodeDirectory)
        XCTAssertEqual(requirements.readUInt32BE(at: 8), 1)
        XCTAssertNotNil(requirements.range(of: Data("subject.CN".utf8)))
        XCTAssertNotNil(requirements.range(of: Data("RorkSignTest".utf8)))

        try fixture.verifyDetachedCMS(cmsPayload, content: codeDirectory)
        let swiftReport = try RorkSigner.verifyDetachedCMSSignature(cmsPayload, content: codeDirectory)
        XCTAssertEqual(swiftReport.signingCertificate.subjectCommonName, "RorkSignTest")
    }

    func testIdentitySigningOmitsEntitlementsForNonExecuteMachO() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let entitlements = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>application-identifier</key><string>TEAMID1234.app.rork.sign.dylib</string><key>com.apple.developer.team-identifier</key><string>TEAMID1234</string><key>get-task-allow</key><true/></dict></plist>
        """

        let signed = try RorkSigner.signMachOWithIdentity(
            Fixtures.machO64DylibWithCodeSignature(),
            bundleIdentifier: "app.rork.sign.dylib",
            identity: fixture.identity,
            entitlementsXML: entitlements
        )

        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let cmsBlob = try XCTUnwrap(blobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
        let cmsPayload = cmsBlob.subdata(in: 8..<cmsLength)

        XCTAssertNil(blobs[5])
        XCTAssertNil(blobs[7])
        XCTAssertEqual(codeDirectory.readUInt32BE(at: 24), 2)
        XCTAssertEqual(codeDirectory.readUInt64BE(at: 80), 0)
        XCTAssertEqual(
            nullTerminatedString(in: codeDirectory, offset: Int(codeDirectory.readUInt32BE(at: 48))),
            "TEAMID1234"
        )

        try fixture.verifyDetachedCMS(cmsPayload, content: codeDirectory)
    }

    func testSignsMachOWithP256IdentityAndEmbedsVerifiableCMSBlob() throws {
        let fixture = try OpenSSLECFixture()
        defer {
            fixture.remove()
        }

        let signed = try RorkSigner.signMachOWithIdentity(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.identity.p256",
            identity: fixture.identity
        )
        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let cmsBlob = try XCTUnwrap(blobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
        let cmsPayload = cmsBlob.subdata(in: 8..<cmsLength)

        try fixture.verifyDetachedCMS(cmsPayload, content: codeDirectory)
        let swiftReport = try RorkSigner.verifyDetachedCMSSignature(cmsPayload, content: codeDirectory)
        XCTAssertEqual(swiftReport.signingCertificate.subjectCommonName, "RorkSignECTestP256")
        XCTAssertEqual(swiftReport.signingCertificate.keyAlgorithm, "EC P-256")
    }

    func testSignsMachOWithP384AndP521IdentitiesAndEmbedsVerifiableCMSBlobs() throws {
        for curve in [OpenSSLECCurve.p384, .p521] {
            let fixture = try OpenSSLECFixture(curve: curve)
            defer {
                fixture.remove()
            }

            let signed = try RorkSigner.signMachOWithIdentity(
                Fixtures.machO64WithCodeSignature(),
                bundleIdentifier: "app.rork.sign.identity.\(curve.opensslName)",
                identity: fixture.identity
            )
            let blobs = try signatureBlobs(in: signed)
            let codeDirectory = try XCTUnwrap(blobs[0])
            let cmsBlob = try XCTUnwrap(blobs[0x10000])
            let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
            let cmsPayload = cmsBlob.subdata(in: 8..<cmsLength)

            try fixture.verifyDetachedCMS(cmsPayload, content: codeDirectory)
            let swiftReport = try RorkSigner.verifyDetachedCMSSignature(cmsPayload, content: codeDirectory)
            XCTAssertEqual(swiftReport.signingCertificate.subjectCommonName, curve.commonName)
            XCTAssertEqual(swiftReport.signingCertificate.keyAlgorithm, curve.keyAlgorithm)
        }
    }

    func testChecksMachOEmbeddedSigningCertificate() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let signed = try RorkSigner.signMachOWithIdentity(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.check-cms",
            identity: fixture.identity
        )

        let reports = try RorkSigner.checkMachOCodeSignatures(signed)

        XCTAssertEqual(reports.count, 1)
        XCTAssertEqual(reports[0].architectureIndex, 0)
        XCTAssertTrue(reports[0].hasCMS)
        XCTAssertTrue(reports[0].cmsSignatureValid)
        XCTAssertTrue(reports[0].codeDirectoryHashesValid)
        XCTAssertEqual(reports[0].codeDirectories.count, 2)
        XCTAssertEqual(reports[0].signingCertificate?.subjectCommonName, "RorkSignTest")
        XCTAssertEqual(reports[0].signingCertificate?.subjectOrganizationName, "Rork Sign Tests")
        XCTAssertEqual(reports[0].signingCertificate?.keyAlgorithm, "RSA 2048-bit")
        XCTAssertFalse(try XCTUnwrap(reports[0].signingCertificate).isExpired())
        XCTAssertEqual(reports[0].additionalCertificates, [])
    }

    func testChecksMachOCodeDirectoryTamperingSeparatelyFromCMSValidity() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        var signed = try RorkSigner.signMachOWithIdentity(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.sign.check-cms-tamper",
            identity: fixture.identity
        )
        let info = try RorkSigner.inspectMachO(signed)
        flipByte(in: &signed, at: Int(info.codeSignatureOffset) - 1)

        let reports = try RorkSigner.checkMachOCodeSignatures(signed)

        XCTAssertEqual(reports.count, 1)
        XCTAssertTrue(reports[0].hasCMS)
        XCTAssertTrue(reports[0].cmsSignatureValid)
        XCTAssertFalse(reports[0].codeDirectoryHashesValid)
        XCTAssertFalse(reports[0].codeDirectories.allSatisfy(\.codeSlotsValid))
    }

    func testSignsMachOWithIdentityAndSHA256OnlyCodeDirectory() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let signed = try RorkSigner.signMachOWithIdentity(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "app.rork.identity.sha256-only",
            identity: fixture.identity,
            codeDirectoryHashingMode: .sha256Only
        )
        let blobs = try signatureBlobs(in: signed)
        let codeDirectory = try XCTUnwrap(blobs[0])
        let cmsBlob = try XCTUnwrap(blobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
        let cmsPayload = cmsBlob.subdata(in: 8..<cmsLength)

        XCTAssertNil(blobs[0x1000])
        XCTAssertEqual(codeDirectory[36], 32)
        XCTAssertEqual(codeDirectory[37], 2)
        try fixture.verifyDetachedCMS(cmsPayload, content: codeDirectory)
    }

    func testSignsUniversalMachOWithIdentityAndVerifiablePerSliceCMSBlobs() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }

        let signed = try RorkSigner.signMachOWithIdentity(
            Fixtures.universalMachOWithTwoThinSlices(),
            bundleIdentifier: "app.rork.sign.identity.universal",
            identity: fixture.identity
        )
        let slices = try universalThinSlices(in: signed)

        XCTAssertEqual(slices.count, 2)
        for slice in slices {
            let blobs = try signatureBlobs(in: slice)
            let codeDirectory = try XCTUnwrap(blobs[0])
            let alternateCodeDirectory = try XCTUnwrap(blobs[0x1000])
            let cmsBlob = try XCTUnwrap(blobs[0x10000])
            let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))

            XCTAssertEqual(codeDirectory[37], 1)
            XCTAssertEqual(alternateCodeDirectory[37], 2)
            try fixture.verifyDetachedCMS(
                cmsBlob.subdata(in: 8..<cmsLength),
                content: codeDirectory
            )
        }
    }

    func testSignsBundleWithIdentityInsideOut() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeIdentityBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }

        let report = try RorkSigner.signBundleWithIdentity(
            at: bundleURL,
            identity: fixture.identity
        )

        XCTAssertEqual(
            try report.signedCode.map { try relativePath($0, under: bundleURL) },
            [
                "Frameworks/Nested.framework/Nested",
                "Host",
            ]
        )

        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let hostBlobs = try signatureBlobs(in: hostExecutable)
        let hostCodeDirectory = try XCTUnwrap(hostBlobs[0])
        let hostCMSBlob = try XCTUnwrap(hostBlobs[0x10000])
        let cmsLength = Int(hostCMSBlob.readUInt32BE(at: 4))
        try fixture.verifyDetachedCMS(
            hostCMSBlob.subdata(in: 8..<cmsLength),
            content: hostCodeDirectory
        )
    }

    func testIdentityBundleSigningAcceptsAuthorizedProvisioningProfiles() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeIdentityBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let profile = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.host",
            certificateDER: fixture.identity.certificateDER
        )

        let report = try RorkSigner.signBundleWithIdentity(
            at: bundleURL,
            identity: fixture.identity,
            options: BundleSigningOptions(
                provisioningProfilesByBundleIdentifier: [
                    "app.rork.identity.host": profile,
                ]
            )
        )

        XCTAssertEqual(report.embeddedProvisioningProfiles, [bundleURL.appendingPathComponent("embedded.mobileprovision")])
        XCTAssertEqual(try Data(contentsOf: bundleURL.appendingPathComponent("embedded.mobileprovision")), profile)
    }

    func testIdentityBundleSigningAcceptsRootWildcardProvisioningProfileFallback() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeIdentityBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let profile = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.host",
            certificateDER: fixture.identity.certificateDER,
            applicationIdentifier: "TEAMID1234.app.rork.identity.*"
        )

        let report = try RorkSigner.signBundleWithIdentity(
            at: bundleURL,
            identity: fixture.identity,
            options: BundleSigningOptions(rootProvisioningProfile: profile)
        )

        XCTAssertEqual(report.embeddedProvisioningProfiles, [bundleURL.appendingPathComponent("embedded.mobileprovision")])
        XCTAssertEqual(try Data(contentsOf: bundleURL.appendingPathComponent("embedded.mobileprovision")), profile)

        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let hostBlobs = try signatureBlobs(in: hostExecutable)
        let entitlements = try XCTUnwrap(hostBlobs[5])
        let length = Int(entitlements.readUInt32BE(at: 4))
        let payload = String(decoding: entitlements.subdata(in: 8..<length), as: UTF8.self)
        XCTAssertTrue(payload.contains("TEAMID1234.app.rork.identity.host"), payload)
    }

    func testIdentityBundleSigningRejectsProfileForDifferentBundleIdentifier() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeIdentityBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let profile = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.other",
            certificateDER: fixture.identity.certificateDER
        )

        XCTAssertThrowsError(
            try RorkSigner.signBundleWithIdentity(
                at: bundleURL,
                identity: fixture.identity,
                options: BundleSigningOptions(
                    provisioningProfilesByBundleIdentifier: [
                        "app.rork.identity.host": profile,
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidProvisioningProfile(
                    "Provisioning profile does not authorize bundle identifier app.rork.identity.host."
                )
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: bundleURL.appendingPathComponent("embedded.mobileprovision").path))
    }

    func testBundleCredentialSigningUsesProfileWithoutEmbeddingByDefault() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeIdentityBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let profile = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.host",
            certificateDER: fixture.identity.certificateDER
        )

        let report = try RorkSigner.signBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8)
        )

        XCTAssertEqual(report.embeddedProvisioningProfiles, [])
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: bundleURL.appendingPathComponent("embedded.mobileprovision").path
            )
        )

        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let hostBlobs = try signatureBlobs(in: hostExecutable)
        let entitlements = try XCTUnwrap(hostBlobs[5])
        let entitlementsLength = Int(entitlements.readUInt32BE(at: 4))
        let entitlementsPayload = String(
            decoding: entitlements.subdata(in: 8..<entitlementsLength),
            as: UTF8.self
        )
        let codeDirectory = try XCTUnwrap(hostBlobs[0])
        let cmsBlob = try XCTUnwrap(hostBlobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))

        XCTAssertTrue(entitlementsPayload.contains("TEAMID1234.app.rork.identity.host"))
        XCTAssertEqual(try RorkSigner.checkMachOCodeSignatures(hostExecutable).first?.codeDirectories.map(\.hashAlgorithm), [.sha256])
        try fixture.verifyDetachedCMS(cmsBlob.subdata(in: 8..<cmsLength), content: codeDirectory)
    }

    func testBundleCredentialSigningCanUseNonEmbeddedProfileForDifferentBundleIdentifier() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeIdentityBundleFixture(bundleIdentifier: "app.rork.identity.guest")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let profile = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.host",
            certificateDER: fixture.identity.certificateDER
        )

        let report = try RorkSigner.signBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8)
        )

        XCTAssertEqual(report.embeddedProvisioningProfiles, [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: bundleURL.appendingPathComponent("embedded.mobileprovision").path))

        let hostExecutable = try Data(contentsOf: bundleURL.appendingPathComponent("Host"))
        let hostBlobs = try signatureBlobs(in: hostExecutable)
        let entitlements = try XCTUnwrap(hostBlobs[5])
        let entitlementsLength = Int(entitlements.readUInt32BE(at: 4))
        let entitlementsPayload = String(
            decoding: entitlements.subdata(in: 8..<entitlementsLength),
            as: UTF8.self
        )

        XCTAssertTrue(entitlementsPayload.contains("TEAMID1234.app.rork.identity.guest"), entitlementsPayload)
        XCTAssertFalse(entitlementsPayload.contains("TEAMID1234.app.rork.identity.host"), entitlementsPayload)
        XCTAssertEqual(try RorkSigner.checkMachOCodeSignatures(hostExecutable).first?.codeDirectories.map(\.hashAlgorithm), [.sha256])
    }

    func testBundleCredentialSigningOmitsEntitlementsForStandaloneDylib() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeIdentityBundleFixture(bundleIdentifier: "app.rork.identity.guest")
        let standaloneCodeURL = bundleURL.appendingPathComponent("Frameworks/Loose.dylib")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        try Fixtures.machO64DylibWithCodeSignature().write(to: standaloneCodeURL)
        let profile = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.host",
            certificateDER: fixture.identity.certificateDER
        )

        _ = try RorkSigner.signBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: profile,
            credentialData: Data(fixture.privateKeyPEM.utf8),
            options: BundleSigningOptions(
                embedProvisioningProfiles: false,
                codeDirectoryHashingMode: .compatible
            )
        )

        let standaloneCode = try Data(contentsOf: standaloneCodeURL)
        let blobs = try signatureBlobs(in: standaloneCode)
        let codeDirectory = try XCTUnwrap(blobs[0])

        XCTAssertNil(blobs[5])
        XCTAssertNil(blobs[7])
        XCTAssertEqual(
            nullTerminatedString(in: codeDirectory, offset: Int(codeDirectory.readUInt32BE(at: 20))),
            "Loose.dylib"
        )
        XCTAssertEqual(codeDirectory.readUInt64BE(at: 80), 0)
        XCTAssertEqual(
            nullTerminatedString(in: codeDirectory, offset: Int(codeDirectory.readUInt32BE(at: 48))),
            "TEAMID1234"
        )
    }

    func testIdentityBundleSigningRejectsUnauthorizedProvisioningProfile() throws {
        let fixture = try OpenSSLFixture()
        defer {
            fixture.remove()
        }
        let bundleURL = try makeIdentityBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: bundleURL.deletingLastPathComponent())
        }
        let profile = try identityProvisioningProfile(
            bundleIdentifier: "app.rork.identity.host",
            certificateDER: Data([0x01, 0x02, 0x03])
        )

        XCTAssertThrowsError(
            try RorkSigner.signBundleWithIdentity(
                at: bundleURL,
                identity: fixture.identity,
                options: BundleSigningOptions(
                    provisioningProfilesByBundleIdentifier: [
                        "app.rork.identity.host": profile,
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidProvisioningProfile(
                    "Signing identity is not authorized by provisioning profile for app.rork.identity.host."
                )
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: bundleURL.appendingPathComponent("embedded.mobileprovision").path))
    }
}

/// Creates an app fixture containing a signable executable and nested framework.
private func makeIdentityBundleFixture(bundleIdentifier: String = "app.rork.identity.host") throws -> URL {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let bundleURL = rootURL.appendingPathComponent("Host.app", isDirectory: true)
    let frameworkURL = bundleURL.appendingPathComponent("Frameworks/Nested.framework", isDirectory: true)
    try FileManager.default.createDirectory(at: frameworkURL, withIntermediateDirectories: true)

    try writeIdentityInfoPlist(
        bundleIdentifier: bundleIdentifier,
        executableName: "Host",
        to: bundleURL.appendingPathComponent("Info.plist")
    )
    try writeIdentityInfoPlist(
        bundleIdentifier: "\(bundleIdentifier).nested",
        executableName: "Nested",
        to: frameworkURL.appendingPathComponent("Info.plist")
    )
    try Fixtures.machO64WithCodeSignature().write(to: bundleURL.appendingPathComponent("Host"))
    try Fixtures.machO64WithCodeSignature().write(to: frameworkURL.appendingPathComponent("Nested"))
    return bundleURL
}

/// Writes the minimal bundle metadata required by identity-signing fixtures.
private func writeIdentityInfoPlist(bundleIdentifier: String, executableName: String, to url: URL) throws {
    let plist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict><key>CFBundleIdentifier</key><string>\(bundleIdentifier)</string><key>CFBundleExecutable</key><string>\(executableName)</string></dict></plist>
    """
    try Data(plist.utf8).write(to: url)
}

/// Builds a provisioning-profile plist containing one authorized certificate.
private func identityProvisioningProfile(
    bundleIdentifier: String,
    certificateDER: Data,
    applicationIdentifier: String? = nil
) throws -> Data {
    try identityProvisioningProfile(
        bundleIdentifier: bundleIdentifier,
        certificatesDER: [certificateDER],
        applicationIdentifier: applicationIdentifier
    )
}

/// Builds a provisioning-profile plist containing the authorized certificates.
private func identityProvisioningProfile(
    bundleIdentifier: String,
    certificatesDER: [Data],
    applicationIdentifier: String? = nil
) throws -> Data {
    let plist: [String: Any] = [
        "TeamIdentifier": ["TEAMID1234"],
        "ExpirationDate": Date(timeIntervalSince1970: 1_900_000_000),
        "DeveloperCertificates": certificatesDER,
        "Entitlements": [
            "application-identifier": applicationIdentifier ?? "TEAMID1234.\(bundleIdentifier)",
            "com.apple.developer.team-identifier": "TEAMID1234",
        ],
    ]
    return try PropertyListSerialization.data(
        fromPropertyList: plist,
        format: .xml,
        options: 0
    )
}

/// Encodes a dotted-decimal object identifier for CMS attribute assertions.
private func derObjectIdentifier(_ oid: String) -> Data {
    let components = oid.split(separator: ".").compactMap { Int($0) }
    precondition(components.count >= 2)
    var content = Data([UInt8(components[0] * 40 + components[1])])
    for component in components.dropFirst(2) {
        content.append(contentsOf: derBase128(component))
    }
    return Data([0x06]) + derLength(content.count) + content
}

/// Encodes raw content as a DER octet string for CMS attribute assertions.
private func derOctetString(_ content: Data) -> Data {
    Data([0x04]) + derLength(content.count) + content
}

/// Encodes prebuilt DER elements as one DER sequence for CMS attribute assertions.
private func derSequence(_ content: Data) -> Data {
    Data([0x30]) + derLength(content.count) + content
}

/// Encodes one object-identifier component in base-128 form.
private func derBase128(_ value: Int) -> [UInt8] {
    var remaining = value
    var bytes = [UInt8(remaining & 0x7f)]
    remaining >>= 7
    while remaining > 0 {
        bytes.insert(UInt8(remaining & 0x7f) | 0x80, at: 0)
        remaining >>= 7
    }
    return bytes
}

/// Encodes a DER definite length for test-only attribute construction.
private func derLength(_ length: Int) -> Data {
    if length < 0x80 {
        return Data([UInt8(length)])
    }
    var remaining = length
    var bytes: [UInt8] = []
    while remaining > 0 {
        bytes.insert(UInt8(remaining & 0xff), at: 0)
        remaining >>= 8
    }
    return Data([0x80 | UInt8(bytes.count)] + bytes)
}

/// Returns a bundle-relative path while rejecting paths outside the fixture root.
private func relativePath(_ url: URL, under rootURL: URL) throws -> String {
    let rootPath = rootURL.standardizedFileURL.path
    let path = url.standardizedFileURL.path
    guard path.hasPrefix(rootPath + "/") else {
        throw RorkSignError.invalidBundle("Path escaped root: \(path).")
    }
    return String(path.dropFirst(rootPath.count + 1))
}

/// Locates an OpenSSL executable that supports legacy PKCS #12 providers.
private func legacyCapableOpenSSLURL() throws -> URL {
    let environment = ProcessInfo.processInfo.environment
    let candidates = [
        environment["OPENSSL"],
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/bin/openssl",
    ].compactMap { $0 }

    for path in candidates {
        let url = URL(fileURLWithPath: path)
        guard FileManager.default.isExecutableFile(atPath: url.path),
              opensslSupportsPKCS12LegacyProvider(url) else {
            continue
        }
        return url
    }

    throw XCTSkip("OpenSSL with PKCS#12 -legacy support is required for RC4 PBE fixtures.")
}

/// Reports whether an OpenSSL executable accepts the PKCS #12 legacy-provider option.
private func opensslSupportsPKCS12LegacyProvider(_ url: URL) -> Bool {
    let process = Process()
    process.executableURL = url
    process.arguments = ["pkcs12", "-legacy", "-help"]
    process.standardOutput = Pipe()
    process.standardError = Pipe()
    do {
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    } catch {
        return false
    }
}
