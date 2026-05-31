import Foundation

/// Performs local validation of caller-supplied certificate chains.
///
/// This validator deliberately avoids platform trust decisions. It only checks
/// evidence available in the supplied chain: validity dates, issuer/subject
/// linkage, and certificate signatures. Trust anchors, Apple certificate
/// policy, OCSP, and CRLs stay explicit at higher layers.
enum CertificateChainValidator {
    /// Validates `certificatesDER` in leaf-first order.
    static func validate(
        certificatesDER: [Data],
        validationDate: Date
    ) throws -> CertificateChainValidationReport {
        guard !certificatesDER.isEmpty else {
            throw RorkSignError.invalidSigningIdentity("Certificate chain is empty.")
        }

        let certificateInfos = try certificatesDER.map(CertificateInfo.parse)
        let certificateReports = try certificatesDER.map(RorkSigner.certificateCheckReport(fromDER:))
        let validity = certificateInfos.map {
            $0.notBefore <= validationDate && $0.notAfter >= validationDate
        }

        var links: [CertificateChainLinkValidationReport] = []
        if certificateInfos.count > 1 {
            for index in 0..<(certificateInfos.count - 1) {
                let certificate = certificateInfos[index]
                let issuer = certificateInfos[index + 1]
                links.append(
                    CertificateChainLinkValidationReport(
                        certificateIndex: index,
                        issuerIndex: index + 1,
                        certificate: certificateReports[index],
                        issuer: certificateReports[index + 1],
                        issuerSubjectMatches: certificate.issuerDER == issuer.subjectDER,
                        signatureVerified: signatureVerified(
                            certificate,
                            issuerCertificateDER: certificatesDER[index + 1]
                        ),
                        issuerCanSignCertificates: issuer.canSignCertificates,
                        subordinateCertificateAuthorityCount: subordinateCertificateAuthorityCount(
                            belowIssuerAt: index + 1,
                            in: certificateInfos
                        ),
                        issuerPathLengthConstraintSatisfied: pathLengthConstraintSatisfied(
                            issuer: issuer,
                            issuerIndex: index + 1,
                            certificateInfos: certificateInfos
                        ),
                        certificateValidAtValidationDate: validity[index]
                    )
                )
            }
        }

        let rootInfo = certificateInfos[certificateInfos.count - 1]
        let rootDER = certificatesDER[certificatesDER.count - 1]
        return CertificateChainValidationReport(
            certificates: certificateReports,
            links: links,
            validationDate: validationDate,
            allCertificatesValidAtValidationDate: validity.allSatisfy { $0 },
            rootSubjectMatchesIssuer: rootInfo.issuerDER == rootInfo.subjectDER,
            rootSignatureVerified: signatureVerified(rootInfo, issuerCertificateDER: rootDER),
            rootCanSignCertificates: rootInfo.canSignCertificates
        )
    }

    /// Verifies one certificate signature using a candidate issuer certificate.
    private static func signatureVerified(
        _ certificate: CertificateInfo,
        issuerCertificateDER: Data
    ) -> Bool {
        do {
            try OCSPSignatureVerifier.verifySignature(
                certificate.signature,
                algorithmOID: certificate.signatureAlgorithmOID,
                certificateDER: issuerCertificateDER,
                signedResponseData: certificate.tbsCertificateDER
            )
            return true
        } catch {
            return false
        }
    }

    /// Counts CA certificates below an issuer in the supplied leaf-first chain.
    private static func subordinateCertificateAuthorityCount(
        belowIssuerAt issuerIndex: Int,
        in certificateInfos: [CertificateInfo]
    ) -> Int {
        guard issuerIndex > 0 else {
            return 0
        }
        return certificateInfos[..<issuerIndex].filter(\.isCertificateAuthority).count
    }

    /// Checks the issuer's BasicConstraints path length against the supplied chain.
    private static func pathLengthConstraintSatisfied(
        issuer: CertificateInfo,
        issuerIndex: Int,
        certificateInfos: [CertificateInfo]
    ) -> Bool {
        guard let pathLengthConstraint = issuer.pathLengthConstraint else {
            return true
        }
        return subordinateCertificateAuthorityCount(
            belowIssuerAt: issuerIndex,
            in: certificateInfos
        ) <= pathLengthConstraint
    }
}
