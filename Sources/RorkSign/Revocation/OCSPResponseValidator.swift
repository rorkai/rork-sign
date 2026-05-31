import Foundation

/// Performs local OCSP response validation against one request.
///
/// This layer composes the parser and signature verifier with request matching
/// and explicit freshness policy. When the caller supplies the issuer
/// certificate, it also proves the local responder-authorization relationship
/// allowed by RFC 6960. It intentionally stops before network, platform trust,
/// certificate-policy, or responder-revocation decisions.
enum OCSPResponseValidator {
    /// Verifies `responseDER`, matches it to `request`, and checks freshness.
    static func validate(
        responseDER: Data,
        request: OCSPRequest,
        responderCertificateData: Data?,
        issuerCertificateData: Data?,
        policy: OCSPResponseValidationPolicy
    ) throws -> OCSPResponseValidationReport {
        let signatureVerification = try OCSPSignatureVerifier.verify(
            responseDER: responseDER,
            responderCertificateData: responderCertificateData
        )
        let matchedResponse = try matchedSingleResponse(
            in: signatureVerification.response,
            request: request
        )
        try validateFreshness(matchedResponse, policy: policy)
        let responderAuthorization = try issuerCertificateData.map { issuerData in
            try validateResponderAuthorization(
                responderCertificateDER: signatureVerification.responderCertificateDER,
                issuerCertificateData: issuerData,
                policy: policy
            )
        }
        return OCSPResponseValidationReport(
            signatureVerification: signatureVerification,
            matchedResponse: matchedResponse,
            policy: policy,
            responderAuthorization: responderAuthorization
        )
    }

    /// Finds the `SingleResponse` whose `CertID` matches the request.
    private static func matchedSingleResponse(
        in response: OCSPResponseReport,
        request: OCSPRequest
    ) throws -> OCSPSingleResponse {
        guard response.responseStatus == .successful else {
            throw RorkSignError.cmsSigning("OCSP response is not successful.")
        }
        guard let match = response.singleResponses.first(where: { single in
            single.issuerNameHash == request.issuerNameHash
                && single.issuerKeyHash == request.issuerKeyHash
                && single.serialNumberHex == request.serialNumberHex
        }) else {
            throw RorkSignError.cmsSigning("OCSP response does not match the request CertID.")
        }
        return match
    }

    /// Applies caller-supplied freshness policy to one matched response.
    private static func validateFreshness(
        _ response: OCSPSingleResponse,
        policy: OCSPResponseValidationPolicy
    ) throws {
        guard policy.allowedClockSkew >= 0 else {
            throw RorkSignError.cmsSigning("OCSP clock skew policy must be non-negative.")
        }
        if let maximumAge = policy.maximumAge, maximumAge < 0 {
            throw RorkSignError.cmsSigning("OCSP maximum-age policy must be non-negative.")
        }

        let latestAcceptedThisUpdate = policy.validationDate.addingTimeInterval(policy.allowedClockSkew)
        guard response.thisUpdate <= latestAcceptedThisUpdate else {
            throw RorkSignError.cmsSigning("OCSP response thisUpdate is in the future.")
        }

        if let nextUpdate = response.nextUpdate {
            let earliestAcceptedNextUpdate = policy.validationDate.addingTimeInterval(-policy.allowedClockSkew)
            guard nextUpdate >= earliestAcceptedNextUpdate else {
                throw RorkSignError.cmsSigning("OCSP response nextUpdate is expired.")
            }
        } else if policy.requiresNextUpdate {
            throw RorkSignError.cmsSigning("OCSP response does not contain nextUpdate.")
        }

        if let maximumAge = policy.maximumAge {
            let oldestAcceptedThisUpdate = policy.validationDate.addingTimeInterval(-maximumAge - policy.allowedClockSkew)
            guard response.thisUpdate >= oldestAcceptedThisUpdate else {
                throw RorkSignError.cmsSigning("OCSP response is older than maximumAge.")
            }
        }
    }

    /// Validates that the response signer is authorized for the request issuer.
    ///
    /// RFC 6960 allows either the issuer certificate itself or a delegated
    /// responder certificate that is issued by the issuer and carries
    /// `id-kp-OCSPSigning`. This function proves that local relationship only;
    /// platform trust roots, certificate policy, and revocation of the responder
    /// certificate remain caller concerns.
    private static func validateResponderAuthorization(
        responderCertificateDER: Data,
        issuerCertificateData: Data,
        policy: OCSPResponseValidationPolicy
    ) throws -> OCSPResponderAuthorization {
        guard let issuerCertificateDER = try SigningIdentity.certificateChainDER(from: issuerCertificateData).first else {
            throw RorkSignError.invalidSigningIdentity("Issuer certificate data does not contain a certificate.")
        }
        let responderInfo = try CertificateInfo.parse(responderCertificateDER)
        let issuerInfo = try CertificateInfo.parse(issuerCertificateDER)

        if responderInfo.subjectDER == issuerInfo.subjectDER
            && responderInfo.subjectPublicKeyInfoDER == issuerInfo.subjectPublicKeyInfoDER {
            return .issuerCertificate
        }

        guard responderInfo.issuerDER == issuerInfo.subjectDER else {
            throw RorkSignError.cmsSigning("OCSP responder certificate was not issued by the request issuer.")
        }
        guard responderInfo.extendedKeyUsageOIDs.contains(OID.ocspSigning) else {
            throw RorkSignError.cmsSigning("OCSP responder certificate is missing id-kp-OCSPSigning.")
        }

        let earliestValidDate = policy.validationDate.addingTimeInterval(policy.allowedClockSkew)
        let latestValidDate = policy.validationDate.addingTimeInterval(-policy.allowedClockSkew)
        guard responderInfo.notBefore <= earliestValidDate,
              responderInfo.notAfter >= latestValidDate else {
            throw RorkSignError.cmsSigning("OCSP responder certificate is not valid at the validation date.")
        }

        do {
            try OCSPSignatureVerifier.verifySignature(
                responderInfo.signature,
                algorithmOID: responderInfo.signatureAlgorithmOID,
                certificateDER: issuerCertificateDER,
                signedResponseData: responderInfo.tbsCertificateDER
            )
        } catch {
            throw RorkSignError.cmsSigning("OCSP responder certificate was not signed by the request issuer.")
        }
        return .delegatedResponder
    }
}

private enum OID {
    static let ocspSigning = "1.3.6.1.5.5.7.3.9"
}
