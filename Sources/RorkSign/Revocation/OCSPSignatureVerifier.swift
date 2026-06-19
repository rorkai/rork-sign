#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import CryptoExtras
import Foundation

/// Verifies the signature over an OCSP BasicOCSPResponse.
///
/// OCSP signature verification is deliberately separated from trust policy.
/// A valid signature proves that the supplied or embedded responder certificate
/// signed the `ResponseData` bytes. It does not prove that the responder is
/// trusted by the issuer, authorized for the certificate, fresh enough for a
/// caller's policy, or acceptable under platform-specific rules.
enum OCSPSignatureVerifier {
    /// Verifies `responseDER` against caller-supplied and embedded responder certs.
    static func verify(
        responseDER: Data,
        responderCertificateData: Data?
    ) throws -> OCSPSignatureVerificationReport {
        let response = try OCSPResponseParser.parse(responseDER)
        guard response.responseStatus == .successful else {
            throw RorkSignError.cmsSigning("OCSP response is not successful.")
        }
        guard let signedResponseData = response.signedResponseData,
              let signatureAlgorithmOID = response.signatureAlgorithmOID,
              let signature = response.signature else {
            throw RorkSignError.cmsSigning("OCSP response has no BasicOCSPResponse signature.")
        }

        let candidates = try responderCertificateCandidates(
            suppliedData: responderCertificateData,
            embeddedCertificates: response.responderCertificatesDER
        )
        guard !candidates.isEmpty else {
            throw RorkSignError.cmsSigning("OCSP response has no responder certificate to verify.")
        }

        var lastError: Error?
        for candidate in candidates {
            do {
                try verifySignature(
                    signature,
                    algorithmOID: signatureAlgorithmOID,
                    certificateDER: candidate.certificateDER,
                    signedResponseData: signedResponseData
                )
                return OCSPSignatureVerificationReport(
                    response: response,
                    responderCertificate: try RorkSigner.certificateCheckReport(fromDER: candidate.certificateDER),
                    responderCertificateDER: candidate.certificateDER,
                    usedEmbeddedResponderCertificate: candidate.embedded
                )
            } catch {
                lastError = error
            }
        }

        if candidates.count == 1, let lastError {
            throw lastError
        }
        throw RorkSignError.cmsSigning(
            "OCSP response signature did not verify with any responder certificate."
        )
    }

    /// Builds a de-duplicated candidate list, preserving caller-supplied certs first.
    private static func responderCertificateCandidates(
        suppliedData: Data?,
        embeddedCertificates: [Data]
    ) throws -> [ResponderCertificateCandidate] {
        var result: [ResponderCertificateCandidate] = []
        var seen: Set<Data> = []

        if let suppliedData {
            for certificateDER in try SigningIdentity.certificateChainDER(from: suppliedData) {
                if seen.insert(certificateDER).inserted {
                    result.append(
                        ResponderCertificateCandidate(certificateDER: certificateDER, embedded: false)
                    )
                }
            }
        }

        for certificateDER in embeddedCertificates where seen.insert(certificateDER).inserted {
            result.append(
                ResponderCertificateCandidate(certificateDER: certificateDER, embedded: true)
            )
        }
        return result
    }

    /// Verifies the BasicOCSPResponse signature for supported algorithms.
    static func verifySignature(
        _ signatureBytes: Data,
        algorithmOID: String,
        certificateDER: Data,
        signedResponseData: Data
    ) throws {
        let certificateInfo = try CertificateInfo.parse(certificateDER)
        switch algorithmOID {
        case OID.sha1WithRSAEncryption:
            try verifyRSASignature(
                signatureBytes,
                certificateInfo: certificateInfo,
                digest: Insecure.SHA1.hash(data: signedResponseData)
            )
        case OID.sha256WithRSAEncryption:
            try verifyRSASignature(
                signatureBytes,
                certificateInfo: certificateInfo,
                digest: SHA256.hash(data: signedResponseData)
            )
        case OID.sha384WithRSAEncryption:
            try verifyRSASignature(
                signatureBytes,
                certificateInfo: certificateInfo,
                digest: SHA384.hash(data: signedResponseData)
            )
        case OID.sha512WithRSAEncryption:
            try verifyRSASignature(
                signatureBytes,
                certificateInfo: certificateInfo,
                digest: SHA512.hash(data: signedResponseData)
            )
        case OID.ecdsaWithSHA1:
            try verifyECDSASignature(
                signatureBytes,
                certificateInfo: certificateInfo,
                digest: Insecure.SHA1.hash(data: signedResponseData)
            )
        case OID.ecdsaWithSHA256:
            try verifyECDSASignature(
                signatureBytes,
                certificateInfo: certificateInfo,
                digest: SHA256.hash(data: signedResponseData)
            )
        case OID.ecdsaWithSHA384:
            try verifyECDSASignature(
                signatureBytes,
                certificateInfo: certificateInfo,
                digest: SHA384.hash(data: signedResponseData)
            )
        case OID.ecdsaWithSHA512:
            try verifyECDSASignature(
                signatureBytes,
                certificateInfo: certificateInfo,
                digest: SHA512.hash(data: signedResponseData)
            )
        default:
            throw RorkSignError.cmsSigning(
                "OCSP signature algorithm is not supported: \(algorithmOID)."
            )
        }
    }

    /// Verifies an RSA PKCS#1 v1.5 signature for the supplied digest.
    private static func verifyRSASignature<D: Digest>(
        _ signatureBytes: Data,
        certificateInfo: CertificateInfo,
        digest: D
    ) throws {
        let publicKey = try _RSA.Signing.PublicKey(
            derRepresentation: certificateInfo.subjectPublicKeyInfoDER
        )
        let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureBytes)
        guard publicKey.isValidSignature(
            signature,
            for: digest,
            padding: .insecurePKCS1v1_5
        ) else {
            throw RorkSignError.cmsSigning("OCSP RSA signature is invalid.")
        }
    }

    /// Verifies ECDSA signatures for the supported NIST curves.
    private static func verifyECDSASignature<D: Digest>(
        _ signatureBytes: Data,
        certificateInfo: CertificateInfo,
        digest: D
    ) throws {
        if let publicKey = try? P256.Signing.PublicKey(
            derRepresentation: certificateInfo.subjectPublicKeyInfoDER
        ) {
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureBytes)
            guard publicKey.isValidSignature(signature, for: digest) else {
                throw RorkSignError.cmsSigning("OCSP ECDSA signature is invalid.")
            }
            return
        }

        if let publicKey = try? P384.Signing.PublicKey(
            derRepresentation: certificateInfo.subjectPublicKeyInfoDER
        ) {
            let signature = try P384.Signing.ECDSASignature(derRepresentation: signatureBytes)
            guard publicKey.isValidSignature(signature, for: digest) else {
                throw RorkSignError.cmsSigning("OCSP ECDSA signature is invalid.")
            }
            return
        }

        if let publicKey = try? P521.Signing.PublicKey(
            derRepresentation: certificateInfo.subjectPublicKeyInfoDER
        ) {
            let signature = try P521.Signing.ECDSASignature(derRepresentation: signatureBytes)
            guard publicKey.isValidSignature(signature, for: digest) else {
                throw RorkSignError.cmsSigning("OCSP ECDSA signature is invalid.")
            }
            return
        }

        throw RorkSignError.cmsSigning(
            "OCSP ECDSA public key is not supported: \(certificateInfo.keyAlgorithm)."
        )
    }
}

private struct ResponderCertificateCandidate {
    let certificateDER: Data
    let embedded: Bool
}

private enum OID {
    static let sha1WithRSAEncryption = "1.2.840.113549.1.1.5"
    static let sha256WithRSAEncryption = "1.2.840.113549.1.1.11"
    static let sha384WithRSAEncryption = "1.2.840.113549.1.1.12"
    static let sha512WithRSAEncryption = "1.2.840.113549.1.1.13"
    static let ecdsaWithSHA1 = "1.2.840.10045.4.1"
    static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
    static let ecdsaWithSHA384 = "1.2.840.10045.4.3.3"
    static let ecdsaWithSHA512 = "1.2.840.10045.4.3.4"
}
