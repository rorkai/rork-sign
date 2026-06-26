#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// A certificate signing request whose private key remains owned by this value.
///
/// Create this value in the environment that will ultimately sign application
/// bundles, then send only `pemRepresentation` to the certificate issuer. After
/// the issuer returns a DER certificate, `makeSigningIdentity` verifies that
/// the certificate contains this request's public key before making the private
/// key available to RorkSign's signing pipeline.
///
/// The request currently generates an RSA-2048 key because Apple development
/// certificates use RSA identities. The private key is intentionally opaque and
/// has no public serialization API.
public struct DevelopmentCertificateRequest: Sendable {
    /// PEM-encoded PKCS#10 request to submit to the certificate issuer.
    public let pemRepresentation: String

    /// Opaque key retained until the issuer returns the matching certificate.
    ///
    /// Keeping the key inside the request prevents callers from accidentally
    /// exporting it while the certificate request is in flight.
    private let privateKey: RSAPrivateSigningKey

    /// Generates a new private key and a signed PKCS#10 request.
    ///
    /// - Parameter commonName: Subject common name recorded in the request.
    /// - Throws: `RorkSignError.invalidSigningIdentity` when the common name is
    ///   empty, or a cryptographic error when key generation fails.
    public init(commonName: String) throws {
        let commonName = commonName.trimmingCharacters(
            in: .whitespacesAndNewlines
        )
        guard !commonName.isEmpty else {
            throw RorkSignError.invalidSigningIdentity(
                "Certificate request common name must not be empty."
            )
        }

        let privateKey = try RSAPrivateSigningKey()
        let requestInfo = DEREncoding.sequence([
            DEREncoding.integer(0),
            Self.distinguishedName(commonName: commonName),
            privateKey.publicKeyDERRepresentation,
            DEREncoding.contextSpecificConstructed(0, content: Data()),
        ])
        let signature = try privateKey.signature(
            for: SHA256.hash(data: requestInfo)
        )
        let request = DEREncoding.sequence([
            requestInfo,
            DEREncoding.sequence([
                DEREncoding.objectIdentifier(
                    "1.2.840.113549.1.1.11"
                ),
                DEREncoding.null(),
            ]),
            DEREncoding.bitString(signature),
        ])

        self.privateKey = privateKey
        self.pemRepresentation = Self.pemRepresentation(
            type: "CERTIFICATE REQUEST",
            der: request
        )
    }

    /// Completes the request with the certificate returned by the issuer.
    ///
    /// The certificate is accepted only when its public key matches the opaque
    /// private key generated for this request. Additional certificates are
    /// preserved as CMS chain material when the resulting identity signs code.
    ///
    /// - Parameters:
    ///   - certificateDER: DER-encoded certificate issued for this request.
    ///   - additionalCertificatesDER: Intermediate or root certificates to
    ///     preserve with the completed identity.
    /// - Returns: A signing identity backed by this request's private key.
    /// - Throws: `RorkSignError.invalidSigningIdentity` when the certificate is
    ///   malformed or does not contain this request's public key.
    public func makeSigningIdentity(
        certificateDER: Data,
        additionalCertificatesDER: [Data] = []
    ) throws -> SigningIdentity {
        try SigningIdentity(
            certificateDER: certificateDER,
            additionalCertificatesDER: additionalCertificatesDER,
            privateKey: .rsa(privateKey)
        )
    }

    /// Encodes the request subject as a distinguished name containing one CN.
    private static func distinguishedName(commonName: String) -> Data {
        DEREncoding.sequence([
            DEREncoding.set([
                DEREncoding.sequence([
                    DEREncoding.objectIdentifier("2.5.4.3"),
                    DEREncoding.utf8String(commonName),
                ]),
            ]),
        ])
    }

    /// Wraps DER bytes in the 64-column PEM form expected by Apple and OpenSSL.
    private static func pemRepresentation(type: String, der: Data) -> String {
        let encoded = der.base64EncodedString()
        let lines = stride(from: 0, to: encoded.count, by: 64).map { offset in
            let start = encoded.index(encoded.startIndex, offsetBy: offset)
            let end = encoded.index(
                start,
                offsetBy: min(64, encoded.distance(from: start, to: encoded.endIndex))
            )
            return String(encoded[start..<end])
        }
        return """
        -----BEGIN \(type)-----
        \(lines.joined(separator: "\n"))
        -----END \(type)-----
        """
    }
}
