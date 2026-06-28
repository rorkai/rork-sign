#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// A certificate signing request whose private key remains owned by this value.
///
/// Create and retain this value in the environment that will ultimately sign
/// application bundles, then send only `pemRepresentation` to the certificate
/// issuer. The PEM representation contains no private key and cannot be used to
/// reconstruct one. After the issuer returns a DER certificate,
/// `makeSigningIdentity` verifies that the certificate contains this request's
/// public key before making the private key available to the signing pipeline.
/// Discarding this value before certificate issuance also discards the only
/// reference to its private key.
///
/// The request currently generates an RSA-2048 key because Apple development
/// certificates use RSA identities. `privateKeyPKCS8` exists for browser
/// installers that must persist a pending Apple certificate request across page
/// reloads; callers should keep that value encrypted and scoped to the local
/// browser identity.
public struct DevelopmentCertificateRequest: Sendable {
    /// PEM-encoded PKCS#10 request that can be sent to the certificate issuer.
    ///
    /// This representation contains the public key and request signature, but
    /// not the private key retained by this value.
    public let pemRepresentation: String

    /// SHA-256 fingerprint of the SubjectPublicKeyInfo carried by the request.
    ///
    /// Persist this value before asking a certificate issuer to create a
    /// certificate. If the browser crashes after a successful issuer-side
    /// creation, the fingerprint lets the caller reconcile the pending local
    /// request with the remote certificate list without consuming another
    /// certificate slot.
    public let publicKeyFingerprint: String

    /// PKCS#8 DER for the private key that signed this request.
    ///
    /// This is intentionally the only private-key export on the certificate
    /// request. Browser installers need it to recover from reloads between CSR
    /// creation and certificate issuance, while native callers can ignore it and
    /// keep the request in memory.
    public var privateKeyPKCS8: Data {
        privateKey.pkcs8DERRepresentation
    }

    /// Opaque key retained until the issuer returns the matching certificate.
    ///
    /// Keeping the key inside the request prevents callers from accidentally
    /// exporting it while the certificate request is in flight.
    private let privateKey: RSAPrivateSigningKey

    /// Generates a new private key and its signed PKCS#10 request.
    ///
    /// Retain the initialized value until the issuer returns a certificate.
    /// Recreating a request, even with the same common name, generates a
    /// different key and cannot complete the original issuance request.
    ///
    /// - Parameter commonName: Subject common name recorded in the request.
    /// - Throws: `RorkSignError.invalidSigningIdentity` when the common name is
    ///   empty, or a cryptographic error when key generation fails.
    public init(commonName: String) throws {
        try self.init(
            commonName: commonName,
            privateKey: RSAPrivateSigningKey()
        )
    }

    /// Restores a pending request from previously exported PKCS#8 key data.
    ///
    /// Use this initializer only after decrypting trusted browser-local pending
    /// state. The common name must match the original request context; changing
    /// it creates a different CSR for the same private key and should be treated
    /// as a new issuer request.
    ///
    /// - Parameters:
    ///   - commonName: Subject common name recorded in the request.
    ///   - privateKeyPKCS8: PKCS#8 DER returned by `privateKeyPKCS8`.
    /// - Throws: `RorkSignError.invalidSigningIdentity` when the common name is
    ///   empty or the private key cannot be loaded as RSA-2048 signing material.
    public init(
        commonName: String,
        privateKeyPKCS8: Data
    ) throws {
        try self.init(
            commonName: commonName,
            privateKey: RSAPrivateSigningKey(
                derRepresentation: privateKeyPKCS8
            )
        )
    }

    /// Builds a PKCS#10 request around an existing RSA private key.
    ///
    /// Both public initializers funnel through this path so fresh and restored
    /// requests share the same common-name validation, fingerprinting, and PEM
    /// encoding behavior.
    private init(
        commonName: String,
        privateKey: RSAPrivateSigningKey
    ) throws {
        let commonName = commonName.trimmingCharacters(
            in: .whitespacesAndNewlines
        )
        guard !commonName.isEmpty else {
            throw RorkSignError.invalidSigningIdentity(
                "Certificate request common name must not be empty."
            )
        }
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
        self.publicKeyFingerprint = Self.fingerprint(
            for: privateKey.publicKeyDERRepresentation
        )
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

    private static func fingerprint(for data: Data) -> String {
        SHA256.hash(data: data).map {
            String(format: "%02x", $0)
        }.joined()
    }

    /// Wraps DER bytes in the 64-column PEM form expected by Apple and OpenSSL.
    private static func pemRepresentation(type: String, der: Data) -> String {
        let encoded = der.base64EncodedString()
        let lines = stride(from: 0, to: encoded.count, by: 64).map { offset in
            let start = encoded.index(encoded.startIndex, offsetBy: offset)
            let end = encoded.index(
                start,
                offsetBy: min(
                    64,
                    encoded.distance(from: start, to: encoded.endIndex)
                )
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
