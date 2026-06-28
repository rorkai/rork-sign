#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import CryptoExtras
import Foundation

/// Writes signing identities as interoperable password-protected PKCS#12 data.
///
/// The private key is encrypted with PBES2 using PBKDF2-HMAC-SHA256 and
/// AES-256-CBC. A separate PKCS#12 MAC authenticates the complete safe so
/// consumers reject a wrong password or a modified container before importing
/// its certificate and key material.
enum PKCS12IdentityExporter {
    /// PBKDF2 work factor protecting the encrypted private-key bag.
    ///
    /// Private-key encryption is the container's primary password-hardening
    /// boundary, so it uses a substantially larger work factor than the
    /// integrity-only PKCS#12 MAC.
    private static let encryptionIterationCount = 210_000

    /// PKCS#12 KDF work factor used to authenticate the complete container.
    private static let macIterationCount = 2_048

    /// Encodes an identity as a complete password-protected PFX value.
    ///
    /// - Parameters:
    ///   - identity: Certificate chain and private key to place in the
    ///     container.
    ///   - password: Passphrase used for key encryption and container
    ///     authentication.
    /// - Returns: DER-encoded PKCS#12 data.
    /// - Throws: A cryptographic error when the private key cannot be encrypted.
    static func data(
        for identity: SigningIdentity,
        password: String
    ) throws -> Data {
        let localKeyID = localKeyID(for: identity.certificateDER)
        let encryptedPrivateKey = try encryptedPrivateKeyInfo(
            identity.privateKey.pkcs8DERRepresentation,
            password: password
        )
        let safeContents = DEREncoding.sequence(
            [privateKeyBag(encryptedPrivateKey, localKeyID: localKeyID)]
                + certificateBags(
                    [identity.certificateDER] + identity.additionalCertificatesDER,
                    localKeyID: localKeyID
                )
        )
        let authenticatedSafe = DEREncoding.sequence([
            dataContentInfo(safeContents),
        ])
        let authSafe = dataContentInfo(authenticatedSafe)
        let macData = macData(
            authenticating: authenticatedSafe,
            password: password
        )

        return DEREncoding.sequence([
            DEREncoding.integer(3),
            authSafe,
            macData,
        ])
    }

    /// Encrypts PKCS#8 key bytes using PBES2, PBKDF2, and AES-256-CBC.
    private static func encryptedPrivateKeyInfo(
        _ privateKey: Data,
        password: String
    ) throws -> Data {
        let salt = randomBytes(count: 16)
        let initializationVector = randomBytes(count: 16)
        let encryptionKey = try KDF.Insecure.PBKDF2.deriveKey(
            from: Data(password.utf8),
            salt: salt,
            using: .sha256,
            outputByteCount: 32,
            rounds: encryptionIterationCount
        )
        let encryptedPrivateKey = try AES._CBC.encrypt(
            privateKey,
            using: encryptionKey,
            iv: AES._CBC.IV(ivBytes: initializationVector)
        )

        let pbkdf2Parameters = DEREncoding.sequence([
            DEREncoding.octetString(salt),
            DEREncoding.integer(encryptionIterationCount),
            DEREncoding.integer(32),
            algorithmIdentifier(
                oid: OID.hmacWithSHA256,
                parameters: DEREncoding.null()
            ),
        ])
        let pbes2Parameters = DEREncoding.sequence([
            algorithmIdentifier(
                oid: OID.pbkdf2,
                parameters: pbkdf2Parameters
            ),
            algorithmIdentifier(
                oid: OID.aes256CBC,
                parameters: DEREncoding.octetString(initializationVector)
            ),
        ])

        return DEREncoding.sequence([
            algorithmIdentifier(
                oid: OID.pbes2,
                parameters: pbes2Parameters
            ),
            DEREncoding.octetString(encryptedPrivateKey),
        ])
    }

    /// Wraps an encrypted PKCS#8 value in a PKCS#12 shrouded-key SafeBag.
    private static func privateKeyBag(
        _ encryptedPrivateKey: Data,
        localKeyID: Data
    ) -> Data {
        DEREncoding.sequence([
            DEREncoding.objectIdentifier(OID.pkcs8ShroudedKeyBag),
            DEREncoding.contextSpecificConstructed(
                0,
                content: encryptedPrivateKey
            ),
            safeBagAttributes(localKeyID: localKeyID),
        ])
    }

    /// Wraps the leaf and chain certificates as X.509 certificate SafeBags.
    private static func certificateBags(
        _ certificates: [Data],
        localKeyID: Data
    ) -> [Data] {
        certificates.enumerated().map { offset, certificate in
            let certificateBag = DEREncoding.sequence([
                DEREncoding.objectIdentifier(OID.x509Certificate),
                DEREncoding.contextSpecificConstructed(
                    0,
                    content: DEREncoding.octetString(certificate)
                ),
            ])
            var safeBag = [
                DEREncoding.objectIdentifier(OID.certBag),
                DEREncoding.contextSpecificConstructed(
                    0,
                    content: certificateBag
                ),
            ]
            if offset == 0 {
                safeBag.append(safeBagAttributes(localKeyID: localKeyID))
            }
            return DEREncoding.sequence(safeBag)
        }
    }

    /// Adds the PKCS#9 localKeyID that Security.framework uses to pair bags.
    private static func safeBagAttributes(localKeyID: Data) -> Data {
        DEREncoding.set([
            DEREncoding.sequence([
                DEREncoding.objectIdentifier(OID.localKeyID),
                DEREncoding.set([
                    DEREncoding.octetString(localKeyID),
                ]),
            ]),
        ])
    }

    /// Wraps safe contents in the PKCS#7 data ContentInfo used by PFX.
    private static func dataContentInfo(_ content: Data) -> Data {
        DEREncoding.sequence([
            DEREncoding.objectIdentifier(OID.pkcs7Data),
            DEREncoding.contextSpecificConstructed(
                0,
                content: DEREncoding.octetString(content)
            ),
        ])
    }

    /// Authenticates the encoded AuthenticatedSafe with the PKCS#12 MAC KDF.
    ///
    /// The MAC covers the octets carried by `authSafe`, not its outer
    /// ContentInfo wrapper, matching RFC 7292's PFX definition.
    private static func macData(
        authenticating authenticatedSafe: Data,
        password: String
    ) -> Data {
        let salt = randomBytes(count: 16)
        let algorithm = LegacyPKCS12KDF.HashAlgorithm.sha256
        let keyBytes = LegacyPKCS12KDF.derive(
            password: LegacyPKCS12KDF.passwordBytes(password),
            salt: salt,
            id: .mac,
            iterations: macIterationCount,
            outputByteCount: algorithm.digestByteCount,
            hashAlgorithm: algorithm
        )
        let digest = algorithm.authenticationCode(
            for: authenticatedSafe,
            key: SymmetricKey(data: keyBytes)
        )
        let digestInfo = DEREncoding.sequence([
            algorithmIdentifier(
                oid: OID.sha256,
                parameters: DEREncoding.null()
            ),
            DEREncoding.octetString(digest),
        ])

        return DEREncoding.sequence([
            digestInfo,
            DEREncoding.octetString(salt),
            DEREncoding.integer(macIterationCount),
        ])
    }

    /// Encodes an AlgorithmIdentifier from a package-owned OID and parameters.
    private static func algorithmIdentifier(
        oid: String,
        parameters: Data
    ) -> Data {
        DEREncoding.sequence([
            DEREncoding.objectIdentifier(oid),
            parameters,
        ])
    }

    /// Produces cryptographically secure random bytes for salts and IVs.
    private static func randomBytes(count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data(
            (0..<count).map { _ in
                UInt8.random(in: .min ... .max, using: &generator)
            }
        )
    }

    /// Uses the common certificate hash form also emitted by OpenSSL exports.
    private static func localKeyID(for certificateDER: Data) -> Data {
        Data(Insecure.SHA1.hash(data: certificateDER))
    }

    /// Object identifiers required by the modern PKCS#12 encoding profile.
    private enum OID {
        /// PKCS#7 data ContentInfo.
        static let pkcs7Data = "1.2.840.113549.1.7.1"

        /// PKCS#12 shrouded private-key SafeBag.
        static let pkcs8ShroudedKeyBag = "1.2.840.113549.1.12.10.1.2"

        /// PKCS#12 certificate SafeBag.
        static let certBag = "1.2.840.113549.1.12.10.1.3"

        /// PKCS#9 X.509 certificate bag value.
        static let x509Certificate = "1.2.840.113549.1.9.22.1"

        /// PKCS#9 local key identifier bag attribute.
        static let localKeyID = "1.2.840.113549.1.9.21"

        /// Password-Based Encryption Scheme 2.
        static let pbes2 = "1.2.840.113549.1.5.13"

        /// Password-Based Key Derivation Function 2.
        static let pbkdf2 = "1.2.840.113549.1.5.12"

        /// HMAC using SHA-256.
        static let hmacWithSHA256 = "1.2.840.113549.2.9"

        /// SHA-256 digest algorithm.
        static let sha256 = "2.16.840.1.101.3.4.2.1"

        /// AES-256 in CBC mode.
        static let aes256CBC = "2.16.840.1.101.3.4.1.42"
    }
}
