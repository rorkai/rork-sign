import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import CryptoExtras

/// CMS signature algorithms supported by signing identities.
enum CMSSignatureAlgorithm: Sendable {
    /// RSA PKCS#1 v1.5 with the generic `rsaEncryption` SignerInfo algorithm.
    case rsaEncryption

    /// ECDSA over a NIST P-curve with SHA-256.
    case ecdsaWithSHA256

    /// Object identifier written into CMS SignerInfo.
    var oid: String {
        switch self {
        case .rsaEncryption:
            return "1.2.840.113549.1.1.1"
        case .ecdsaWithSHA256:
            return "1.2.840.10045.4.3.2"
        }
    }

    /// Whether AlgorithmIdentifier parameters should contain DER NULL.
    var includesNullParameters: Bool {
        switch self {
        case .rsaEncryption:
            return true
        case .ecdsaWithSHA256:
            return false
        }
    }

    /// Whether the encoded signature length can vary between signing attempts.
    var usesVariableLengthSignature: Bool {
        switch self {
        case .rsaEncryption:
            return false
        case .ecdsaWithSHA256:
            return true
        }
    }
}

/// Private key usable for CMS code-signature generation.
///
/// Keeping this internal avoids exposing Swift Crypto's concrete RSA and EC key
/// types through the public API while still supporting the signing key families
/// used by common Apple code-signing certificates.
enum SigningPrivateKey: Sendable {
    /// RSA signing key.
    case rsa(RSAPrivateSigningKey)

    /// P-256 ECDSA signing key.
    case p256(P256PrivateSigningKey)

    /// P-384 ECDSA signing key.
    case p384(P384PrivateSigningKey)

    /// P-521 ECDSA signing key.
    case p521(P521PrivateSigningKey)

    /// Loads an RSA or NIST EC private key from DER bytes.
    static func load(derRepresentation: Data, password: String = "") throws -> SigningPrivateKey {
        if let rsa = try? RSAPrivateSigningKey(derRepresentation: derRepresentation, password: password) {
            return .rsa(rsa)
        }
        if let p256 = try? P256PrivateSigningKey(derRepresentation: derRepresentation, password: password) {
            return .p256(p256)
        }
        if let p384 = try? P384PrivateSigningKey(derRepresentation: derRepresentation, password: password) {
            return .p384(p384)
        }
        if let p521 = try? P521PrivateSigningKey(derRepresentation: derRepresentation, password: password) {
            return .p521(p521)
        }
        throw RorkSignError.invalidSigningIdentity(
            "Private key DER could not be loaded as RSA, P-256, P-384, or P-521."
        )
    }

    /// Loads an RSA or NIST EC private key from PEM text.
    static func load(pemRepresentation: String, password: String = "") throws -> SigningPrivateKey {
        do {
            let rsa = try RSAPrivateSigningKey(pemRepresentation: pemRepresentation, password: password)
            return .rsa(rsa)
        } catch let error as RorkSignError {
            if pemRepresentation.contains("-----BEGIN RSA PRIVATE KEY-----") {
                throw error
            }
        } catch {
            if pemRepresentation.contains("-----BEGIN RSA PRIVATE KEY-----") {
                throw RorkSignError.invalidSigningIdentity("RSA private key PEM could not be loaded.")
            }
        }

        if let p256 = try? P256PrivateSigningKey(pemRepresentation: pemRepresentation, password: password) {
            return .p256(p256)
        }
        if let p384 = try? P384PrivateSigningKey(pemRepresentation: pemRepresentation, password: password) {
            return .p384(p384)
        }
        if let p521 = try? P521PrivateSigningKey(pemRepresentation: pemRepresentation, password: password) {
            return .p521(p521)
        }
        throw RorkSignError.invalidSigningIdentity(
            "Private key PEM could not be loaded as RSA, P-256, P-384, or P-521."
        )
    }

    /// CMS signature algorithm used by this key.
    var cmsSignatureAlgorithm: CMSSignatureAlgorithm {
        switch self {
        case .rsa:
            return .rsaEncryption
        case .p256, .p384, .p521:
            return .ecdsaWithSHA256
        }
    }

    /// SubjectPublicKeyInfo DER for matching the key against a certificate.
    var publicKeyDERRepresentation: Data {
        switch self {
        case .rsa(let key):
            return key.publicKeyDERRepresentation
        case .p256(let key):
            return key.publicKeyDERRepresentation
        case .p384(let key):
            return key.publicKeyDERRepresentation
        case .p521(let key):
            return key.publicKeyDERRepresentation
        }
    }

    /// PKCS#8 DER used when exporting the identity into a portable container.
    var pkcs8DERRepresentation: Data {
        switch self {
        case .rsa(let key):
            return key.pkcs8DERRepresentation
        case .p256(let key):
            return key.pkcs8DERRepresentation
        case .p384(let key):
            return key.pkcs8DERRepresentation
        case .p521(let key):
            return key.pkcs8DERRepresentation
        }
    }

    /// Signs the precomputed SHA-256 digest of the CMS signed-attribute set.
    func signature(for digest: SHA256.Digest) throws -> Data {
        switch self {
        case .rsa(let key):
            return try key.signature(for: digest)
        case .p256(let key):
            return try key.signature(for: digest)
        case .p384(let key):
            return try key.signature(for: digest)
        case .p521(let key):
            return try key.signature(for: digest)
        }
    }
}

/// Small wrapper around Swift Crypto's RSA private key type.
struct RSAPrivateSigningKey: Sendable {
    private let privateKey: _RSA.Signing.PrivateKey

    /// Generates the RSA-2048 key required by Apple development certificates.
    init() throws {
        self.privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
    }

    init(derRepresentation: Data, password: String = "") throws {
        let candidate = try decryptedDERIfNeeded(
            derRepresentation,
            password: password,
            keyFamily: "RSA"
        )
        do {
            self.privateKey = try _RSA.Signing.PrivateKey(derRepresentation: candidate)
        } catch {
            throw RorkSignError.invalidSigningIdentity("RSA private key DER could not be loaded.")
        }
    }

    init(pemRepresentation: String, password: String = "") throws {
        do {
            self.privateKey = try _RSA.Signing.PrivateKey(pemRepresentation: pemRepresentation)
        } catch {
            if let decryptedPrivateKeyDER = try TraditionalPEMPrivateKeyDecryptor.decrypt(
                pemRepresentation,
                password: password
            ) {
                do {
                    self.privateKey = try _RSA.Signing.PrivateKey(derRepresentation: decryptedPrivateKeyDER)
                    return
                } catch {
                    throw RorkSignError.invalidSigningIdentity("Decrypted RSA private key PEM could not be loaded.")
                }
            }

            let encryptedPrivateKeyDER = try PEM.decode(
                pemRepresentation,
                acceptedTypes: ["ENCRYPTED PRIVATE KEY"]
            )
            let decrypted = try EncryptedPrivateKeyInfo.decrypt(
                encryptedPrivateKeyDER,
                password: password
            )
            do {
                self.privateKey = try _RSA.Signing.PrivateKey(derRepresentation: decrypted)
            } catch {
                throw RorkSignError.invalidSigningIdentity("Decrypted RSA private key PEM could not be loaded.")
            }
        }
    }

    /// Signs a digest using RSA PKCS#1 v1.5 as expected by CMS
    /// `rsaEncryption` SignerInfo records.
    func signature(for digest: SHA256.Digest) throws -> Data {
        do {
            return try privateKey
                .signature(for: digest, padding: .insecurePKCS1v1_5)
                .rawRepresentation
        } catch {
            throw RorkSignError.cmsSigning("RSA signature generation failed.")
        }
    }

    /// SubjectPublicKeyInfo DER submitted in certificate signing requests.
    var publicKeyDERRepresentation: Data {
        privateKey.publicKey.derRepresentation
    }

    /// PKCS#8 DER used only when placing this opaque key into PKCS#12.
    var pkcs8DERRepresentation: Data {
        privateKey.pkcs8DERRepresentation
    }
}

/// Small wrapper around Swift Crypto's P-256 signing key type.
struct P256PrivateSigningKey: Sendable {
    private let privateKey: P256.Signing.PrivateKey

    init(derRepresentation: Data, password: String = "") throws {
        let candidate = try decryptedDERIfNeeded(
            derRepresentation,
            password: password,
            keyFamily: "P-256"
        )
        do {
            self.privateKey = try P256.Signing.PrivateKey(derRepresentation: candidate)
        } catch {
            if let rawScalar = try? sec1PrivateKeyScalar(
                from: candidate,
                expectedCurveOID: OID.prime256v1,
                scalarByteCount: 32,
                keyFamily: "P-256"
            ) {
                do {
                    self.privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawScalar)
                    return
                } catch {
                    throw RorkSignError.invalidSigningIdentity("P-256 SEC.1 private key DER could not be loaded.")
                }
            }
            throw RorkSignError.invalidSigningIdentity("P-256 private key DER could not be loaded.")
        }
    }

    init(pemRepresentation: String, password: String = "") throws {
        do {
            self.privateKey = try P256.Signing.PrivateKey(pemRepresentation: pemRepresentation)
        } catch {
            if let sec1DER = try? PEM.decode(pemRepresentation, acceptedTypes: ["EC PRIVATE KEY"]),
               let rawScalar = try? sec1PrivateKeyScalar(
                   from: sec1DER,
                   expectedCurveOID: OID.prime256v1,
                   scalarByteCount: 32,
                   keyFamily: "P-256"
               ) {
                do {
                    self.privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawScalar)
                    return
                } catch {
                    throw RorkSignError.invalidSigningIdentity("P-256 SEC.1 private key PEM could not be loaded.")
                }
            }

            let encryptedPrivateKeyDER = try PEM.decode(
                pemRepresentation,
                acceptedTypes: ["ENCRYPTED PRIVATE KEY"]
            )
            let decrypted = try EncryptedPrivateKeyInfo.decrypt(
                encryptedPrivateKeyDER,
                password: password
            )
            do {
                self.privateKey = try P256.Signing.PrivateKey(derRepresentation: decrypted)
            } catch {
                throw RorkSignError.invalidSigningIdentity("Decrypted P-256 private key PEM could not be loaded.")
            }
        }
    }

    /// Signs a digest with ECDSA over P-256 and returns DER-encoded `r,s`.
    func signature(for digest: SHA256.Digest) throws -> Data {
        do {
            return try privateKey.signature(for: digest).derRepresentation
        } catch {
            throw RorkSignError.cmsSigning("P-256 ECDSA signature generation failed.")
        }
    }

    var publicKeyDERRepresentation: Data {
        privateKey.publicKey.derRepresentation
    }

    /// PKCS#8 DER used only when placing this opaque key into PKCS#12.
    var pkcs8DERRepresentation: Data {
        privateKey.pkcs8DERRepresentation
    }
}

/// Small wrapper around Swift Crypto's P-384 signing key type.
struct P384PrivateSigningKey: Sendable {
    private let privateKey: P384.Signing.PrivateKey

    init(derRepresentation: Data, password: String = "") throws {
        let candidate = try decryptedDERIfNeeded(
            derRepresentation,
            password: password,
            keyFamily: "P-384"
        )
        do {
            self.privateKey = try P384.Signing.PrivateKey(derRepresentation: candidate)
        } catch {
            if let rawScalar = try? sec1PrivateKeyScalar(
                from: candidate,
                expectedCurveOID: OID.secp384r1,
                scalarByteCount: 48,
                keyFamily: "P-384"
            ) {
                do {
                    self.privateKey = try P384.Signing.PrivateKey(rawRepresentation: rawScalar)
                    return
                } catch {
                    throw RorkSignError.invalidSigningIdentity("P-384 SEC.1 private key DER could not be loaded.")
                }
            }
            throw RorkSignError.invalidSigningIdentity("P-384 private key DER could not be loaded.")
        }
    }

    init(pemRepresentation: String, password: String = "") throws {
        do {
            self.privateKey = try P384.Signing.PrivateKey(pemRepresentation: pemRepresentation)
        } catch {
            if let sec1DER = try? PEM.decode(pemRepresentation, acceptedTypes: ["EC PRIVATE KEY"]),
               let rawScalar = try? sec1PrivateKeyScalar(
                   from: sec1DER,
                   expectedCurveOID: OID.secp384r1,
                   scalarByteCount: 48,
                   keyFamily: "P-384"
               ) {
                do {
                    self.privateKey = try P384.Signing.PrivateKey(rawRepresentation: rawScalar)
                    return
                } catch {
                    throw RorkSignError.invalidSigningIdentity("P-384 SEC.1 private key PEM could not be loaded.")
                }
            }

            let encryptedPrivateKeyDER = try PEM.decode(
                pemRepresentation,
                acceptedTypes: ["ENCRYPTED PRIVATE KEY"]
            )
            let decrypted = try EncryptedPrivateKeyInfo.decrypt(
                encryptedPrivateKeyDER,
                password: password
            )
            do {
                self.privateKey = try P384.Signing.PrivateKey(derRepresentation: decrypted)
            } catch {
                throw RorkSignError.invalidSigningIdentity("Decrypted P-384 private key PEM could not be loaded.")
            }
        }
    }

    /// Signs a digest with ECDSA over P-384 and returns DER-encoded `r,s`.
    func signature(for digest: SHA256.Digest) throws -> Data {
        do {
            return try privateKey.signature(for: digest).derRepresentation
        } catch {
            throw RorkSignError.cmsSigning("P-384 ECDSA signature generation failed.")
        }
    }

    var publicKeyDERRepresentation: Data {
        privateKey.publicKey.derRepresentation
    }

    /// PKCS#8 DER used only when placing this opaque key into PKCS#12.
    var pkcs8DERRepresentation: Data {
        privateKey.pkcs8DERRepresentation
    }
}

/// Small wrapper around Swift Crypto's P-521 signing key type.
struct P521PrivateSigningKey: Sendable {
    private let privateKey: P521.Signing.PrivateKey

    init(derRepresentation: Data, password: String = "") throws {
        let candidate = try decryptedDERIfNeeded(
            derRepresentation,
            password: password,
            keyFamily: "P-521"
        )
        do {
            self.privateKey = try P521.Signing.PrivateKey(derRepresentation: candidate)
        } catch {
            if let rawScalar = try? sec1PrivateKeyScalar(
                from: candidate,
                expectedCurveOID: OID.secp521r1,
                scalarByteCount: 66,
                keyFamily: "P-521"
            ) {
                do {
                    self.privateKey = try P521.Signing.PrivateKey(rawRepresentation: rawScalar)
                    return
                } catch {
                    throw RorkSignError.invalidSigningIdentity("P-521 SEC.1 private key DER could not be loaded.")
                }
            }
            throw RorkSignError.invalidSigningIdentity("P-521 private key DER could not be loaded.")
        }
    }

    init(pemRepresentation: String, password: String = "") throws {
        do {
            self.privateKey = try P521.Signing.PrivateKey(pemRepresentation: pemRepresentation)
        } catch {
            if let sec1DER = try? PEM.decode(pemRepresentation, acceptedTypes: ["EC PRIVATE KEY"]),
               let rawScalar = try? sec1PrivateKeyScalar(
                   from: sec1DER,
                   expectedCurveOID: OID.secp521r1,
                   scalarByteCount: 66,
                   keyFamily: "P-521"
               ) {
                do {
                    self.privateKey = try P521.Signing.PrivateKey(rawRepresentation: rawScalar)
                    return
                } catch {
                    throw RorkSignError.invalidSigningIdentity("P-521 SEC.1 private key PEM could not be loaded.")
                }
            }

            let encryptedPrivateKeyDER = try PEM.decode(
                pemRepresentation,
                acceptedTypes: ["ENCRYPTED PRIVATE KEY"]
            )
            let decrypted = try EncryptedPrivateKeyInfo.decrypt(
                encryptedPrivateKeyDER,
                password: password
            )
            do {
                self.privateKey = try P521.Signing.PrivateKey(derRepresentation: decrypted)
            } catch {
                throw RorkSignError.invalidSigningIdentity("Decrypted P-521 private key PEM could not be loaded.")
            }
        }
    }

    /// Signs a digest with ECDSA over P-521 and returns DER-encoded `r,s`.
    func signature(for digest: SHA256.Digest) throws -> Data {
        do {
            return try privateKey.signature(for: digest).derRepresentation
        } catch {
            throw RorkSignError.cmsSigning("P-521 ECDSA signature generation failed.")
        }
    }

    var publicKeyDERRepresentation: Data {
        privateKey.publicKey.derRepresentation
    }

    /// PKCS#8 DER used only when placing this opaque key into PKCS#12.
    var pkcs8DERRepresentation: Data {
        privateKey.pkcs8DERRepresentation
    }
}

/// Decrypts encrypted PKCS#8 private-key input before family-specific parsing.
private func decryptedDERIfNeeded(_ data: Data, password: String, keyFamily: String) throws -> Data {
    guard EncryptedPrivateKeyInfo.looksLike(data) else {
        return data
    }
    guard !password.isEmpty else {
        throw RorkSignError.invalidSigningIdentity("\(keyFamily) private key DER is encrypted.")
    }
    return try EncryptedPrivateKeyInfo.decrypt(data, password: password)
}

/// Extracts the private scalar from an SEC.1 `ECPrivateKey` value.
///
/// OpenSSL commonly emits unencrypted EC keys as `BEGIN EC PRIVATE KEY`
/// documents. Swift Crypto accepts many of those directly, but parsing the
/// small SEC.1 wrapper ourselves gives the signer stable behavior across all
/// supported NIST curves while still delegating the actual ECDSA operations to
/// Swift Crypto.
private func sec1PrivateKeyScalar(
    from data: Data,
    expectedCurveOID: String,
    scalarByteCount: Int,
    keyFamily: String
) throws -> Data {
    var outerReader = DERReader(data)
    let ecPrivateKey = try outerReader.readNode(expectedTag: 0x30)
    guard outerReader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("\(keyFamily) SEC.1 private key has trailing data.")
    }

    var reader = DERReader(ecPrivateKey.content)
    let version = try reader.readNode(expectedTag: 0x02)
    guard version.content == Data([0x01]) else {
        throw RorkSignError.invalidSigningIdentity("\(keyFamily) SEC.1 private key version is not 1.")
    }

    let privateKey = try reader.readNode(expectedTag: 0x04).content
    var curveOID: String?
    while !reader.isAtEnd {
        let field = try reader.readNode()
        switch field.tag {
        case 0xa0:
            var parameterReader = DERReader(field.content)
            let oidNode = try parameterReader.readNode(expectedTag: 0x06)
            guard parameterReader.isAtEnd, let oid = objectIdentifierValue(oidNode) else {
                throw RorkSignError.invalidSigningIdentity("\(keyFamily) SEC.1 curve parameters are malformed.")
            }
            curveOID = oid
        case 0xa1:
            continue
        default:
            throw RorkSignError.invalidSigningIdentity("\(keyFamily) SEC.1 private key has an unexpected field.")
        }
    }

    if let curveOID, curveOID != expectedCurveOID {
        throw RorkSignError.invalidSigningIdentity("\(keyFamily) SEC.1 private key uses curve \(curveOID).")
    }

    if privateKey.count == scalarByteCount {
        return privateKey
    }
    if privateKey.count < scalarByteCount {
        return Data(repeating: 0, count: scalarByteCount - privateKey.count) + privateKey
    }
    if privateKey.count == scalarByteCount + 1, privateKey.first == 0 {
        return Data(privateKey.dropFirst())
    }

    throw RorkSignError.invalidSigningIdentity("\(keyFamily) SEC.1 private scalar has an unexpected length.")
}

/// Extracted X.509 certificate fields used by signing, inspection, and OCSP.
struct CertificateInfo: Sendable {
    let tbsCertificateDER: Data
    let issuerDER: Data
    let subjectDER: Data
    let serialNumberDER: Data
    let serialNumberHex: String
    let subjectCommonName: String
    let subjectOrganizationName: String
    let issuerCommonName: String
    let ocspResponderURLs: [String]
    let crlDistributionPointURLs: [String]
    let extendedKeyUsageOIDs: [String]
    let isCertificateAuthority: Bool
    let pathLengthConstraint: Int?
    let hasKeyUsageExtension: Bool
    let keyUsage: CertificateKeyUsage
    let notBefore: Date
    let notAfter: Date
    let subjectPublicKeyInfoDER: Data
    let keyAlgorithm: String
    let signatureAlgorithmOID: String
    let signature: Data

    /// Whether this certificate is structurally allowed to issue child certificates.
    var canSignCertificates: Bool {
        isCertificateAuthority && (!hasKeyUsageExtension || keyUsage.contains(.keyCertSign))
    }

    /// Parses the leaf certificate fields needed by signing and diagnostics.
    ///
    /// Full certificate validation is intentionally out of scope here. CMS needs
    /// the issuer-and-serial identifier so verifiers can match SignerInfo to the
    /// embedded certificate. Code-signing requirements also need the subject
    /// common name so identity-backed signatures can bind the designated
    /// requirement to the selected certificate identity. Certificate-check
    /// diagnostics additionally expose Authority Information Access OCSP URLs
    /// and CRL Distribution Point URLs when the certificate advertises them.
    /// OCSP response validation also uses the TBSCertificate, certificate
    /// signature, validity window, and Extended Key Usage metadata to authorize
    /// delegated responders without making a network revocation decision.
    static func parse(_ certificateDER: Data) throws -> CertificateInfo {
        var certificateReader = DERReader(certificateDER)
        let certificate = try certificateReader.readNode(expectedTag: 0x30)
        guard certificateReader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("Certificate DER has trailing data.")
        }

        var certificateBody = DERReader(certificate.content)
        let tbsCertificate = try certificateBody.readNode(expectedTag: 0x30)
        let signatureAlgorithm = try certificateBody.readNode(expectedTag: 0x30)
        let signature = try certificateSignatureBytes(from: try certificateBody.readNode(expectedTag: 0x03))
        guard certificateBody.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("Certificate has extra fields.")
        }

        var tbs = DERReader(tbsCertificate.content)

        let first = try tbs.readNode()
        let serialNode: DERNode
        if first.tag == 0xa0 {
            serialNode = try tbs.readNode(expectedTag: 0x02)
        } else if first.tag == 0x02 {
            serialNode = first
        } else {
            throw RorkSignError.invalidSigningIdentity("Certificate TBSCertificate is missing a serial number.")
        }

        _ = try tbs.readNode(expectedTag: 0x30)
        let issuer = try tbs.readNode(expectedTag: 0x30)
        let validity = try tbs.readNode(expectedTag: 0x30)
        let validityWindow = try certificateValidity(in: validity)
        let subject = try tbs.readNode(expectedTag: 0x30)
        let subjectPublicKeyInfo = try tbs.readNode(expectedTag: 0x30)
        let extensionMetadata = try certificateExtensionMetadata(inRemainingTBSCertificateFields: &tbs)

        return CertificateInfo(
            tbsCertificateDER: tbsCertificate.fullDER,
            issuerDER: issuer.fullDER,
            subjectDER: subject.fullDER,
            serialNumberDER: serialNode.fullDER,
            serialNumberHex: formattedSerialNumberHex(from: serialNode.content),
            subjectCommonName: nameAttributeValue(in: subject, oid: OID.commonName) ?? "",
            subjectOrganizationName: nameAttributeValue(in: subject, oid: OID.organizationName) ?? "",
            issuerCommonName: nameAttributeValue(in: issuer, oid: OID.commonName) ?? "",
            ocspResponderURLs: extensionMetadata.ocspResponderURLs,
            crlDistributionPointURLs: extensionMetadata.crlDistributionPointURLs,
            extendedKeyUsageOIDs: extensionMetadata.extendedKeyUsageOIDs,
            isCertificateAuthority: extensionMetadata.isCertificateAuthority,
            pathLengthConstraint: extensionMetadata.pathLengthConstraint,
            hasKeyUsageExtension: extensionMetadata.hasKeyUsageExtension,
            keyUsage: extensionMetadata.keyUsage,
            notBefore: validityWindow.notBefore,
            notAfter: validityWindow.notAfter,
            subjectPublicKeyInfoDER: subjectPublicKeyInfo.fullDER,
            keyAlgorithm: try publicKeyAlgorithm(in: subjectPublicKeyInfo),
            signatureAlgorithmOID: try algorithmIdentifierOID(signatureAlgorithm),
            signature: signature
        )
    }
}

/// Revocation-related URLs advertised by X.509 certificate extensions.
private struct CertificateExtensionMetadata {
    var ocspResponderURLs: [String] = []
    var crlDistributionPointURLs: [String] = []
    var extendedKeyUsageOIDs: [String] = []
    var isCertificateAuthority = false
    var pathLengthConstraint: Int?
    var hasKeyUsageExtension = false
    var keyUsage: CertificateKeyUsage = []
}

/// Extracts revocation metadata from the optional X.509 extensions wrapper.
private func certificateExtensionMetadata(
    inRemainingTBSCertificateFields tbs: inout DERReader
) throws -> CertificateExtensionMetadata {
    var metadata = CertificateExtensionMetadata()
    while !tbs.isAtEnd {
        let field = try tbs.readNode()
        guard field.tag == 0xa3 else {
            continue
        }
        metadata.append(try certificateExtensionMetadata(inExtensionsWrapper: field))
    }
    return metadata
}

/// Parses the explicit `[3] Extensions` wrapper from a TBSCertificate.
private func certificateExtensionMetadata(inExtensionsWrapper wrapper: DERNode) throws -> CertificateExtensionMetadata {
    var wrapperReader = DERReader(wrapper.content)
    let extensions = try wrapperReader.readNode(expectedTag: 0x30)
    guard wrapperReader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate extensions wrapper has trailing data.")
    }

    var metadata = CertificateExtensionMetadata()
    var extensionsReader = DERReader(extensions.content)
    while !extensionsReader.isAtEnd {
        let ext = try extensionsReader.readNode(expectedTag: 0x30)
        metadata.append(try certificateExtensionMetadata(inExtension: ext))
    }
    return metadata
}

/// Parses one X.509 extension and returns metadata from known extensions.
private func certificateExtensionMetadata(inExtension ext: DERNode) throws -> CertificateExtensionMetadata {
    var reader = DERReader(ext.content)
    let oidNode = try reader.readNode(expectedTag: 0x06)
    guard let oid = objectIdentifierValue(oidNode),
          oid == OID.authorityInfoAccess
            || oid == OID.crlDistributionPoints
            || oid == OID.extendedKeyUsage
            || oid == OID.basicConstraints
            || oid == OID.keyUsage else {
        return CertificateExtensionMetadata()
    }

    if !reader.isAtEnd, try reader.peekByte() == 0x01 {
        _ = try reader.readNode(expectedTag: 0x01)
    }
    let value = try reader.readNode(expectedTag: 0x04)
    guard reader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate extension has trailing data.")
    }

    if oid == OID.authorityInfoAccess {
        return CertificateExtensionMetadata(
            ocspResponderURLs: try certificateOCSPResponderURLs(inAuthorityInfoAccess: value.content)
        )
    } else if oid == OID.crlDistributionPoints {
        return CertificateExtensionMetadata(
            crlDistributionPointURLs: try certificateCRLDistributionPointURLs(inCRLDistributionPoints: value.content)
        )
    } else if oid == OID.extendedKeyUsage {
        return CertificateExtensionMetadata(
            extendedKeyUsageOIDs: try certificateExtendedKeyUsageOIDs(in: value.content)
        )
    } else if oid == OID.basicConstraints {
        let basicConstraints = try certificateBasicConstraints(in: value.content)
        return CertificateExtensionMetadata(
            isCertificateAuthority: basicConstraints.isCertificateAuthority,
            pathLengthConstraint: basicConstraints.pathLengthConstraint
        )
    } else {
        return CertificateExtensionMetadata(
            hasKeyUsageExtension: true,
            keyUsage: try certificateKeyUsage(in: value.content)
        )
    }
}

/// Parses AuthorityInfoAccessSyntax and extracts `id-ad-ocsp` URI names.
private func certificateOCSPResponderURLs(inAuthorityInfoAccess data: Data) throws -> [String] {
    var reader = DERReader(data)
    let sequence = try reader.readNode(expectedTag: 0x30)
    guard reader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate AIA payload has trailing data.")
    }

    var urls: [String] = []
    var accessDescriptions = DERReader(sequence.content)
    while !accessDescriptions.isAtEnd {
        let accessDescription = try accessDescriptions.readNode(expectedTag: 0x30)
        var accessReader = DERReader(accessDescription.content)
        let method = try accessReader.readNode(expectedTag: 0x06)
        let location = try accessReader.readNode()
        guard accessReader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("Certificate AIA access description has trailing data.")
        }
        guard objectIdentifierValue(method) == OID.ocsp,
              location.tag == 0x86,
              let url = String(data: location.content, encoding: .ascii),
              !url.isEmpty else {
            continue
        }
        urls.append(url)
    }
    return urls
}

/// Parses CRLDistributionPoints and extracts full-name URI entries.
private func certificateCRLDistributionPointURLs(inCRLDistributionPoints data: Data) throws -> [String] {
    var reader = DERReader(data)
    let sequence = try reader.readNode(expectedTag: 0x30)
    guard reader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate CRL distribution points payload has trailing data.")
    }

    var urls: [String] = []
    var points = DERReader(sequence.content)
    while !points.isAtEnd {
        let point = try points.readNode(expectedTag: 0x30)
        urls.append(contentsOf: try certificateCRLDistributionPointURLs(inDistributionPoint: point))
    }
    return urls
}

/// Parses one DistributionPoint and returns URI names from its `fullName`.
private func certificateCRLDistributionPointURLs(inDistributionPoint point: DERNode) throws -> [String] {
    var urls: [String] = []
    var reader = DERReader(point.content)
    while !reader.isAtEnd {
        let field = try reader.readNode()
        guard field.tag == 0xa0 else {
            continue
        }
        urls.append(contentsOf: try certificateCRLDistributionPointURLs(inDistributionPointName: field.content))
    }
    return urls
}

/// Parses DistributionPointName and keeps only URI GeneralName values.
private func certificateCRLDistributionPointURLs(inDistributionPointName data: Data) throws -> [String] {
    var reader = DERReader(data)
    let name = try reader.readNode()
    guard reader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate CRL distribution point name has trailing data.")
    }
    guard name.tag == 0xa0 else {
        return []
    }
    return try certificateURIGeneralNames(inGeneralNamesContent: name.content)
}

/// Parses a GeneralNames payload and returns URI GeneralName values.
private func certificateURIGeneralNames(inGeneralNamesContent data: Data) throws -> [String] {
    var urls: [String] = []
    var reader = DERReader(data)
    while !reader.isAtEnd {
        let name = try reader.readNode()
        guard name.tag == 0x86,
              let url = String(data: name.content, encoding: .ascii),
              !url.isEmpty else {
            continue
        }
        urls.append(url)
    }
    return urls
}

/// Parses the ExtKeyUsageSyntax sequence into OID strings.
private func certificateExtendedKeyUsageOIDs(in data: Data) throws -> [String] {
    var reader = DERReader(data)
    let sequence = try reader.readNode(expectedTag: 0x30)
    guard reader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate extended key usage payload has trailing data.")
    }

    var result: [String] = []
    var usages = DERReader(sequence.content)
    while !usages.isAtEnd {
        let oidNode = try usages.readNode(expectedTag: 0x06)
        guard let oid = objectIdentifierValue(oidNode) else {
            throw RorkSignError.invalidSigningIdentity("Certificate extended key usage OID is malformed.")
        }
        result.append(oid)
    }
    return result
}

/// Parses BasicConstraints and returns CA/path-length metadata.
private func certificateBasicConstraints(
    in data: Data
) throws -> (isCertificateAuthority: Bool, pathLengthConstraint: Int?) {
    var reader = DERReader(data)
    let sequence = try reader.readNode(expectedTag: 0x30)
    guard reader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate basic constraints payload has trailing data.")
    }

    var constraints = DERReader(sequence.content)
    var isCertificateAuthority = false
    if !constraints.isAtEnd, try constraints.peekByte() == 0x01 {
        let ca = try constraints.readNode(expectedTag: 0x01)
        guard ca.content.count == 1 else {
            throw RorkSignError.invalidSigningIdentity("Certificate basic constraints CA boolean is malformed.")
        }
        isCertificateAuthority = ca.content[0] != 0
    }

    var pathLengthConstraint: Int?
    if !constraints.isAtEnd {
        pathLengthConstraint = try certificateNonNegativeInteger(
            try constraints.readNode(expectedTag: 0x02),
            fieldName: "Certificate basic constraints path length"
        )
    }
    guard constraints.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate basic constraints has extra fields.")
    }
    return (isCertificateAuthority, pathLengthConstraint)
}

/// Parses KeyUsage and returns recognized RFC 5280 usage bits.
private func certificateKeyUsage(in data: Data) throws -> CertificateKeyUsage {
    var reader = DERReader(data)
    let bitString = try reader.readNode(expectedTag: 0x03)
    guard reader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate key usage payload has trailing data.")
    }
    guard let unusedBitCount = bitString.content.first,
          unusedBitCount <= 7 else {
        throw RorkSignError.invalidSigningIdentity("Certificate key usage BIT STRING is malformed.")
    }

    let bytes = Array(bitString.content.dropFirst())
    guard !bytes.isEmpty || unusedBitCount == 0 else {
        throw RorkSignError.invalidSigningIdentity("Certificate key usage BIT STRING is malformed.")
    }

    let bitCount = bytes.count * 8 - Int(unusedBitCount)
    var keyUsage: CertificateKeyUsage = []
    for bitIndex in 0..<Swift.min(bitCount, 9) {
        let byte = bytes[bitIndex / 8]
        let mask = UInt8(0x80 >> UInt8(bitIndex % 8))
        guard byte & mask != 0 else {
            continue
        }
        keyUsage.insert(CertificateKeyUsage(rawValue: UInt16(1 << bitIndex)))
    }
    return keyUsage
}

private extension CertificateExtensionMetadata {
    /// Merges metadata from a nested certificate extension parser.
    mutating func append(_ other: CertificateExtensionMetadata) {
        ocspResponderURLs.append(contentsOf: other.ocspResponderURLs)
        crlDistributionPointURLs.append(contentsOf: other.crlDistributionPointURLs)
        extendedKeyUsageOIDs.append(contentsOf: other.extendedKeyUsageOIDs)
        isCertificateAuthority = isCertificateAuthority || other.isCertificateAuthority
        if let pathLengthConstraint = other.pathLengthConstraint {
            self.pathLengthConstraint = pathLengthConstraint
        }
        hasKeyUsageExtension = hasKeyUsageExtension || other.hasKeyUsageExtension
        keyUsage.formUnion(other.keyUsage)
    }
}

/// Decodes one non-negative DER INTEGER used by certificate extensions.
private func certificateNonNegativeInteger(_ node: DERNode, fieldName: String) throws -> Int {
    guard !node.content.isEmpty else {
        throw RorkSignError.invalidSigningIdentity("\(fieldName) is empty.")
    }
    guard node.content[0] & 0x80 == 0 else {
        throw RorkSignError.invalidSigningIdentity("\(fieldName) is negative.")
    }

    var value = 0
    for byte in node.content {
        if value > (Int.max - Int(byte)) / 256 {
            throw RorkSignError.invalidSigningIdentity("\(fieldName) is too large.")
        }
        value = value * 256 + Int(byte)
    }
    return value
}

/// Formats an X.509 serial number as colon-separated uppercase hex.
private func formattedSerialNumberHex(from serial: Data) -> String {
    var bytes = Array(serial)
    while bytes.count > 1 && bytes.first == 0 {
        bytes.removeFirst()
    }
    return bytes
        .map { String(format: "%02X", $0) }
        .joined(separator: ":")
}

/// Extracts the X.509 validity window.
private func certificateValidity(in validity: DERNode) throws -> (notBefore: Date, notAfter: Date) {
    var reader = DERReader(validity.content)
    let notBefore = try reader.readNode()
    let notAfter = try reader.readNode()
    guard reader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("Certificate validity has extra fields.")
    }
    return (try certificateTime(notBefore), try certificateTime(notAfter))
}

/// Parses the DER time formats allowed by X.509 certificates.
private func certificateTime(_ node: DERNode) throws -> Date {
    guard let value = String(data: node.content, encoding: .ascii) else {
        throw RorkSignError.invalidSigningIdentity("Certificate validity time is not ASCII.")
    }

    switch node.tag {
    case 0x17:
        return try parseCertificateTime(value, yearDigitCount: 2)
    case 0x18:
        return try parseCertificateTime(value, yearDigitCount: 4)
    default:
        throw RorkSignError.invalidSigningIdentity("Certificate validity time has an unsupported tag.")
    }
}

/// Parses `UTCTime` and `GeneralizedTime` values with `Z` or numeric offsets.
private func parseCertificateTime(_ value: String, yearDigitCount: Int) throws -> Date {
    guard let zoneStart = value.firstIndex(where: { $0 == "Z" || $0 == "+" || $0 == "-" }) else {
        throw RorkSignError.invalidSigningIdentity("Certificate validity time has no time zone.")
    }

    var timestamp = String(value[..<zoneStart])
    if let fractionalStart = timestamp.firstIndex(of: ".") {
        timestamp = String(timestamp[..<fractionalStart])
    }
    let zone = String(value[zoneStart...])
    let minimumDigitCount = yearDigitCount + 8
    let maximumDigitCount = yearDigitCount + 10
    guard timestamp.count == minimumDigitCount || timestamp.count == maximumDigitCount else {
        throw RorkSignError.invalidSigningIdentity("Certificate validity time has an unsupported precision.")
    }

    let yearDigits = try integerPrefix(timestamp, offset: 0, count: yearDigitCount)
    let year = yearDigitCount == 2
        ? (yearDigits >= 50 ? 1900 + yearDigits : 2000 + yearDigits)
        : yearDigits
    let month = try integerPrefix(timestamp, offset: yearDigitCount, count: 2)
    let day = try integerPrefix(timestamp, offset: yearDigitCount + 2, count: 2)
    let hour = try integerPrefix(timestamp, offset: yearDigitCount + 4, count: 2)
    let minute = try integerPrefix(timestamp, offset: yearDigitCount + 6, count: 2)
    let second = timestamp.count == maximumDigitCount
        ? try integerPrefix(timestamp, offset: yearDigitCount + 8, count: 2)
        : 0
    let secondsFromGMT = try timeZoneOffsetSeconds(zone)

    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(secondsFromGMT: secondsFromGMT) ?? TimeZone(secondsFromGMT: 0)!
    var components = DateComponents()
    components.calendar = calendar
    components.timeZone = calendar.timeZone
    components.year = year
    components.month = month
    components.day = day
    components.hour = hour
    components.minute = minute
    components.second = second
    guard let date = components.date else {
        throw RorkSignError.invalidSigningIdentity("Certificate validity time is invalid.")
    }
    return date
}

private func integerPrefix(_ value: String, offset: Int, count: Int) throws -> Int {
    let start = value.index(value.startIndex, offsetBy: offset)
    let end = value.index(start, offsetBy: count)
    guard let integer = Int(value[start..<end]) else {
        throw RorkSignError.invalidSigningIdentity("Certificate validity time contains non-digits.")
    }
    return integer
}

private func timeZoneOffsetSeconds(_ value: String) throws -> Int {
    if value == "Z" {
        return 0
    }
    guard value.count == 5,
          let sign = value.first,
          sign == "+" || sign == "-" else {
        throw RorkSignError.invalidSigningIdentity("Certificate validity time has an invalid time zone.")
    }
    let hours = try integerPrefix(value, offset: 1, count: 2)
    let minutes = try integerPrefix(value, offset: 3, count: 2)
    guard hours <= 23, minutes <= 59 else {
        throw RorkSignError.invalidSigningIdentity("Certificate validity time zone is out of range.")
    }
    let offset = hours * 3600 + minutes * 60
    return sign == "+" ? offset : -offset
}

/// Extracts the first X.509 Name attribute matching `oid`.
private func nameAttributeValue(in name: DERNode, oid: String) -> String? {
    var rdnSequence = DERReader(name.content)
    while !rdnSequence.isAtEnd {
        guard let relativeDistinguishedName = try? rdnSequence.readNode(expectedTag: 0x31) else {
            return nil
        }
        var attributes = DERReader(relativeDistinguishedName.content)
        while !attributes.isAtEnd {
            guard let attribute = try? attributes.readNode(expectedTag: 0x30) else {
                return nil
            }
            guard let value = nameAttributeValue(attribute, oid: oid) else {
                continue
            }
            return value
        }
    }
    return nil
}

/// Decodes one AttributeTypeAndValue if its type matches `oid`.
private func nameAttributeValue(_ attribute: DERNode, oid: String) -> String? {
    var reader = DERReader(attribute.content)
    guard let oidNode = try? reader.readNode(expectedTag: 0x06),
          objectIdentifierValue(oidNode) == oid,
          let valueNode = try? reader.readNode() else {
        return nil
    }

    switch valueNode.tag {
    case 0x0c, 0x13, 0x16:
        return String(data: valueNode.content, encoding: .utf8)
    case 0x1e:
        return stringFromBMPString(valueNode.content)
    default:
        return nil
    }
}

/// Returns a human-readable public-key algorithm summary from SubjectPublicKeyInfo.
private func publicKeyAlgorithm(in subjectPublicKeyInfo: DERNode) throws -> String {
    var reader = DERReader(subjectPublicKeyInfo.content)
    let algorithmIdentifier = try reader.readNode(expectedTag: 0x30)
    let publicKey = try reader.readNode(expectedTag: 0x03)

    var algorithmReader = DERReader(algorithmIdentifier.content)
    let algorithmOIDNode = try algorithmReader.readNode(expectedTag: 0x06)
    guard let algorithmOID = objectIdentifierValue(algorithmOIDNode) else {
        throw RorkSignError.invalidSigningIdentity("Certificate public-key algorithm OID is malformed.")
    }

    switch algorithmOID {
    case OID.rsaEncryption:
        if let bitCount = try? rsaPublicKeyBitCount(in: publicKey) {
            return "RSA \(bitCount)-bit"
        }
        return "RSA"
    case OID.ecPublicKey:
        if let curveName = ellipticCurveName(from: try? algorithmReader.readNode()) {
            return "EC \(curveName)"
        }
        return "EC"
    case OID.ed25519:
        return "Ed25519"
    default:
        return algorithmOID
    }
}

/// Returns the object identifier from an AlgorithmIdentifier sequence.
private func algorithmIdentifierOID(_ node: DERNode) throws -> String {
    var reader = DERReader(node.content)
    let oidNode = try reader.readNode(expectedTag: 0x06)
    guard let oid = objectIdentifierValue(oidNode) else {
        throw RorkSignError.invalidSigningIdentity("AlgorithmIdentifier OID is malformed.")
    }
    if !reader.isAtEnd {
        _ = try reader.readNode()
    }
    guard reader.isAtEnd else {
        throw RorkSignError.invalidSigningIdentity("AlgorithmIdentifier has extra fields.")
    }
    return oid
}

/// Extracts the byte-aligned certificate signature from a BIT STRING.
private func certificateSignatureBytes(from node: DERNode) throws -> Data {
    guard node.content.first == 0 else {
        throw RorkSignError.invalidSigningIdentity("Certificate signature BIT STRING is malformed.")
    }
    return Data(node.content.dropFirst())
}

/// Reads the RSA modulus size from a SubjectPublicKeyInfo BIT STRING.
private func rsaPublicKeyBitCount(in bitString: DERNode) throws -> Int {
    guard bitString.tag == 0x03,
          let unusedBits = bitString.content.first,
          unusedBits == 0 else {
        throw RorkSignError.invalidSigningIdentity("Certificate RSA public key is malformed.")
    }

    let publicKeyDER = bitString.content.dropFirst()
    var publicKeyReader = DERReader(Data(publicKeyDER))
    let rsaPublicKey = try publicKeyReader.readNode(expectedTag: 0x30)
    var rsaReader = DERReader(rsaPublicKey.content)
    let modulus = try rsaReader.readNode(expectedTag: 0x02)
    return bitCount(ofPositiveInteger: modulus.content)
}

/// Counts the meaningful bits in a positive ASN.1 INTEGER.
private func bitCount(ofPositiveInteger integer: Data) -> Int {
    var bytes = Array(integer)
    while bytes.count > 1 && bytes.first == 0 {
        bytes.removeFirst()
    }
    guard let first = bytes.first, first != 0 else {
        return 0
    }
    return (bytes.count - 1) * 8 + (8 - first.leadingZeroBitCount)
}

/// Maps common EC curve OIDs to concise names.
private func ellipticCurveName(from node: DERNode?) -> String? {
    guard let node, node.tag == 0x06, let oid = objectIdentifierValue(node) else {
        return nil
    }
    switch oid {
    case OID.prime256v1:
        return "P-256"
    case OID.secp384r1:
        return "P-384"
    case OID.secp521r1:
        return "P-521"
    default:
        return oid
    }
}

private func objectIdentifierValue(_ node: DERNode) -> String? {
    guard let first = node.content.first else {
        return nil
    }

    let firstArc: Int
    let secondArc: Int
    if first < 40 {
        firstArc = 0
        secondArc = Int(first)
    } else if first < 80 {
        firstArc = 1
        secondArc = Int(first) - 40
    } else {
        firstArc = 2
        secondArc = Int(first) - 80
    }

    var arcs = [firstArc, secondArc]
    var value = 0
    var hasContinuation = false
    for byte in node.content.dropFirst() {
        guard value <= (Int.max >> 7) else {
            return nil
        }
        value = (value << 7) | Int(byte & 0x7f)
        hasContinuation = byte & 0x80 != 0
        if !hasContinuation {
            arcs.append(value)
            value = 0
        }
    }
    guard !hasContinuation else {
        return nil
    }
    return arcs.map(String.init).joined(separator: ".")
}

private func stringFromBMPString(_ data: Data) -> String? {
    guard data.count.isMultiple(of: 2) else {
        return nil
    }
    var utf16: [UInt16] = []
    utf16.reserveCapacity(data.count / 2)
    var offset = 0
    while offset < data.count {
        utf16.append((UInt16(data[offset]) << 8) | UInt16(data[offset + 1]))
        offset += 2
    }
    return String(decoding: utf16, as: UTF16.self)
}

private enum OID {
    static let commonName = "2.5.4.3"
    static let organizationName = "2.5.4.10"
    static let rsaEncryption = "1.2.840.113549.1.1.1"
    static let ecPublicKey = "1.2.840.10045.2.1"
    static let ed25519 = "1.3.101.112"
    static let authorityInfoAccess = "1.3.6.1.5.5.7.1.1"
    static let basicConstraints = "2.5.29.19"
    static let keyUsage = "2.5.29.15"
    static let crlDistributionPoints = "2.5.29.31"
    static let extendedKeyUsage = "2.5.29.37"
    static let ocsp = "1.3.6.1.5.5.7.48.1"
    static let prime256v1 = "1.2.840.10045.3.1.7"
    static let secp384r1 = "1.3.132.0.34"
    static let secp521r1 = "1.3.132.0.35"
}

/// Minimal PEM decoder for public RorkSign identity inputs.
enum PEM {
    /// Decodes every PEM block whose type is expected by the caller.
    ///
    /// Certificate inputs often arrive as a concatenated leaf-plus-chain PEM.
    /// Returning every block lets identity signing preserve that chain in CMS
    /// output, while still rejecting unexpected PEM labels instead of silently
    /// treating unrelated data as signing material.
    static func decodeAll(_ pem: String, acceptedTypes: Set<String>) throws -> [Data] {
        let lines = pem
            .split(whereSeparator: \.isNewline)
            .map(String.init)
        var result: [Data] = []
        var searchIndex = lines.startIndex

        while let beginIndex = lines[searchIndex...].firstIndex(where: { line in
            line.hasPrefix("-----BEGIN ") && line.hasSuffix("-----")
        }) {
            guard let endIndex = lines[(beginIndex + 1)...].firstIndex(where: { line in
                line.hasPrefix("-----END ") && line.hasSuffix("-----")
            }) else {
                throw RorkSignError.invalidSigningIdentity("PEM document is malformed.")
            }

            let type = String(lines[beginIndex].dropFirst("-----BEGIN ".count).dropLast("-----".count))
            let endType = String(lines[endIndex].dropFirst("-----END ".count).dropLast("-----".count))
            guard type == endType, acceptedTypes.contains(type) else {
                throw RorkSignError.invalidSigningIdentity("PEM document type is not supported.")
            }

            let base64 = lines[(beginIndex + 1)..<endIndex].joined()
            guard let data = Data(base64Encoded: base64) else {
                throw RorkSignError.invalidSigningIdentity("PEM payload is not valid base64.")
            }
            result.append(data)
            searchIndex = endIndex + 1
        }

        guard !result.isEmpty else {
            throw RorkSignError.invalidSigningIdentity("PEM document is malformed.")
        }
        return result
    }

    static func decode(_ pem: String, acceptedTypes: Set<String>) throws -> Data {
        try decodeAll(pem, acceptedTypes: acceptedTypes)[0]
    }
}

struct DERNode {
    let tag: UInt8
    let fullDER: Data
    let content: Data
}

/// Small definite-length DER reader used for certificate field extraction.
struct DERReader {
    private let data: Data
    private var offset: Int = 0

    init(_ data: Data) {
        self.data = data
    }

    var isAtEnd: Bool {
        offset == data.count
    }

    mutating func readNode(expectedTag: UInt8? = nil) throws -> DERNode {
        guard data.containsRange(offset: offset, length: 2) else {
            throw RorkSignError.invalidSigningIdentity("DER node is truncated.")
        }

        let start = offset
        let tag = data[offset]
        offset += 1
        let length = try readLength()
        guard data.containsRange(offset: offset, length: length) else {
            throw RorkSignError.invalidSigningIdentity("DER node length exceeds input.")
        }
        if let expectedTag, tag != expectedTag {
            throw RorkSignError.invalidSigningIdentity("DER node has an unexpected tag.")
        }

        let contentStart = offset
        offset += length
        return DERNode(
            tag: tag,
            fullDER: data.subdata(in: start..<offset),
            content: data.subdata(in: contentStart..<offset)
        )
    }

    /// Returns the next tag byte without advancing the reader.
    func peekByte() throws -> UInt8 {
        guard data.containsRange(offset: offset, length: 1) else {
            throw RorkSignError.invalidSigningIdentity("DER node is truncated.")
        }
        return data[offset]
    }

    private mutating func readLength() throws -> Int {
        guard data.containsRange(offset: offset, length: 1) else {
            throw RorkSignError.invalidSigningIdentity("DER length is missing.")
        }
        let first = data[offset]
        offset += 1
        if first & 0x80 == 0 {
            return Int(first)
        }

        let byteCount = Int(first & 0x7f)
        guard byteCount > 0, byteCount <= 4,
              data.containsRange(offset: offset, length: byteCount) else {
            throw RorkSignError.invalidSigningIdentity("DER length is malformed.")
        }

        var length = 0
        for _ in 0..<byteCount {
            length = (length << 8) | Int(data[offset])
            offset += 1
        }
        return length
    }
}
