#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import CryptoExtras
import Foundation

/// Certificate/private-key material extracted from a PKCS#12 container.
struct PKCS12IdentityMaterial {
    /// Leaf certificate whose public key matches `privateKeyDER`.
    let certificateDER: Data

    /// Additional X.509 certificates carried by the container.
    ///
    /// These are not used to select the signing key, but they belong in the CMS
    /// certificate set so identity-backed signatures preserve the same chain
    /// material that was exported with the `.p12`.
    let additionalCertificatesDER: [Data]

    /// PKCS#8 private key matching `certificateDER`.
    let privateKeyDER: Data
}

/// Pure Swift PKCS#12 reader for signing identities.
///
/// PKCS#12 is a nested ASN.1 container rather than a single key format:
/// `PFX -> AuthenticatedSafe -> SafeContents -> SafeBag`. Modern exports can
/// protect both safe contents and private keys with PBES2, where the actual
/// crypto is PBKDF2 plus AES-CBC. Older Keychain/OpenSSL exports commonly use
/// the PKCS#12 SHA-1 KDF with RC2/RC4/3DES; those paths are implemented here so
/// the package can consume common `.p12` identity exports without OpenSSL.
enum PKCS12IdentityImporter {
    /// Extracts the first certificate/private-key pair whose public keys match.
    static func importIdentity(_ data: Data, password: String) throws -> PKCS12IdentityMaterial {
        let pfx = try PFX.parse(data, password: password)
        let safeContents = try authenticatedSafeContents(
            from: pfx.authSafe,
            password: password
        )

        var certificates: [Data] = []
        var privateKeys: [Data] = []
        for safeContent in safeContents {
            for bag in try SafeBagParser.bags(in: safeContent) {
                switch bag {
                case .certificate(let certificateDER):
                    certificates.append(certificateDER)
                case .privateKey(let privateKeyDER):
                    privateKeys.append(privateKeyDER)
                case .encryptedPrivateKey(let encryptedPrivateKeyInfoDER):
                    privateKeys.append(
                        try EncryptedPrivateKeyInfo.decrypt(
                            encryptedPrivateKeyInfoDER,
                            password: password
                        )
                    )
                case .ignored:
                    continue
                }
            }
        }

        guard !certificates.isEmpty else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 container has no X.509 certificate.")
        }
        guard !privateKeys.isEmpty else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 container has no private key.")
        }

        for certificateDER in certificates {
            for privateKeyDER in privateKeys {
                if (try? SigningIdentity(certificateDER: certificateDER, privateKeyDER: privateKeyDER)) != nil {
                    return PKCS12IdentityMaterial(
                        certificateDER: certificateDER,
                        additionalCertificatesDER: additionalCertificates(
                            from: certificates,
                            excluding: certificateDER
                        ),
                        privateKeyDER: privateKeyDER
                    )
                }
            }
        }

        throw RorkSignError.invalidSigningIdentity("PKCS#12 certificate does not match any private key.")
    }

    /// Returns every distinct certificate except the selected leaf, preserving
    /// the container's relative order.
    private static func additionalCertificates(from certificates: [Data], excluding leaf: Data) -> [Data] {
        var result: [Data] = []
        for certificate in certificates where certificate != leaf && !result.contains(certificate) {
            result.append(certificate)
        }
        return result
    }

    /// Decodes the top-level AuthenticatedSafe and decrypts any encrypted safe.
    private static func authenticatedSafeContents(
        from authSafe: ContentInfo,
        password: String
    ) throws -> [Data] {
        guard authSafe.contentType == OID.pkcs7Data else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 authSafe is not pkcs7-data.")
        }
        let authenticatedSafeDER = try authSafe.dataContent()
        var reader = DERReader(authenticatedSafeDER)
        let sequence = try reader.readNode(expectedTag: DERTag.sequence)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 AuthenticatedSafe has trailing data.")
        }

        var contentReader = DERReader(sequence.content)
        var safeContents: [Data] = []
        while !contentReader.isAtEnd {
            let contentInfo = try ContentInfo.parse(try contentReader.readNode().fullDER)
            switch contentInfo.contentType {
            case OID.pkcs7Data:
                safeContents.append(try contentInfo.dataContent())
            case OID.pkcs7EncryptedData:
                safeContents.append(
                    try EncryptedData.decrypt(contentInfo.content, password: password)
                )
            default:
                throw RorkSignError.unsupported(
                    "PKCS#12 safe content type is not supported: \(contentInfo.contentType)."
                )
            }
        }
        return safeContents
    }
}

/// Top-level PKCS#12 `PFX` wrapper.
private struct PFX {
    let authSafe: ContentInfo

    static func parse(_ data: Data, password: String) throws -> PFX {
        var reader = DERReader(data)
        let root = try reader.readNode(expectedTag: DERTag.sequence)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 PFX has trailing data.")
        }

        var pfx = DERReader(root.content)
        let version = try pfx.readInteger()
        guard version == 3 else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 PFX version is not 3.")
        }
        let authSafe = try ContentInfo.parse(try pfx.readNode().fullDER)
        if !pfx.isAtEnd {
            let macData = try MacData.parse(try pfx.readNode(expectedTag: DERTag.sequence))
            guard pfx.isAtEnd else {
                throw RorkSignError.invalidSigningIdentity("PKCS#12 PFX has extra fields.")
            }
            try macData.verify(authSafeContent: try authSafe.dataContent(), password: password)
        }
        return PFX(authSafe: authSafe)
    }
}

/// PKCS#12 MacData authenticates the serialized AuthenticatedSafe.
///
/// The MAC is separate from safe-content encryption. Verifying it catches
/// corrupted or wrong-password containers before the importer starts trusting
/// any certificate/key material inside.
private struct MacData {
    let digestAlgorithm: LegacyPKCS12KDF.HashAlgorithm
    let digest: Data
    let salt: Data
    let iterationCount: Int

    static func parse(_ node: DERNode) throws -> MacData {
        var reader = DERReader(node.content)
        let digestInfo = try reader.readNode(expectedTag: DERTag.sequence)
        let salt = try reader.readNode(expectedTag: DERTag.octetString).content
        let iterationCount = reader.isAtEnd ? 1 : try reader.readInteger()
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 MacData has extra fields.")
        }
        guard iterationCount > 0 else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 MacData iteration count must be positive.")
        }

        var digestInfoReader = DERReader(digestInfo.content)
        let algorithm = try AlgorithmIdentifier.parse(
            try digestInfoReader.readNode(expectedTag: DERTag.sequence)
        )
        let digest = try digestInfoReader.readNode(expectedTag: DERTag.octetString).content
        guard digestInfoReader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 MacData DigestInfo has extra fields.")
        }

        return MacData(
            digestAlgorithm: try Self.hashAlgorithm(for: algorithm.oid),
            digest: digest,
            salt: salt,
            iterationCount: iterationCount
        )
    }

    func verify(authSafeContent: Data, password: String) throws {
        let keyBytes = LegacyPKCS12KDF.derive(
            password: LegacyPKCS12KDF.passwordBytes(password),
            salt: salt,
            id: .mac,
            iterations: iterationCount,
            outputByteCount: digestAlgorithm.digestByteCount,
            hashAlgorithm: digestAlgorithm
        )
        let expectedDigest = digestAlgorithm.authenticationCode(
            for: authSafeContent,
            key: SymmetricKey(data: keyBytes)
        )
        guard constantTimeEqual(digest, expectedDigest) else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 MAC verification failed.")
        }
    }

    private static func hashAlgorithm(for oid: String) throws -> LegacyPKCS12KDF.HashAlgorithm {
        switch oid {
        case OID.sha1:
            return .sha1
        case OID.sha256:
            return .sha256
        case OID.sha384:
            return .sha384
        case OID.sha512:
            return .sha512
        default:
            throw RorkSignError.unsupported("PKCS#12 MAC digest algorithm is not supported: \(oid).")
        }
    }
}

/// PKCS#7 `ContentInfo` used inside PKCS#12 containers.
private struct ContentInfo {
    let contentType: String
    let content: DERNode

    static func parse(_ data: Data) throws -> ContentInfo {
        var reader = DERReader(data)
        let root = try reader.readNode(expectedTag: DERTag.sequence)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 ContentInfo has trailing data.")
        }

        var contentInfo = DERReader(root.content)
        let contentType = try contentInfo.readObjectIdentifier()
        let content = try contentInfo.readNode(expectedTag: DERTag.explicit(0))
        guard contentInfo.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 ContentInfo has extra fields.")
        }
        return ContentInfo(contentType: contentType, content: content)
    }

    /// Returns the octets carried by `pkcs7-data`.
    func dataContent() throws -> Data {
        let octetString = try content.explicitValue(expectedTag: DERTag.octetString)
        return octetString.content
    }
}

/// Parser for `SafeBag` values inside one SafeContents sequence.
private enum SafeBagParser {
    enum Bag {
        case certificate(Data)
        case privateKey(Data)
        case encryptedPrivateKey(Data)
        case ignored
    }

    static func bags(in safeContentsDER: Data) throws -> [Bag] {
        var reader = DERReader(safeContentsDER)
        let root = try reader.readNode(expectedTag: DERTag.sequence)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("PKCS#12 SafeContents has trailing data.")
        }

        var bagReader = DERReader(root.content)
        var bags: [Bag] = []
        while !bagReader.isAtEnd {
            bags.append(try parseBag(try bagReader.readNode(expectedTag: DERTag.sequence)))
        }
        return bags
    }

    private static func parseBag(_ node: DERNode) throws -> Bag {
        var reader = DERReader(node.content)
        let bagID = try reader.readObjectIdentifier()
        let bagValue = try reader.readNode(expectedTag: DERTag.explicit(0))
        // Bag attributes are intentionally ignored. They are useful for matching
        // local key IDs, but the importer verifies the certificate/key pair
        // directly, which is stronger than trusting attributes.

        switch bagID {
        case OID.keyBag:
            return .privateKey(try bagValue.explicitValue().fullDER)
        case OID.pkcs8ShroudedKeyBag:
            return .encryptedPrivateKey(try bagValue.explicitValue().fullDER)
        case OID.certBag:
            return .certificate(try parseCertificateBag(try bagValue.explicitValue(expectedTag: DERTag.sequence)))
        default:
            return .ignored
        }
    }

    private static func parseCertificateBag(_ node: DERNode) throws -> Data {
        var reader = DERReader(node.content)
        let certificateType = try reader.readObjectIdentifier()
        guard certificateType == OID.x509Certificate else {
            throw RorkSignError.unsupported("PKCS#12 certificate bag type is not supported: \(certificateType).")
        }

        let certificateValue = try reader.readNode(expectedTag: DERTag.explicit(0))
        let octetString = try certificateValue.explicitValue(expectedTag: DERTag.octetString)
        return octetString.content
    }
}

/// PKCS#7 `EncryptedData` support for encrypted SafeContents.
private enum EncryptedData {
    static func decrypt(_ encryptedDataContent: DERNode, password: String) throws -> Data {
        let encryptedData = try encryptedDataContent.explicitValue(expectedTag: DERTag.sequence)
        var reader = DERReader(encryptedData.content)
        let version = try reader.readInteger()
        guard version == 0 else {
            throw RorkSignError.unsupported("PKCS#12 EncryptedData version is not supported.")
        }

        let encryptedContentInfo = try reader.readNode(expectedTag: DERTag.sequence)
        var contentInfoReader = DERReader(encryptedContentInfo.content)
        let contentType = try contentInfoReader.readObjectIdentifier()
        guard contentType == OID.pkcs7Data else {
            throw RorkSignError.unsupported("PKCS#12 encrypted content type is not supported: \(contentType).")
        }

        let algorithm = try AlgorithmIdentifier.parse(try contentInfoReader.readNode(expectedTag: DERTag.sequence))
        let encryptedContent = try contentInfoReader.readNode(expectedTag: DERTag.contextPrimitive(0)).content
        return try PasswordBasedDecryption.decrypt(
            encryptedContent,
            algorithm: algorithm,
            password: password
        )
    }
}

/// `EncryptedPrivateKeyInfo` support for shrouded PKCS#8 key bags.
enum EncryptedPrivateKeyInfo {
    static func looksLike(_ data: Data) -> Bool {
        var reader = DERReader(data)
        guard let root = try? reader.readNode(expectedTag: DERTag.sequence),
              reader.isAtEnd else {
            return false
        }

        var encryptedPrivateKeyInfo = DERReader(root.content)
        guard (try? encryptedPrivateKeyInfo.readNode(expectedTag: DERTag.sequence)) != nil,
              (try? encryptedPrivateKeyInfo.readNode(expectedTag: DERTag.octetString)) != nil else {
            return false
        }
        return encryptedPrivateKeyInfo.isAtEnd
    }

    static func decrypt(_ encryptedPrivateKeyInfoDER: Data, password: String) throws -> Data {
        var reader = DERReader(encryptedPrivateKeyInfoDER)
        let root = try reader.readNode(expectedTag: DERTag.sequence)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("EncryptedPrivateKeyInfo has trailing data.")
        }

        var encryptedPrivateKeyInfo = DERReader(root.content)
        let algorithm = try AlgorithmIdentifier.parse(
            try encryptedPrivateKeyInfo.readNode(expectedTag: DERTag.sequence)
        )
        let encryptedData = try encryptedPrivateKeyInfo.readNode(expectedTag: DERTag.octetString).content
        return try PasswordBasedDecryption.decrypt(
            encryptedData,
            algorithm: algorithm,
            password: password
        )
    }
}

/// ASN.1 AlgorithmIdentifier.
private struct AlgorithmIdentifier {
    let oid: String
    let parameters: DERNode?

    static func parse(_ node: DERNode) throws -> AlgorithmIdentifier {
        var reader = DERReader(node.content)
        let oid = try reader.readObjectIdentifier()
        let parameters = reader.isAtEnd ? nil : try reader.readNode()
        return AlgorithmIdentifier(oid: oid, parameters: parameters)
    }
}

/// Password-based decryption algorithms used by supported PKCS#12 exports.
private enum PasswordBasedDecryption {
    static func decrypt(_ ciphertext: Data, algorithm: AlgorithmIdentifier, password: String) throws -> Data {
        switch algorithm.oid {
        case OID.pbes2:
            return try decryptPBES2(ciphertext, parameters: algorithm.parameters, password: password)
        case OID.pbeWithSHAAnd3KeyTripleDESCBC:
            let parameters = try LegacyPBEParameters.parse(algorithm.parameters)
            return try decryptLegacyCBC(
                ciphertext,
                parameters: parameters,
                password: password,
                cipher: .tripleDES3Key
            )
        case OID.pbeWithSHAAnd2KeyTripleDESCBC:
            let parameters = try LegacyPBEParameters.parse(algorithm.parameters)
            return try decryptLegacyCBC(
                ciphertext,
                parameters: parameters,
                password: password,
                cipher: .tripleDES2Key
            )
        case OID.pbeWithSHAAnd128BitRC4:
            let parameters = try LegacyPBEParameters.parse(algorithm.parameters)
            return try decryptLegacyRC4(
                ciphertext,
                parameters: parameters,
                password: password,
                keyByteCount: 16
            )
        case OID.pbeWithSHAAnd40BitRC4:
            let parameters = try LegacyPBEParameters.parse(algorithm.parameters)
            return try decryptLegacyRC4(
                ciphertext,
                parameters: parameters,
                password: password,
                keyByteCount: 5
            )
        case OID.pbeWithSHAAnd40BitRC2CBC:
            let parameters = try LegacyPBEParameters.parse(algorithm.parameters)
            return try decryptLegacyCBC(
                ciphertext,
                parameters: parameters,
                password: password,
                cipher: .rc2(effectiveKeyBits: 40, keyByteCount: 5)
            )
        case OID.pbeWithSHAAnd128BitRC2CBC:
            let parameters = try LegacyPBEParameters.parse(algorithm.parameters)
            return try decryptLegacyCBC(
                ciphertext,
                parameters: parameters,
                password: password,
                cipher: .rc2(effectiveKeyBits: 128, keyByteCount: 16)
            )
        case OID.pbeWithSHA1AndDESCBC:
            let parameters = try LegacyPBEParameters.parse(algorithm.parameters)
            return try decryptPKCS5DESCBC(
                ciphertext,
                parameters: parameters,
                password: password,
                digest: .sha1
            )
        case OID.pbeWithMD5AndDESCBC:
            let parameters = try LegacyPBEParameters.parse(algorithm.parameters)
            return try decryptPKCS5DESCBC(
                ciphertext,
                parameters: parameters,
                password: password,
                digest: .md5
            )
        default:
            throw RorkSignError.unsupported(
                "PKCS#12 password-based encryption algorithm is not supported: \(algorithm.oid)."
            )
        }
    }

    /// Decrypts PBES2 with PBKDF2 and AES-CBC.
    private static func decryptPBES2(_ ciphertext: Data, parameters: DERNode?, password: String) throws -> Data {
        guard let parameters else {
            throw RorkSignError.invalidSigningIdentity("PBES2 parameters are missing.")
        }

        var reader = DERReader(parameters.content)
        let kdf = try AlgorithmIdentifier.parse(try reader.readNode(expectedTag: DERTag.sequence))
        let encryptionScheme = try AlgorithmIdentifier.parse(try reader.readNode(expectedTag: DERTag.sequence))
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("PBES2 parameters have extra fields.")
        }
        guard kdf.oid == OID.pbkdf2 else {
            throw RorkSignError.unsupported("PBES2 KDF is not PBKDF2: \(kdf.oid).")
        }

        let pbkdf2 = try PBKDF2Parameters.parse(kdf.parameters)
        let aes = try AESCBCParameters.parse(encryptionScheme)
        let key = try KDF.Insecure.PBKDF2.deriveKey(
            from: Data(password.utf8),
            salt: pbkdf2.salt,
            using: pbkdf2.hashFunction,
            outputByteCount: aes.keyByteCount,
            unsafeUncheckedRounds: pbkdf2.iterationCount
        )
        let iv = try AES._CBC.IV(ivBytes: aes.iv)
        do {
            return try AES._CBC.decrypt(ciphertext, using: key, iv: iv)
        } catch {
            throw RorkSignError.invalidSigningIdentity("PBES2 AES-CBC decryption failed.")
        }
    }

    /// Decrypts legacy PKCS#12 PBE algorithms.
    private static func decryptLegacyCBC(
        _ ciphertext: Data,
        parameters: LegacyPBEParameters,
        password: String,
        cipher: LegacyPKCS12Cipher
    ) throws -> Data {
        let passwordBytes = LegacyPKCS12KDF.passwordBytes(password)
        let key = LegacyPKCS12KDF.derive(
            password: passwordBytes,
            salt: parameters.salt,
            id: .key,
            iterations: parameters.iterationCount,
            outputByteCount: cipher.keyByteCount
        )
        let iv = LegacyPKCS12KDF.derive(
            password: passwordBytes,
            salt: parameters.salt,
            id: .iv,
            iterations: parameters.iterationCount,
            outputByteCount: cipher.blockByteCount
        )

        do {
            switch cipher {
            case .tripleDES3Key:
                return try TripleDESCBC.decrypt(ciphertext, key: key, iv: iv)
            case .tripleDES2Key:
                return try TripleDESCBC.decrypt(ciphertext, key: key, iv: iv)
            case .rc2(let effectiveKeyBits, _):
                return try RC2CBC.decrypt(
                    ciphertext,
                    key: key,
                    effectiveKeyBits: effectiveKeyBits,
                    iv: iv
                )
            }
        } catch {
            throw RorkSignError.invalidSigningIdentity("Legacy PKCS#12 PBE decryption failed.")
        }
    }

    /// Decrypts legacy PKCS#12 RC4 PBE algorithms.
    ///
    /// The RC4 variants use the same PKCS#12 SHA-1 KDF as the CBC algorithms,
    /// but only derive a stream-cipher key. There is no IV and no block padding
    /// to remove from the plaintext.
    private static func decryptLegacyRC4(
        _ ciphertext: Data,
        parameters: LegacyPBEParameters,
        password: String,
        keyByteCount: Int
    ) throws -> Data {
        let key = LegacyPKCS12KDF.derive(
            password: LegacyPKCS12KDF.passwordBytes(password),
            salt: parameters.salt,
            id: .key,
            iterations: parameters.iterationCount,
            outputByteCount: keyByteCount
        )

        do {
            return try RC4.decrypt(ciphertext, key: key)
        } catch {
            throw RorkSignError.invalidSigningIdentity("Legacy PKCS#12 RC4 PBE decryption failed.")
        }
    }

    /// Decrypts PKCS#5 v1.5 PBE with PBKDF1 and DES-CBC.
    ///
    /// Some OpenSSL PKCS#12 exports can use PKCS#5 PBE algorithms such as
    /// `pbeWithSHA1AndDES-CBC` or `pbeWithMD5AndDES-CBC` for shrouded private
    /// keys. Unlike PKCS#12 PBE, these use PBKDF1 over the password's raw bytes
    /// and split the digest output into DES key and IV bytes.
    private static func decryptPKCS5DESCBC(
        _ ciphertext: Data,
        parameters: LegacyPBEParameters,
        password: String,
        digest: PKCS5PBKDF1Digest
    ) throws -> Data {
        let derived = pbkdf1(
            password: Data(password.utf8),
            salt: parameters.salt,
            iterations: parameters.iterationCount,
            digest: digest
        )
        do {
            return try DESCBC.decrypt(
                ciphertext,
                key: derived.subdata(in: 0..<8),
                iv: derived.subdata(in: 8..<16)
            )
        } catch {
            throw RorkSignError.invalidSigningIdentity("PKCS#5 \(digest.label)/DES-CBC decryption failed.")
        }
    }

    /// PBKDF1 as used by PKCS#5 v1.5 PBE.
    private static func pbkdf1(
        password: Data,
        salt: Data,
        iterations: Int,
        digest algorithm: PKCS5PBKDF1Digest
    ) -> Data {
        var digest = algorithm.hash(password + salt)
        if iterations > 1 {
            for _ in 1..<iterations {
                digest = algorithm.hash(digest)
            }
        }
        return digest
    }
}

/// Digest algorithms allowed by PKCS#5 v1.5 PBKDF1 PBE.
private enum PKCS5PBKDF1Digest {
    case md5
    case sha1

    var label: String {
        switch self {
        case .md5:
            return "MD5"
        case .sha1:
            return "SHA1"
        }
    }

    /// Hashes one PBKDF1 round.
    func hash(_ data: Data) -> Data {
        switch self {
        case .md5:
            return Data(Insecure.MD5.hash(data: data))
        case .sha1:
            return Data(Insecure.SHA1.hash(data: data))
        }
    }
}

/// Legacy PKCS#12 PBE parameters.
private struct LegacyPBEParameters {
    let salt: Data
    let iterationCount: Int

    static func parse(_ node: DERNode?) throws -> LegacyPBEParameters {
        guard let node else {
            throw RorkSignError.invalidSigningIdentity("Legacy PKCS#12 PBE parameters are missing.")
        }
        var reader = DERReader(node.content)
        let salt = try reader.readNode(expectedTag: DERTag.octetString).content
        let iterationCount = try reader.readInteger()
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("Legacy PKCS#12 PBE parameters have extra fields.")
        }
        guard iterationCount > 0 else {
            throw RorkSignError.invalidSigningIdentity("Legacy PKCS#12 PBE iteration count must be positive.")
        }
        return LegacyPBEParameters(salt: salt, iterationCount: iterationCount)
    }
}

/// Legacy PKCS#12 block ciphers supported by the importer.
private enum LegacyPKCS12Cipher {
    case tripleDES3Key
    case tripleDES2Key
    case rc2(effectiveKeyBits: Int, keyByteCount: Int)

    var keyByteCount: Int {
        switch self {
        case .tripleDES3Key:
            return 24
        case .tripleDES2Key:
            return 16
        case .rc2(_, let keyByteCount):
            return keyByteCount
        }
    }

    var blockByteCount: Int {
        8
    }
}

/// PBKDF2-params from PBES2.
private struct PBKDF2Parameters {
    let salt: Data
    let iterationCount: Int
    let hashFunction: KDF.Insecure.PBKDF2.HashFunction

    static func parse(_ node: DERNode?) throws -> PBKDF2Parameters {
        guard let node else {
            throw RorkSignError.invalidSigningIdentity("PBKDF2 parameters are missing.")
        }

        var reader = DERReader(node.content)
        let salt = try reader.readNode(expectedTag: DERTag.octetString).content
        let iterationCount = try reader.readInteger()
        if !reader.isAtEnd, (try reader.peekTag()) == DERTag.integer {
            _ = try reader.readInteger()
        }

        let hashFunction: KDF.Insecure.PBKDF2.HashFunction
        if reader.isAtEnd {
            hashFunction = .insecureSHA1
        } else {
            let prf = try AlgorithmIdentifier.parse(try reader.readNode(expectedTag: DERTag.sequence))
            hashFunction = try Self.hashFunction(for: prf.oid)
        }

        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("PBKDF2 parameters have extra fields.")
        }
        guard iterationCount > 0 else {
            throw RorkSignError.invalidSigningIdentity("PBKDF2 iteration count must be positive.")
        }
        return PBKDF2Parameters(
            salt: salt,
            iterationCount: iterationCount,
            hashFunction: hashFunction
        )
    }

    private static func hashFunction(for oid: String) throws -> KDF.Insecure.PBKDF2.HashFunction {
        switch oid {
        case OID.hmacWithSHA1:
            return .insecureSHA1
        case OID.hmacWithSHA256:
            return .sha256
        case OID.hmacWithSHA384:
            return .sha384
        case OID.hmacWithSHA512:
            return .sha512
        default:
            throw RorkSignError.unsupported("PBKDF2 PRF is not supported: \(oid).")
        }
    }
}

/// AES-CBC encryptionScheme parameters from PBES2.
private struct AESCBCParameters {
    let keyByteCount: Int
    let iv: Data

    static func parse(_ algorithm: AlgorithmIdentifier) throws -> AESCBCParameters {
        let keyByteCount: Int
        switch algorithm.oid {
        case OID.aes128CBC:
            keyByteCount = 16
        case OID.aes192CBC:
            keyByteCount = 24
        case OID.aes256CBC:
            keyByteCount = 32
        default:
            throw RorkSignError.unsupported("PBES2 encryption scheme is not AES-CBC: \(algorithm.oid).")
        }

        guard let parameters = algorithm.parameters,
              parameters.tag == DERTag.octetString,
              parameters.content.count == 16 else {
            throw RorkSignError.invalidSigningIdentity("AES-CBC parameters must contain a 16-byte IV.")
        }
        return AESCBCParameters(keyByteCount: keyByteCount, iv: parameters.content)
    }
}

private enum OID {
    static let pkcs7Data = "1.2.840.113549.1.7.1"
    static let pkcs7EncryptedData = "1.2.840.113549.1.7.6"
    static let keyBag = "1.2.840.113549.1.12.10.1.1"
    static let pkcs8ShroudedKeyBag = "1.2.840.113549.1.12.10.1.2"
    static let certBag = "1.2.840.113549.1.12.10.1.3"
    static let x509Certificate = "1.2.840.113549.1.9.22.1"
    static let pbes2 = "1.2.840.113549.1.5.13"
    static let pbkdf2 = "1.2.840.113549.1.5.12"
    static let hmacWithSHA1 = "1.2.840.113549.2.7"
    static let hmacWithSHA256 = "1.2.840.113549.2.9"
    static let hmacWithSHA384 = "1.2.840.113549.2.10"
    static let hmacWithSHA512 = "1.2.840.113549.2.11"
    static let sha1 = "1.3.14.3.2.26"
    static let sha256 = "2.16.840.1.101.3.4.2.1"
    static let sha384 = "2.16.840.1.101.3.4.2.2"
    static let sha512 = "2.16.840.1.101.3.4.2.3"
    static let aes128CBC = "2.16.840.1.101.3.4.1.2"
    static let aes192CBC = "2.16.840.1.101.3.4.1.22"
    static let aes256CBC = "2.16.840.1.101.3.4.1.42"
    static let pbeWithSHAAnd128BitRC4 = "1.2.840.113549.1.12.1.1"
    static let pbeWithSHAAnd40BitRC4 = "1.2.840.113549.1.12.1.2"
    static let pbeWithSHAAnd128BitRC2CBC = "1.2.840.113549.1.12.1.5"
    static let pbeWithSHAAnd40BitRC2CBC = "1.2.840.113549.1.12.1.6"
    static let pbeWithSHAAnd3KeyTripleDESCBC = "1.2.840.113549.1.12.1.3"
    static let pbeWithSHAAnd2KeyTripleDESCBC = "1.2.840.113549.1.12.1.4"
    static let pbeWithMD5AndDESCBC = "1.2.840.113549.1.5.3"
    static let pbeWithSHA1AndDESCBC = "1.2.840.113549.1.5.10"
}

private enum DERTag {
    static let integer: UInt8 = 0x02
    static let octetString: UInt8 = 0x04
    static let objectIdentifier: UInt8 = 0x06
    static let sequence: UInt8 = 0x30

    static func explicit(_ number: UInt8) -> UInt8 {
        0xa0 | number
    }

    static func contextPrimitive(_ number: UInt8) -> UInt8 {
        0x80 | number
    }
}

/// Compares two digests without data-dependent early exit.
private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else {
        return false
    }
    var difference: UInt8 = 0
    for (left, right) in zip(lhs, rhs) {
        difference |= left ^ right
    }
    return difference == 0
}

private extension DERNode {
    /// Unwraps an explicitly tagged value and returns its single inner node.
    func explicitValue(expectedTag: UInt8? = nil) throws -> DERNode {
        var reader = DERReader(content)
        let inner = try reader.readNode(expectedTag: expectedTag)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("Explicit DER value contains extra data.")
        }
        return inner
    }
}

private extension DERReader {
    mutating func readInteger() throws -> Int {
        try integerValue(try readNode(expectedTag: DERTag.integer))
    }

    mutating func readObjectIdentifier() throws -> String {
        try objectIdentifierValue(try readNode(expectedTag: DERTag.objectIdentifier))
    }

    mutating func peekTag() throws -> UInt8 {
        try peekByte()
    }

    private func integerValue(_ node: DERNode) throws -> Int {
        guard !node.content.isEmpty else {
            throw RorkSignError.invalidSigningIdentity("DER integer is empty.")
        }
        guard node.content[0] & 0x80 == 0 else {
            throw RorkSignError.invalidSigningIdentity("Negative DER integers are not supported.")
        }

        var value = 0
        for byte in node.content {
            guard value <= (Int.max - Int(byte)) / 256 else {
                throw RorkSignError.invalidSigningIdentity("DER integer is too large.")
            }
            value = value * 256 + Int(byte)
        }
        return value
    }

    private func objectIdentifierValue(_ node: DERNode) throws -> String {
        guard let first = node.content.first else {
            throw RorkSignError.invalidSigningIdentity("DER object identifier is empty.")
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
                throw RorkSignError.invalidSigningIdentity("DER object identifier arc is too large.")
            }
            value = (value << 7) | Int(byte & 0x7f)
            hasContinuation = byte & 0x80 != 0
            if !hasContinuation {
                arcs.append(value)
                value = 0
            }
        }
        guard !hasContinuation else {
            throw RorkSignError.invalidSigningIdentity("DER object identifier is truncated.")
        }
        return arcs.map(String.init).joined(separator: ".")
    }
}
