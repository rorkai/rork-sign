#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import CryptoExtras
import Foundation

/// Verifies detached CMS SignedData payloads used by Apple code signatures.
///
/// The verifier intentionally stays narrow: it checks the CMS structure emitted
/// by this package and common Apple-style code signatures, validates the
/// `messageDigest` signed attribute against caller-provided detached content,
/// and verifies the RSA or NIST EC ECDSA signature over the DER
/// signed-attributes set. Trust roots, OCSP, revocation, and certificate policy
/// remain separate concerns.
enum CMSVerifier {
    /// Verifies `cmsPayload` against detached `content` and returns the signer
    /// certificate first, followed by the remaining embedded certificates.
    static func verifyDetached(cmsPayload: Data, content: Data) throws -> [Data] {
        do {
            let signedData = try parseContentInfo(cmsPayload)
            guard let signerInfo = signedData.signerInfos.first else {
                throw RorkSignError.cmsSigning("Detached CMS has no SignerInfo.")
            }
            guard signerInfo.digestAlgorithmOID == OID.sha256 else {
                throw RorkSignError.cmsSigning(
                    "Detached CMS digest algorithm is not SHA-256."
                )
            }
            let attributes = try signedAttributes(in: signerInfo.signedAttributesContent)
            guard attributes.contentTypeOID == OID.data else {
                throw RorkSignError.cmsSigning("Detached CMS content type is not data.")
            }
            let expectedDigest = Data(SHA256.hash(data: content))
            guard constantTimeEqual(attributes.messageDigest, expectedDigest) else {
                throw RorkSignError.cmsSigning(
                    "Detached CMS messageDigest does not match content."
                )
            }

            let signerCertificate = try signingCertificate(
                for: signerInfo.signerIdentifier,
                certificates: signedData.certificates
            )
            let certificateInfo = try CertificateInfo.parse(signerCertificate)
            let signatureInput = derSet(signerInfo.signedAttributesContent)
            try verifySignature(
                signerInfo.signature,
                algorithmOID: signerInfo.signatureAlgorithmOID,
                certificateInfo: certificateInfo,
                signatureInput: signatureInput
            )

            var certificates = signedData.certificates
            if let index = certificates.firstIndex(of: signerCertificate) {
                certificates.remove(at: index)
            }
            return [signerCertificate] + certificates
        } catch let error as RorkSignError {
            throw error
        } catch {
            throw RorkSignError.cmsSigning("Detached CMS is malformed.")
        }
    }

    /// Verifies the SignerInfo signature using the embedded certificate key.
    private static func verifySignature(
        _ signatureBytes: Data,
        algorithmOID: String,
        certificateInfo: CertificateInfo,
        signatureInput: Data
    ) throws {
        switch algorithmOID {
        case OID.rsaEncryption:
            let publicKey = try _RSA.Signing.PublicKey(
                derRepresentation: certificateInfo.subjectPublicKeyInfoDER
            )
            let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureBytes)
            guard publicKey.isValidSignature(
                signature,
                for: SHA256.hash(data: signatureInput),
                padding: .insecurePKCS1v1_5
            ) else {
                throw RorkSignError.cmsSigning("Detached CMS RSA signature is invalid.")
            }
        case OID.ecdsaWithSHA256:
            try verifyECDSASignature(
                signatureBytes,
                certificateInfo: certificateInfo,
                signatureInput: signatureInput
            )
        default:
            throw RorkSignError.cmsSigning(
                "Detached CMS signature algorithm is not supported: \(algorithmOID)."
            )
        }
    }

    /// Verifies ECDSA-with-SHA256 CMS signatures for supported NIST curves.
    private static func verifyECDSASignature(
        _ signatureBytes: Data,
        certificateInfo: CertificateInfo,
        signatureInput: Data
    ) throws {
        let digest = SHA256.hash(data: signatureInput)

        if let publicKey = try? P256.Signing.PublicKey(
            derRepresentation: certificateInfo.subjectPublicKeyInfoDER
        ) {
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureBytes)
            guard publicKey.isValidSignature(signature, for: digest) else {
                throw RorkSignError.cmsSigning("Detached CMS ECDSA signature is invalid.")
            }
            return
        }

        if let publicKey = try? P384.Signing.PublicKey(
            derRepresentation: certificateInfo.subjectPublicKeyInfoDER
        ) {
            let signature = try P384.Signing.ECDSASignature(derRepresentation: signatureBytes)
            guard publicKey.isValidSignature(signature, for: digest) else {
                throw RorkSignError.cmsSigning("Detached CMS ECDSA signature is invalid.")
            }
            return
        }

        if let publicKey = try? P521.Signing.PublicKey(
            derRepresentation: certificateInfo.subjectPublicKeyInfoDER
        ) {
            let signature = try P521.Signing.ECDSASignature(derRepresentation: signatureBytes)
            guard publicKey.isValidSignature(signature, for: digest) else {
                throw RorkSignError.cmsSigning("Detached CMS ECDSA signature is invalid.")
            }
            return
        }

        throw RorkSignError.cmsSigning(
            "Detached CMS ECDSA public key is not supported: \(certificateInfo.keyAlgorithm)."
        )
    }

    /// Parses the outer CMS `ContentInfo` and returns its SignedData body.
    private static func parseContentInfo(_ cmsPayload: Data) throws -> ParsedSignedData {
        var outerReader = DERReader(cmsPayload)
        let contentInfo = try outerReader.readNode(expectedTag: DERTag.sequence)
        guard outerReader.isAtEnd else {
            throw RorkSignError.cmsSigning("Detached CMS has trailing data.")
        }

        var contentInfoReader = DERReader(contentInfo.content)
        let contentType = try contentInfoReader.readNode(expectedTag: DERTag.objectIdentifier)
        guard objectIdentifierValue(contentType) == OID.signedData else {
            throw RorkSignError.cmsSigning("Detached CMS is not SignedData.")
        }

        let signedDataWrapper = try contentInfoReader.readNode(expectedTag: DERTag.explicit(0))
        guard contentInfoReader.isAtEnd else {
            throw RorkSignError.cmsSigning("Detached CMS ContentInfo has trailing fields.")
        }

        var wrapperReader = DERReader(signedDataWrapper.content)
        let signedData = try wrapperReader.readNode(expectedTag: DERTag.sequence)
        guard wrapperReader.isAtEnd else {
            throw RorkSignError.cmsSigning("Detached CMS SignedData wrapper has trailing fields.")
        }
        return try parseSignedData(signedData)
    }

    /// Reads the certificate set and SignerInfo set from SignedData.
    private static func parseSignedData(_ signedData: DERNode) throws -> ParsedSignedData {
        var reader = DERReader(signedData.content)
        _ = try reader.readNode(expectedTag: DERTag.integer)
        _ = try reader.readNode(expectedTag: DERTag.set)
        let encapContentInfo = try reader.readNode(expectedTag: DERTag.sequence)
        try validateDetachedEncapContentInfo(encapContentInfo)

        var certificates: [Data] = []
        var signerInfos: [SignerInfo] = []
        while !reader.isAtEnd {
            switch try reader.peekByte() {
            case DERTag.explicit(0):
                certificates = try parseCertificateSet(try reader.readNode().content)
            case DERTag.explicit(1):
                _ = try reader.readNode()
            case DERTag.set:
                signerInfos = try parseSignerInfos(try reader.readNode())
            default:
                throw RorkSignError.cmsSigning("Detached CMS SignedData has an unexpected field.")
            }
        }

        return ParsedSignedData(
            certificates: certificates,
            signerInfos: signerInfos
        )
    }

    /// Detached code-signature CMS should name `id-data` without embedding the
    /// content bytes inside `encapContentInfo`.
    private static func validateDetachedEncapContentInfo(_ node: DERNode) throws {
        var reader = DERReader(node.content)
        let contentType = try reader.readNode(expectedTag: DERTag.objectIdentifier)
        guard objectIdentifierValue(contentType) == OID.data else {
            throw RorkSignError.cmsSigning("Detached CMS encapContentInfo is not data.")
        }
        guard reader.isAtEnd else {
            throw RorkSignError.cmsSigning("Detached CMS unexpectedly embeds content.")
        }
    }

    /// Reads the implicitly tagged CMS certificate set.
    private static func parseCertificateSet(_ data: Data) throws -> [Data] {
        var reader = DERReader(data)
        var certificates: [Data] = []
        while !reader.isAtEnd {
            let choice = try reader.readNode()
            guard choice.tag == DERTag.sequence else {
                continue
            }
            _ = try CertificateInfo.parse(choice.fullDER)
            certificates.append(choice.fullDER)
        }
        return certificates
    }

    /// Reads every SignerInfo in the CMS signerInfos SET.
    private static func parseSignerInfos(_ signerInfos: DERNode) throws -> [SignerInfo] {
        var reader = DERReader(signerInfos.content)
        var result: [SignerInfo] = []
        while !reader.isAtEnd {
            result.append(try parseSignerInfo(try reader.readNode(expectedTag: DERTag.sequence)))
        }
        return result
    }

    /// Parses one SignerInfo using issuer-and-serial SignerIdentifier.
    private static func parseSignerInfo(_ signerInfo: DERNode) throws -> SignerInfo {
        var reader = DERReader(signerInfo.content)
        _ = try reader.readNode(expectedTag: DERTag.integer)
        let signerIdentifier = try parseSignerIdentifier(try reader.readNode())
        let digestAlgorithmOID = try parseAlgorithmIdentifier(
            try reader.readNode(expectedTag: DERTag.sequence)
        )
        let signedAttributes = try reader.readNode(expectedTag: DERTag.explicit(0))
        let signatureAlgorithmOID = try parseAlgorithmIdentifier(
            try reader.readNode(expectedTag: DERTag.sequence)
        )
        let signature = try reader.readNode(expectedTag: DERTag.octetString).content
        if !reader.isAtEnd {
            _ = try reader.readNode()
        }
        guard reader.isAtEnd else {
            throw RorkSignError.cmsSigning("Detached CMS SignerInfo has trailing fields.")
        }

        return SignerInfo(
            signerIdentifier: signerIdentifier,
            digestAlgorithmOID: digestAlgorithmOID,
            signatureAlgorithmOID: signatureAlgorithmOID,
            signedAttributesContent: signedAttributes.content,
            signature: signature
        )
    }

    /// Reads issuer-and-serial SignerIdentifier.
    private static func parseSignerIdentifier(_ signerIdentifier: DERNode) throws -> SignerIdentifier {
        guard signerIdentifier.tag == DERTag.sequence else {
            throw RorkSignError.cmsSigning("Detached CMS SignerIdentifier is not issuer-and-serial.")
        }
        var reader = DERReader(signerIdentifier.content)
        let issuer = try reader.readNode(expectedTag: DERTag.sequence)
        let serial = try reader.readNode(expectedTag: DERTag.integer)
        guard reader.isAtEnd else {
            throw RorkSignError.cmsSigning("Detached CMS SignerIdentifier has trailing fields.")
        }
        return SignerIdentifier(
            issuerDER: issuer.fullDER,
            serialNumberDER: serial.fullDER
        )
    }

    /// Returns the object identifier from an AlgorithmIdentifier sequence.
    private static func parseAlgorithmIdentifier(_ node: DERNode) throws -> String {
        var reader = DERReader(node.content)
        let oid = try reader.readNode(expectedTag: DERTag.objectIdentifier)
        _ = reader.isAtEnd ? nil : try reader.readNode()
        guard reader.isAtEnd else {
            throw RorkSignError.cmsSigning("Detached CMS AlgorithmIdentifier has trailing fields.")
        }
        guard let value = objectIdentifierValue(oid) else {
            throw RorkSignError.cmsSigning("Detached CMS AlgorithmIdentifier OID is malformed.")
        }
        return value
    }

    /// Reads the CMS signed attributes needed for detached verification.
    private static func signedAttributes(in data: Data) throws -> SignedAttributes {
        var reader = DERReader(data)
        var contentTypeOID: String?
        var messageDigest: Data?
        while !reader.isAtEnd {
            let attribute = try reader.readNode(expectedTag: DERTag.sequence)
            var attributeReader = DERReader(attribute.content)
            let oidNode = try attributeReader.readNode(expectedTag: DERTag.objectIdentifier)
            let values = try attributeReader.readNode(expectedTag: DERTag.set)
            guard attributeReader.isAtEnd else {
                throw RorkSignError.cmsSigning("Detached CMS signed attribute has trailing fields.")
            }
            guard let oid = objectIdentifierValue(oidNode) else {
                throw RorkSignError.cmsSigning("Detached CMS signed attribute OID is malformed.")
            }
            switch oid {
            case OID.contentType:
                contentTypeOID = try singleObjectIdentifierValue(in: values)
            case OID.messageDigest:
                messageDigest = try singleOctetStringValue(in: values)
            default:
                continue
            }
        }

        guard let contentTypeOID else {
            throw RorkSignError.cmsSigning("Detached CMS has no contentType signed attribute.")
        }
        guard let messageDigest else {
            throw RorkSignError.cmsSigning("Detached CMS has no messageDigest signed attribute.")
        }
        return SignedAttributes(
            contentTypeOID: contentTypeOID,
            messageDigest: messageDigest
        )
    }

    private static func singleObjectIdentifierValue(in set: DERNode) throws -> String {
        var reader = DERReader(set.content)
        let oid = try reader.readNode(expectedTag: DERTag.objectIdentifier)
        guard reader.isAtEnd, let value = objectIdentifierValue(oid) else {
            throw RorkSignError.cmsSigning("Detached CMS contentType attribute is malformed.")
        }
        return value
    }

    private static func singleOctetStringValue(in set: DERNode) throws -> Data {
        var reader = DERReader(set.content)
        let value = try reader.readNode(expectedTag: DERTag.octetString)
        guard reader.isAtEnd else {
            throw RorkSignError.cmsSigning("Detached CMS messageDigest attribute is malformed.")
        }
        return value.content
    }

    /// Selects the certificate referenced by SignerInfo.
    private static func signingCertificate(
        for signerIdentifier: SignerIdentifier,
        certificates: [Data]
    ) throws -> Data {
        guard let certificate = certificates.first(where: { certificateDER in
            guard let info = try? CertificateInfo.parse(certificateDER) else {
                return false
            }
            return info.issuerDER == signerIdentifier.issuerDER
                && info.serialNumberDER == signerIdentifier.serialNumberDER
        }) else {
            throw RorkSignError.cmsSigning("Detached CMS signer certificate is missing.")
        }
        return certificate
    }

    /// Encodes the SignerInfo signed-attributes content as a DER SET.
    private static func derSet(_ content: Data) -> Data {
        Data([DERTag.set]) + derLength(content.count) + content
    }

    private static func derLength(_ length: Int) -> Data {
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

    /// Decodes a DER object identifier into dotted-decimal form.
    private static func objectIdentifierValue(_ node: DERNode) -> String? {
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

    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) {
            difference |= left ^ right
        }
        return difference == 0
    }
}

private struct ParsedSignedData {
    let certificates: [Data]
    let signerInfos: [SignerInfo]
}

private struct SignerInfo {
    let signerIdentifier: SignerIdentifier
    let digestAlgorithmOID: String
    let signatureAlgorithmOID: String
    let signedAttributesContent: Data
    let signature: Data
}

private struct SignerIdentifier {
    let issuerDER: Data
    let serialNumberDER: Data
}

private struct SignedAttributes {
    let contentTypeOID: String
    let messageDigest: Data
}

private enum DERTag {
    static let integer: UInt8 = 0x02
    static let octetString: UInt8 = 0x04
    static let objectIdentifier: UInt8 = 0x06
    static let sequence: UInt8 = 0x30
    static let set: UInt8 = 0x31

    static func explicit(_ tagNumber: UInt8) -> UInt8 {
        0xa0 | tagNumber
    }
}

private enum OID {
    static let data = "1.2.840.113549.1.7.1"
    static let signedData = "1.2.840.113549.1.7.2"
    static let contentType = "1.2.840.113549.1.9.3"
    static let messageDigest = "1.2.840.113549.1.9.4"
    static let rsaEncryption = "1.2.840.113549.1.1.1"
    static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
    static let sha256 = "2.16.840.1.101.3.4.2.1"
}
