import Foundation

/// Extracts signing certificates from detached CMS SignedData payloads.
///
/// Apple code signatures store identity-backed signatures in a BlobWrapper slot
/// whose payload is a detached CMS `SignedData` value. For local diagnostics we
/// only need the embedded certificate set and the SignerInfo issuer/serial
/// reference. This parser does not verify the CMS signature or validate trust;
/// it mirrors the rest of the package's inspection APIs by returning structural
/// metadata from the bytes already present in the Mach-O signature.
enum CMSCertificateInspector {
    /// Returns the signer certificate first, followed by the remaining embedded
    /// certificates in their CMS order.
    static func signingCertificates(in cmsPayload: Data) throws -> [Data] {
        do {
            return try parseSigningCertificates(in: cmsPayload)
        } catch let error as RorkSignError {
            throw error
        } catch {
            throw RorkSignError.cmsSigning("Embedded CMS certificate data is malformed.")
        }
    }

    /// Parses a CMS `ContentInfo` wrapping `signedData`.
    private static func parseSigningCertificates(in cmsPayload: Data) throws -> [Data] {
        var outerReader = DERReader(cmsPayload)
        let contentInfo = try outerReader.readNode(expectedTag: 0x30)
        guard outerReader.isAtEnd else {
            throw RorkSignError.cmsSigning("Embedded CMS has trailing data.")
        }

        var contentInfoReader = DERReader(contentInfo.content)
        let contentType = try contentInfoReader.readNode(expectedTag: 0x06)
        guard objectIdentifierValue(contentType) == OID.signedData else {
            throw RorkSignError.cmsSigning("Embedded CMS is not SignedData.")
        }

        let signedDataWrapper = try contentInfoReader.readNode(expectedTag: 0xa0)
        guard contentInfoReader.isAtEnd else {
            throw RorkSignError.cmsSigning("Embedded CMS ContentInfo has trailing fields.")
        }

        var wrapperReader = DERReader(signedDataWrapper.content)
        let signedData = try wrapperReader.readNode(expectedTag: 0x30)
        guard wrapperReader.isAtEnd else {
            throw RorkSignError.cmsSigning("Embedded CMS SignedData wrapper has trailing fields.")
        }

        let parsedSignedData = try parseSignedData(signedData)
        guard !parsedSignedData.certificates.isEmpty else {
            return []
        }
        guard let signerIdentifier = parsedSignedData.signerIdentifier else {
            return parsedSignedData.certificates
        }

        guard let signerIndex = parsedSignedData.certificates.firstIndex(where: { certificateDER in
            guard let info = try? CertificateInfo.parse(certificateDER) else {
                return false
            }
            return info.issuerDER == signerIdentifier.issuerDER
                && info.serialNumberDER == signerIdentifier.serialNumberDER
        }) else {
            return parsedSignedData.certificates
        }

        var certificates = parsedSignedData.certificates
        let signer = certificates.remove(at: signerIndex)
        certificates.insert(signer, at: 0)
        return certificates
    }

    /// Reads the certificate set and first SignerInfo identifier from SignedData.
    private static func parseSignedData(_ signedData: DERNode) throws -> ParsedSignedData {
        var reader = DERReader(signedData.content)
        _ = try reader.readNode(expectedTag: 0x02)
        _ = try reader.readNode(expectedTag: 0x31)
        _ = try reader.readNode(expectedTag: 0x30)

        var certificates: [Data] = []
        var signerInfos: DERNode?
        while !reader.isAtEnd {
            let tag = try reader.peekByte()
            switch tag {
            case 0xa0:
                certificates = try parseCertificateSet(try reader.readNode().content)
            case 0xa1:
                _ = try reader.readNode()
            case 0x31:
                signerInfos = try reader.readNode()
            default:
                throw RorkSignError.cmsSigning("Embedded CMS SignedData has an unexpected field.")
            }
        }

        return ParsedSignedData(
            certificates: certificates,
            signerIdentifier: try signerInfos.flatMap(parseFirstSignerIdentifier(in:))
        )
    }

    /// Reads the implicitly tagged CMS certificate set.
    private static func parseCertificateSet(_ data: Data) throws -> [Data] {
        var reader = DERReader(data)
        var certificates: [Data] = []
        while !reader.isAtEnd {
            let choice = try reader.readNode()
            guard choice.tag == 0x30 else {
                continue
            }
            _ = try CertificateInfo.parse(choice.fullDER)
            certificates.append(choice.fullDER)
        }
        return certificates
    }

    /// Extracts the issuer-and-serial SignerIdentifier from the first SignerInfo.
    private static func parseFirstSignerIdentifier(in signerInfos: DERNode) throws -> SignerIdentifier? {
        var setReader = DERReader(signerInfos.content)
        guard !setReader.isAtEnd else {
            return nil
        }

        let signerInfo = try setReader.readNode(expectedTag: 0x30)
        var signerReader = DERReader(signerInfo.content)
        _ = try signerReader.readNode(expectedTag: 0x02)
        let signerIdentifier = try signerReader.readNode()
        guard signerIdentifier.tag == 0x30 else {
            return nil
        }

        var identifierReader = DERReader(signerIdentifier.content)
        let issuer = try identifierReader.readNode(expectedTag: 0x30)
        let serial = try identifierReader.readNode(expectedTag: 0x02)
        return SignerIdentifier(
            issuerDER: issuer.fullDER,
            serialNumberDER: serial.fullDER
        )
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
}

private struct ParsedSignedData {
    let certificates: [Data]
    let signerIdentifier: SignerIdentifier?
}

private struct SignerIdentifier {
    let issuerDER: Data
    let serialNumberDER: Data
}

private enum OID {
    static let signedData = "1.2.840.113549.1.7.2"
}
