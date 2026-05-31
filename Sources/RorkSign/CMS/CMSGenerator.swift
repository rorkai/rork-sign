import Crypto
import Foundation

/// Builds detached CMS SignedData blobs for Apple code signatures.
///
/// The CMS payload signs the CodeDirectory via signed attributes. In addition
/// to the generic CMS `contentType` and `messageDigest` attributes, Apple code
/// signatures carry private cdhash attributes under `1.2.840.113635.100.9.*`.
/// Those attributes are not needed by OpenSSL to verify the CMS, but they are
/// part of the shape Apple tooling emits and consumers expect when inspecting
/// signed Mach-O files.
enum CMSGenerator {
    /// Generates a detached CMS SignedData payload over `content`.
    static func signDetached(
        content: Data,
        alternateCodeDirectory: Data = Data(),
        identity: SigningIdentity
    ) throws -> Data {
        guard !content.isEmpty else {
            throw RorkSignError.cmsSigning("CMS signing needs non-empty content.")
        }

        let signedAttributes = signedAttributes(
            for: content,
            alternateCodeDirectory: alternateCodeDirectory
        )
        let signatureInput = DER.set(signedAttributes)
        let signature = try identity.privateKey.signature(for: SHA256.hash(data: signatureInput))
        let certificates = cmsCertificates(for: identity)
        let signedData = try signedData(
            certificatesDER: certificates,
            certificateInfo: identity.certificateInfo,
            signedAttributes: signedAttributes,
            signature: signature,
            signatureAlgorithm: identity.privateKey.cmsSignatureAlgorithm
        )

        return DER.sequence(
            DER.objectIdentifier(OID.signedData)
                + DER.explicit(0, signedData)
        )
    }

    /// Returns the CMS certificate set in leaf-to-root order.
    ///
    /// Caller-supplied chain material wins. If a common Apple development
    /// credential only carries the leaf certificate, add the matching public
    /// WWDR issuer chain so iOS code-signing validation can build the same
    /// certificate path that Apple tooling emits.
    private static func cmsCertificates(for identity: SigningIdentity) -> [Data] {
        let suppliedCertificates = [identity.certificateDER] + identity.additionalCertificatesDER
        let appleChain = AppleCertificateChain.additionalCertificates(
            for: identity.certificateInfo,
            existing: suppliedCertificates
        )
        return suppliedCertificates + appleChain
    }

    /// CMS signed attributes signed by RSA.
    ///
    /// `messageDigest` remains the normative CMS binding to the detached
    /// primary CodeDirectory content. The Apple-private attributes describe the
    /// cdhashes used by code-signing tools: a plist of 20-byte cdhash values, plus
    /// a DER sequence naming SHA-256 and the complete modern digest. When an
    /// alternate CodeDirectory exists, that SHA-256 digest belongs to the
    /// alternate directory while the CMS still signs the primary directory.
    private static func signedAttributes(for content: Data, alternateCodeDirectory: Data) -> [Data] {
        [
            attribute(
                OID.contentType,
                values: [DER.objectIdentifier(OID.data)]
            ),
            attribute(
                OID.messageDigest,
                values: [DER.octetString(Data(SHA256.hash(data: content)))]
            ),
            attribute(
                OID.appleCDHashesPlist,
                values: [DER.octetString(cdHashesPlist(
                    primaryCodeDirectory: content,
                    alternateCodeDirectory: alternateCodeDirectory
                ))]
            ),
            attribute(
                OID.appleCDHashSequence,
                values: [cdHashSequence(
                    primaryCodeDirectory: content,
                    alternateCodeDirectory: alternateCodeDirectory
                )]
            ),
        ]
    }

    /// Builds Apple's XML plist attribute containing the relevant cdhashes.
    ///
    /// When a SHA-256 alternate CodeDirectory is present, Apple records both the
    /// primary SHA-1 cdhash and the alternate SHA-256 cdhash prefix. Without an
    /// alternate directory, the single cdhash is the SHA-256 digest prefix of the
    /// signed primary content.
    private static func cdHashesPlist(primaryCodeDirectory: Data, alternateCodeDirectory: Data) -> Data {
        let cdHashes: [Data]
        if alternateCodeDirectory.isEmpty {
            cdHashes = [Data(SHA256.hash(data: primaryCodeDirectory)).prefixData(20)]
        } else {
            cdHashes = [
                Data(Insecure.SHA1.hash(data: primaryCodeDirectory)),
                Data(SHA256.hash(data: alternateCodeDirectory)).prefixData(20),
            ]
        }
        let entries = cdHashes
            .map { "\t\t<data>\n\t\t\($0.base64EncodedString())\n\t\t</data>" }
            .joined(separator: "\n")
        return Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
        \t<key>cdhashes</key>
        \t<array>
        \(entries)
        \t</array>
        </dict>
        </plist>
        """.utf8)
    }

    /// Builds Apple's structured SHA-256 cdhash attribute value.
    private static func cdHashSequence(primaryCodeDirectory: Data, alternateCodeDirectory: Data) -> Data {
        let digestInput = alternateCodeDirectory.isEmpty ? primaryCodeDirectory : alternateCodeDirectory
        return DER.sequence(
            DER.objectIdentifier(OID.sha256)
                + DER.octetString(Data(SHA256.hash(data: digestInput)))
        )
    }

    private static func signedData(
        certificatesDER: [Data],
        certificateInfo: CertificateInfo,
        signedAttributes: [Data],
        signature: Data,
        signatureAlgorithm: CMSSignatureAlgorithm
    ) throws -> Data {
        DER.sequence(
            DER.integer(1)
                + DER.set([algorithmIdentifier(OID.sha256)])
                + DER.sequence(DER.objectIdentifier(OID.data))
                + DER.implicitSet(0, certificatesDER)
                + DER.set([
                    signerInfo(
                        certificateInfo: certificateInfo,
                        signedAttributes: signedAttributes,
                        signature: signature,
                        signatureAlgorithm: signatureAlgorithm
                    ),
                ])
        )
    }

    private static func signerInfo(
        certificateInfo: CertificateInfo,
        signedAttributes: [Data],
        signature: Data,
        signatureAlgorithm: CMSSignatureAlgorithm
    ) -> Data {
        let signedAttributeSet = DER.set(signedAttributes)
        let signedAttributeContent = DER.contentBytes(of: signedAttributeSet)

        return DER.sequence(
            DER.integer(1)
                + DER.sequence(certificateInfo.issuerDER + certificateInfo.serialNumberDER)
                + algorithmIdentifier(OID.sha256)
                + DER.implicit(0, signedAttributeContent)
                + algorithmIdentifier(
                    signatureAlgorithm.oid,
                    includeNullParameters: signatureAlgorithm.includesNullParameters
                )
                + DER.octetString(signature)
        )
    }

    private static func algorithmIdentifier(_ oid: String, includeNullParameters: Bool = true) -> Data {
        DER.sequence(DER.objectIdentifier(oid) + (includeNullParameters ? DER.null() : Data()))
    }

    private static func attribute(_ oid: String, values: [Data]) -> Data {
        DER.sequence(DER.objectIdentifier(oid) + DER.set(values))
    }
}

private enum OID {
    static let data = "1.2.840.113549.1.7.1"
    static let signedData = "1.2.840.113549.1.7.2"
    static let contentType = "1.2.840.113549.1.9.3"
    static let messageDigest = "1.2.840.113549.1.9.4"
    static let sha256 = "2.16.840.1.101.3.4.2.1"
    static let appleCDHashesPlist = "1.2.840.113635.100.9.1"
    static let appleCDHashSequence = "1.2.840.113635.100.9.2"
}

/// Minimal DER writer for CMS.
private enum DER {
    static func sequence(_ content: Data) -> Data {
        tagged(0x30, content)
    }

    static func set(_ elements: [Data]) -> Data {
        tagged(0x31, elements.sortedLexicographically().reduce(Data(), +))
    }

    static func objectIdentifier(_ oid: String) -> Data {
        let components = oid.split(separator: ".").compactMap { Int($0) }
        precondition(components.count >= 2)
        var content = Data([UInt8(components[0] * 40 + components[1])])
        for component in components.dropFirst(2) {
            content.append(contentsOf: base128(component))
        }
        return tagged(0x06, content)
    }

    static func integer(_ value: Int) -> Data {
        precondition(value >= 0)
        var remaining = value
        var bytes: [UInt8] = []
        repeat {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        } while remaining > 0
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        return tagged(0x02, Data(bytes))
    }

    static func octetString(_ content: Data) -> Data {
        tagged(0x04, content)
    }

    static func null() -> Data {
        Data([0x05, 0x00])
    }

    static func explicit(_ tagNumber: UInt8, _ encodedValue: Data) -> Data {
        tagged(0xa0 | tagNumber, encodedValue)
    }

    static func `implicit`(_ tagNumber: UInt8, _ content: Data) -> Data {
        tagged(0xa0 | tagNumber, content)
    }

    static func implicitSet(_ tagNumber: UInt8, _ elements: [Data]) -> Data {
        tagged(0xa0 | tagNumber, elements.sortedLexicographically().reduce(Data(), +))
    }

    static func contentBytes(of encodedValue: Data) -> Data {
        var reader = DERReader(encodedValue)
        // The value is produced locally, so failure here indicates a programmer
        // error rather than malformed user input.
        return (try? reader.readNode().content) ?? Data()
    }

    private static func tagged(_ tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + length(content.count) + content
    }

    private static func length(_ length: Int) -> Data {
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

    private static func base128(_ value: Int) -> [UInt8] {
        var remaining = value
        var bytes = [UInt8(remaining & 0x7f)]
        remaining >>= 7
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0x7f) | 0x80, at: 0)
            remaining >>= 7
        }
        return bytes
    }
}

private extension Array where Element == Data {
    func sortedLexicographically() -> [Data] {
        sorted { lhs, rhs in
            lhs.lexicographicallyPrecedes(rhs)
        }
    }
}

private extension Data {
    func prefixData(_ count: Int) -> Data {
        Data(prefix(count))
    }
}
