#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// Builds deterministic OCSP requests for X.509 signing certificates.
///
/// This type intentionally stops at request construction. Sending the request,
/// enforcing responder freshness, and making a trust decision require network
/// and policy choices that should remain explicit at the call site. The DER
/// shape matches OpenSSL's `OCSP_cert_to_id(EVP_sha1(), leaf, issuer)` output
/// without a nonce, which is the request form used by the ZSign-compatible
/// certificate-check flow.
enum OCSPRequestBuilder {
    /// Creates an OCSP request for `certificateDER` using `issuerCertificateDER`.
    static func makeRequest(
        certificateDER: Data,
        issuerCertificateDER: Data
    ) throws -> OCSPRequest {
        let certificate = try CertificateInfo.parse(certificateDER)
        let issuer = try CertificateInfo.parse(issuerCertificateDER)
        let issuerPublicKey = try subjectPublicKeyBytes(in: issuer.subjectPublicKeyInfoDER)
        let issuerNameHash = Data(Insecure.SHA1.hash(data: issuer.subjectDER))
        let issuerKeyHash = Data(Insecure.SHA1.hash(data: issuerPublicKey))
        let der = requestDER(
            serialNumberDER: certificate.serialNumberDER,
            issuerNameHash: issuerNameHash,
            issuerKeyHash: issuerKeyHash
        )

        return OCSPRequest(
            derRepresentation: der,
            responderURL: responderURL(for: certificate, issuer: issuer),
            issuerNameHash: issuerNameHash,
            issuerKeyHash: issuerKeyHash,
            serialNumberHex: certificate.serialNumberHex
        )
    }

    /// Returns the responder URL advertised by AIA, falling back to Apple's
    /// WWDR OCSP paths when the issuer name identifies one of those roots.
    private static func responderURL(for certificate: CertificateInfo, issuer: CertificateInfo) -> URL? {
        for candidate in certificate.ocspResponderURLs {
            if let url = URL(string: candidate.trimmingCharacters(in: .whitespacesAndNewlines)) {
                return url
            }
        }

        let issuerCommonName = issuer.subjectCommonName
        let path: String?
        if issuerCommonName.contains("G6") {
            path = "/ocsp03-wwdrg6"
        } else if issuerCommonName.contains("G3") {
            path = "/ocsp03-wwdrg3"
        } else if issuerCommonName.contains("G2") {
            path = "/ocsp03-wwdrg2"
        } else if issuerCommonName.contains("Apple") || issuerCommonName.contains("Worldwide Developer Relations") {
            path = "/ocsp03-wwdr01"
        } else {
            path = nil
        }

        guard let path else {
            return nil
        }
        return URL(string: "http://ocsp.apple.com\(path)")
    }

    /// Extracts the raw SubjectPublicKey BIT STRING bytes used by OCSP CertID.
    private static func subjectPublicKeyBytes(in subjectPublicKeyInfoDER: Data) throws -> Data {
        var reader = DERReader(subjectPublicKeyInfoDER)
        let subjectPublicKeyInfo = try reader.readNode(expectedTag: 0x30)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("Issuer SubjectPublicKeyInfo has trailing data.")
        }

        var spki = DERReader(subjectPublicKeyInfo.content)
        _ = try spki.readNode(expectedTag: 0x30)
        let publicKey = try spki.readNode(expectedTag: 0x03)
        guard spki.isAtEnd,
              publicKey.content.first == 0 else {
            throw RorkSignError.invalidSigningIdentity("Issuer SubjectPublicKeyInfo BIT STRING is malformed.")
        }
        return Data(publicKey.content.dropFirst())
    }

    /// Builds the DER OCSPRequest wrapper with one SHA-1 CertID.
    private static func requestDER(
        serialNumberDER: Data,
        issuerNameHash: Data,
        issuerKeyHash: Data
    ) -> Data {
        let certID = DER.sequence(
            algorithmIdentifier(OID.sha1)
                + DER.octetString(issuerNameHash)
                + DER.octetString(issuerKeyHash)
                + serialNumberDER
        )
        let request = DER.sequence(certID)
        let requestList = DER.sequence(request)
        let tbsRequest = DER.sequence(requestList)
        return DER.sequence(tbsRequest)
    }

    /// OCSP CertID hash AlgorithmIdentifier.
    private static func algorithmIdentifier(_ oid: String) -> Data {
        DER.sequence(DER.objectIdentifier(oid) + DER.null())
    }
}

private enum OID {
    static let sha1 = "1.3.14.3.2.26"
}

/// Minimal DER writer for OCSP request construction.
private enum DER {
    static func sequence(_ content: Data) -> Data {
        tagged(0x30, content)
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

    static func octetString(_ content: Data) -> Data {
        tagged(0x04, content)
    }

    static func null() -> Data {
        Data([0x05, 0x00])
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
