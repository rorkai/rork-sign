#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
@testable import RorkSign

/// A generated identity keeps portable tests independent of host credential
/// stores and command-line certificate tools.
struct SyntheticSigningFixture {
    let directory: URL
    let identity: SigningIdentity
    let certificateURL: URL
    let privateKeyURL: URL

    init() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true
            )
            let privateKey = try RSAPrivateSigningKey()
            let certificateDER = try syntheticCertificate(
                publicKeyDER: privateKey.publicKeyDERRepresentation,
                privateKey: privateKey
            )
            let privateKeyDER = privateKey.pkcs8DERRepresentation
            let certificateURL = directory.appendingPathComponent(
                "certificate.der"
            )
            let privateKeyURL = directory.appendingPathComponent(
                "private-key.der"
            )
            try certificateDER.write(to: certificateURL)
            try privateKeyDER.write(to: privateKeyURL)

            self.directory = directory
            self.identity = try SigningIdentity(
                certificateDER: certificateDER,
                privateKeyDER: privateKeyDER
            )
            self.certificateURL = certificateURL
            self.privateKeyURL = privateKeyURL
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}

/// The certificate carries only the X.509 fields consumed by signing tests. Its
/// self-signature remains valid so the fixture can also cross verification paths.
private func syntheticCertificate(
    publicKeyDER: Data,
    privateKey: RSAPrivateSigningKey
) throws -> Data {
    let signatureAlgorithm = DEREncoding.sequence([
        DEREncoding.objectIdentifier("1.2.840.113549.1.1.11"),
        DEREncoding.null(),
    ])
    let name = DEREncoding.sequence([
        DEREncoding.set([
            DEREncoding.sequence([
                DEREncoding.objectIdentifier("2.5.4.3"),
                DEREncoding.utf8String("Portable Test Identity"),
            ])
        ])
    ])
    let validity = DEREncoding.sequence([
        DEREncoding.tagged(0x17, Data("250101000000Z".utf8)),
        DEREncoding.tagged(0x17, Data("490101000000Z".utf8)),
    ])
    let certificateBody = DEREncoding.sequence([
        DEREncoding.contextSpecificConstructed(
            0,
            content: DEREncoding.integer(2)
        ),
        DEREncoding.integer(1),
        signatureAlgorithm,
        name,
        validity,
        name,
        publicKeyDER,
    ])
    let signature = try privateKey.signature(
        for: SHA256.hash(data: certificateBody)
    )
    return DEREncoding.sequence([
        certificateBody,
        signatureAlgorithm,
        DEREncoding.bitString(signature),
    ])
}
