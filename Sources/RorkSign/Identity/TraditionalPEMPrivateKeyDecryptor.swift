#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import CryptoExtras
import Foundation

/// Decrypts OpenSSL's traditional encrypted RSA private-key PEM format.
///
/// This is the pre-PKCS#8 shape that looks like `BEGIN RSA PRIVATE KEY` with
/// `Proc-Type` and `DEK-Info` headers. OpenSSL derives the symmetric key with
/// `EVP_BytesToKey` using MD5 and the first eight IV bytes as salt, then
/// decrypts the DER `RSAPrivateKey` payload with the cipher named by
/// `DEK-Info`.
enum TraditionalPEMPrivateKeyDecryptor {
    /// Returns decrypted RSA private-key DER when `pem` is an encrypted
    /// traditional PEM document, or `nil` when it is another PEM type.
    static func decrypt(_ pem: String, password: String) throws -> Data? {
        let lines = pem
            .split(whereSeparator: \.isNewline)
            .map(String.init)
        guard let beginIndex = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN ") && $0.hasSuffix("-----") }),
              let endIndex = lines[(beginIndex + 1)...].firstIndex(where: { $0.hasPrefix("-----END ") && $0.hasSuffix("-----") }) else {
            return nil
        }

        let type = String(lines[beginIndex].dropFirst("-----BEGIN ".count).dropLast("-----".count))
        let endType = String(lines[endIndex].dropFirst("-----END ".count).dropLast("-----".count))
        guard type == "RSA PRIVATE KEY", endType == type else {
            return nil
        }

        let body = Array(lines[(beginIndex + 1)..<endIndex])
        let parsed = parseHeadersAndPayload(body)
        guard parsed.headers["Proc-Type"]?.contains("ENCRYPTED") == true
                || parsed.headers["DEK-Info"] != nil else {
            return nil
        }
        guard !password.isEmpty else {
            throw RorkSignError.invalidSigningIdentity("Encrypted RSA private key requires a password.")
        }
        guard let dekInfo = parsed.headers["DEK-Info"] else {
            throw RorkSignError.invalidSigningIdentity("Encrypted RSA private key is missing DEK-Info.")
        }

        let encryption = try LegacyPEMEncryption(dekInfo: dekInfo)
        guard let ciphertext = Data(base64Encoded: parsed.payload.joined()) else {
            throw RorkSignError.invalidSigningIdentity("Encrypted RSA private key payload is not valid base64.")
        }
        return try encryption.decrypt(ciphertext, password: Data(password.utf8))
    }

    /// Splits PEM body lines into RFC 1421-style headers and base64 payload.
    private static func parseHeadersAndPayload(_ body: [String]) -> (headers: [String: String], payload: [String]) {
        var headers: [String: String] = [:]
        var payload: [String] = []
        var isReadingPayload = false

        for line in body {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                isReadingPayload = true
                continue
            }

            if !isReadingPayload,
               let separator = trimmed.firstIndex(of: ":") {
                let name = String(trimmed[..<separator])
                let value = trimmed[trimmed.index(after: separator)...]
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                headers[name] = value
                continue
            }

            isReadingPayload = true
            payload.append(trimmed)
        }

        return (headers, payload)
    }
}

/// Cipher parameters from a traditional PEM `DEK-Info` header.
private struct LegacyPEMEncryption {
    let algorithm: Algorithm
    let iv: Data

    init(dekInfo: String) throws {
        let parts = dekInfo
            .split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard parts.count == 2 else {
            throw RorkSignError.invalidSigningIdentity("Encrypted RSA private key DEK-Info is malformed.")
        }
        self.algorithm = try Algorithm(name: parts[0])
        self.iv = try Data(hexString: parts[1])
        guard iv.count == algorithm.ivByteCount else {
            throw RorkSignError.invalidSigningIdentity("Encrypted RSA private key IV has an invalid size.")
        }
    }

    func decrypt(_ ciphertext: Data, password: Data) throws -> Data {
        let key = Self.evpBytesToKey(
            password: password,
            salt: Data(iv.prefix(8)),
            keyByteCount: algorithm.keyByteCount
        )

        do {
            switch algorithm {
            case .aesCBC:
                return try AES._CBC.decrypt(
                    ciphertext,
                    using: SymmetricKey(data: key),
                    iv: AES._CBC.IV(ivBytes: iv)
                )
            case .tripleDES3KeyCBC:
                return try TripleDESCBC.decrypt(ciphertext, key: key, iv: iv)
            case .desCBC:
                return try DESCBC.decrypt(ciphertext, key: key, iv: iv)
            }
        } catch {
            throw RorkSignError.invalidSigningIdentity("Encrypted RSA private key decryption failed.")
        }
    }

    /// OpenSSL `EVP_BytesToKey` with MD5 and one iteration.
    private static func evpBytesToKey(password: Data, salt: Data, keyByteCount: Int) -> Data {
        var output = Data()
        var previous = Data()
        while output.count < keyByteCount {
            let digestInput = previous + password + salt
            previous = Data(Insecure.MD5.hash(data: digestInput))
            output.append(previous)
        }
        return Data(output.prefix(keyByteCount))
    }

        enum Algorithm {
        case aesCBC(keyByteCount: Int)
        case tripleDES3KeyCBC
        case desCBC

        init(name: String) throws {
            switch name.uppercased() {
            case "AES-128-CBC":
                self = .aesCBC(keyByteCount: 16)
            case "AES-192-CBC":
                self = .aesCBC(keyByteCount: 24)
            case "AES-256-CBC":
                self = .aesCBC(keyByteCount: 32)
            case "DES-EDE3-CBC":
                self = .tripleDES3KeyCBC
            case "DES-CBC":
                self = .desCBC
            default:
                throw RorkSignError.unsupported("Encrypted RSA private key cipher is not supported: \(name).")
            }
        }

        var keyByteCount: Int {
            switch self {
            case .aesCBC(let keyByteCount):
                return keyByteCount
            case .tripleDES3KeyCBC:
                return 24
            case .desCBC:
                return 8
            }
        }

        var ivByteCount: Int {
            switch self {
            case .aesCBC:
                return 16
            case .tripleDES3KeyCBC:
                return 8
            case .desCBC:
                return 8
            }
        }
    }
}

private extension Data {
    /// Decodes an even-length hexadecimal string.
    init(hexString: String) throws {
        guard hexString.count.isMultiple(of: 2) else {
            throw RorkSignError.invalidSigningIdentity("Hex string has an odd number of characters.")
        }

        var bytes = Data()
        bytes.reserveCapacity(hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else {
                throw RorkSignError.invalidSigningIdentity("Hex string contains non-hex characters.")
            }
            bytes.append(byte)
            index = next
        }
        self = bytes
    }
}
