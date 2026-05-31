import Foundation

/// Parses RFC 6960 OCSP response DER.
///
/// The parser focuses on the data a signer or certificate-health preflight
/// needs locally: top-level response status, BasicOCSPResponse production time,
/// and each `SingleResponse` certificate status. It deliberately does not make
/// network, trust-anchor, or responder-authorization decisions.
enum OCSPResponseParser {
    /// Parses one DER-encoded `OCSPResponse`.
    static func parse(_ data: Data) throws -> OCSPResponseReport {
        var reader = DERReader(data)
        let root = try reader.readNode(expectedTag: DERTag.sequence)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("OCSP response has trailing data.")
        }

        var response = DERReader(root.content)
        let status = try responseStatus(from: try response.readNode(expectedTag: DERTag.enumerated))
        guard status == .successful else {
            guard response.isAtEnd else {
                throw RorkSignError.invalidSigningIdentity("Non-successful OCSP response contains unexpected body.")
            }
            return OCSPResponseReport(
                responseStatus: status,
                responseTypeOID: nil,
                producedAt: nil,
                singleResponses: [],
                signedResponseData: nil,
                signatureAlgorithmOID: nil,
                signature: nil,
                responderCertificatesDER: []
            )
        }

        let responseBytes = try response.readNode(expectedTag: DERTag.explicit(0))
        guard response.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("OCSP response has extra fields.")
        }

        let parsed = try parseResponseBytes(responseBytes)
        return OCSPResponseReport(
            responseStatus: status,
            responseTypeOID: parsed.responseTypeOID,
            producedAt: parsed.producedAt,
            singleResponses: parsed.singleResponses,
            signedResponseData: parsed.signedResponseData,
            signatureAlgorithmOID: parsed.signatureAlgorithmOID,
            signature: parsed.signature,
            responderCertificatesDER: parsed.responderCertificatesDER
        )
    }

    /// Parses the explicit `ResponseBytes` wrapper.
    private static func parseResponseBytes(_ node: DERNode) throws -> ParsedResponseBytes {
        let responseBytes = try node.explicitValue(expectedTag: DERTag.sequence)
        var reader = DERReader(responseBytes.content)
        let responseTypeOID = try reader.readObjectIdentifier()
        guard responseTypeOID == OID.basicOCSPResponse else {
            throw RorkSignError.unsupported("OCSP response type is not BasicOCSPResponse: \(responseTypeOID).")
        }
        let responseOctets = try reader.readNode(expectedTag: DERTag.octetString)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("OCSP ResponseBytes has extra fields.")
        }

        let basic = try parseBasicOCSPResponse(responseOctets.content)
        return ParsedResponseBytes(
            responseTypeOID: responseTypeOID,
            producedAt: basic.producedAt,
            singleResponses: basic.singleResponses,
            signedResponseData: basic.signedResponseData,
            signatureAlgorithmOID: basic.signatureAlgorithmOID,
            signature: basic.signature,
            responderCertificatesDER: basic.responderCertificatesDER
        )
    }

    /// Parses `BasicOCSPResponse` and returns its signed response data.
    private static func parseBasicOCSPResponse(_ data: Data) throws -> ParsedBasicOCSPResponse {
        var reader = DERReader(data)
        let root = try reader.readNode(expectedTag: DERTag.sequence)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("BasicOCSPResponse has trailing data.")
        }

        var basic = DERReader(root.content)
        let responseDataNode = try basic.readNode(expectedTag: DERTag.sequence)
        let responseData = try parseResponseData(responseDataNode)
        let signatureAlgorithmOID = try parseAlgorithmIdentifier(try basic.readNode(expectedTag: DERTag.sequence))
        let signature = try signatureBytes(from: try basic.readNode(expectedTag: DERTag.bitString))
        var responderCertificatesDER: [Data] = []
        if !basic.isAtEnd {
            responderCertificatesDER = try parseResponderCertificates(
                try basic.readNode(expectedTag: DERTag.explicit(0))
            )
        }
        guard basic.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("BasicOCSPResponse has extra fields.")
        }
        return ParsedBasicOCSPResponse(
            producedAt: responseData.producedAt,
            singleResponses: responseData.singleResponses,
            signedResponseData: responseDataNode.fullDER,
            signatureAlgorithmOID: signatureAlgorithmOID,
            signature: signature,
            responderCertificatesDER: responderCertificatesDER
        )
    }

    /// Parses the `ResponseData` block signed by the responder.
    private static func parseResponseData(_ node: DERNode) throws -> ParsedResponseData {
        var reader = DERReader(node.content)
        if !reader.isAtEnd, try reader.peekTag() == DERTag.explicit(0) {
            _ = try reader.readNode(expectedTag: DERTag.explicit(0)) // version
        }
        _ = try reader.readNode() // responderID
        let producedAt = try reader.readGeneralizedTime()
        let responses = try parseSingleResponses(try reader.readNode(expectedTag: DERTag.sequence))
        if !reader.isAtEnd {
            _ = try reader.readNode(expectedTag: DERTag.explicit(1)) // responseExtensions
        }
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("OCSP ResponseData has extra fields.")
        }
        return ParsedResponseData(producedAt: producedAt, singleResponses: responses)
    }

    /// Parses the SEQUENCE OF `SingleResponse`.
    private static func parseSingleResponses(_ node: DERNode) throws -> [OCSPSingleResponse] {
        var reader = DERReader(node.content)
        var responses: [OCSPSingleResponse] = []
        while !reader.isAtEnd {
            responses.append(try parseSingleResponse(try reader.readNode(expectedTag: DERTag.sequence)))
        }
        return responses
    }

    /// Parses one certificate status assertion.
    private static func parseSingleResponse(_ node: DERNode) throws -> OCSPSingleResponse {
        var reader = DERReader(node.content)
        let certID = try parseCertID(try reader.readNode(expectedTag: DERTag.sequence))
        let certificateStatus = try parseCertificateStatus(try reader.readNode())
        let thisUpdate = try reader.readGeneralizedTime()
        var nextUpdate: Date?

        while !reader.isAtEnd {
            let optional = try reader.readNode()
            switch optional.tag {
            case DERTag.explicit(0):
                nextUpdate = try optional.explicitGeneralizedTime()
            case DERTag.explicit(1):
                continue // singleExtensions
            default:
                throw RorkSignError.invalidSigningIdentity("OCSP SingleResponse has an unexpected optional field.")
            }
        }

        return OCSPSingleResponse(
            issuerNameHash: certID.issuerNameHash,
            issuerKeyHash: certID.issuerKeyHash,
            serialNumberHex: certID.serialNumberHex,
            certificateStatus: certificateStatus,
            thisUpdate: thisUpdate,
            nextUpdate: nextUpdate
        )
    }

    /// Parses the OCSP `CertID` used to match a request to a response.
    private static func parseCertID(_ node: DERNode) throws -> ParsedCertID {
        var reader = DERReader(node.content)
        _ = try reader.readNode(expectedTag: DERTag.sequence) // hashAlgorithm
        let issuerNameHash = try reader.readNode(expectedTag: DERTag.octetString).content
        let issuerKeyHash = try reader.readNode(expectedTag: DERTag.octetString).content
        let serial = try reader.readNode(expectedTag: DERTag.integer).content
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("OCSP CertID has extra fields.")
        }
        return ParsedCertID(
            issuerNameHash: issuerNameHash,
            issuerKeyHash: issuerKeyHash,
            serialNumberHex: formattedSerialNumberHex(from: serial)
        )
    }

    /// Returns the object identifier from an AlgorithmIdentifier.
    private static func parseAlgorithmIdentifier(_ node: DERNode) throws -> String {
        var reader = DERReader(node.content)
        let oid = try reader.readObjectIdentifier()
        _ = reader.isAtEnd ? nil : try reader.readNode()
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("OCSP AlgorithmIdentifier has extra fields.")
        }
        return oid
    }

    /// Extracts the raw signature bytes from a BIT STRING.
    private static func signatureBytes(from node: DERNode) throws -> Data {
        guard node.content.first == 0 else {
            throw RorkSignError.invalidSigningIdentity("OCSP signature BIT STRING is malformed.")
        }
        return Data(node.content.dropFirst())
    }

    /// Parses the optional responder certificate sequence.
    private static func parseResponderCertificates(_ node: DERNode) throws -> [Data] {
        let certificates = try node.explicitValue(expectedTag: DERTag.sequence)
        var reader = DERReader(certificates.content)
        var result: [Data] = []
        while !reader.isAtEnd {
            let certificate = try reader.readNode(expectedTag: DERTag.sequence)
            _ = try CertificateInfo.parse(certificate.fullDER)
            result.append(certificate.fullDER)
        }
        return result
    }

    /// Parses the OCSP certificate-status CHOICE.
    private static func parseCertificateStatus(_ node: DERNode) throws -> OCSPCertificateStatus {
        switch node.tag {
        case DERTag.contextPrimitive(0):
            return .good
        case DERTag.explicit(1):
            var reader = DERReader(node.content)
            let revocationTime = try reader.readGeneralizedTime()
            var reason: Int?
            if !reader.isAtEnd {
                let reasonNode = try reader.readNode(expectedTag: DERTag.explicit(0))
                reason = try reasonNode.explicitEnumerated()
            }
            guard reader.isAtEnd else {
                throw RorkSignError.invalidSigningIdentity("OCSP revoked status has extra fields.")
            }
            return .revoked(revocationTime: revocationTime, reason: reason)
        case DERTag.contextPrimitive(2):
            return .unknown
        default:
            throw RorkSignError.invalidSigningIdentity("OCSP certificate status has an unexpected tag.")
        }
    }

    /// Converts an `OCSPResponseStatus` ENUMERATED value.
    private static func responseStatus(from node: DERNode) throws -> OCSPResponseStatus {
        switch try integerValue(node) {
        case 0:
            return .successful
        case 1:
            return .malformedRequest
        case 2:
            return .internalError
        case 3:
            return .tryLater
        case 5:
            return .signatureRequired
        case 6:
            return .unauthorized
        case let code:
            return .unknown(code)
        }
    }
}

private struct ParsedResponseBytes {
    let responseTypeOID: String
    let producedAt: Date
    let singleResponses: [OCSPSingleResponse]
    let signedResponseData: Data
    let signatureAlgorithmOID: String
    let signature: Data
    let responderCertificatesDER: [Data]
}

private struct ParsedBasicOCSPResponse {
    let producedAt: Date
    let singleResponses: [OCSPSingleResponse]
    let signedResponseData: Data
    let signatureAlgorithmOID: String
    let signature: Data
    let responderCertificatesDER: [Data]
}

private struct ParsedResponseData {
    let producedAt: Date
    let singleResponses: [OCSPSingleResponse]
}

private struct ParsedCertID {
    let issuerNameHash: Data
    let issuerKeyHash: Data
    let serialNumberHex: String
}

private enum OID {
    static let basicOCSPResponse = "1.3.6.1.5.5.7.48.1.1"
}

private enum DERTag {
    static let integer: UInt8 = 0x02
    static let bitString: UInt8 = 0x03
    static let octetString: UInt8 = 0x04
    static let objectIdentifier: UInt8 = 0x06
    static let enumerated: UInt8 = 0x0a
    static let generalizedTime: UInt8 = 0x18
    static let sequence: UInt8 = 0x30

    static func explicit(_ number: UInt8) -> UInt8 {
        0xa0 | number
    }

    static func contextPrimitive(_ number: UInt8) -> UInt8 {
        0x80 | number
    }
}

private extension DERNode {
    /// Unwraps an explicitly tagged value and returns its single inner node.
    func explicitValue(expectedTag: UInt8? = nil) throws -> DERNode {
        var reader = DERReader(content)
        let inner = try reader.readNode(expectedTag: expectedTag)
        guard reader.isAtEnd else {
            throw RorkSignError.invalidSigningIdentity("Explicit OCSP DER value contains extra data.")
        }
        return inner
    }

    /// Reads an explicitly tagged `GeneralizedTime`.
    func explicitGeneralizedTime() throws -> Date {
        try parseGeneralizedTime(try explicitValue(expectedTag: DERTag.generalizedTime))
    }

    /// Reads an explicitly tagged ENUMERATED integer.
    func explicitEnumerated() throws -> Int {
        try integerValue(try explicitValue(expectedTag: DERTag.enumerated))
    }
}

private extension DERReader {
    mutating func readObjectIdentifier() throws -> String {
        try objectIdentifierValue(try readNode(expectedTag: DERTag.objectIdentifier))
    }

    mutating func readGeneralizedTime() throws -> Date {
        try parseGeneralizedTime(try readNode(expectedTag: DERTag.generalizedTime))
    }

    mutating func peekTag() throws -> UInt8 {
        try peekByte()
    }
}

/// Decodes a positive ASN.1 INTEGER/ENUMERATED node into `Int`.
private func integerValue(_ node: DERNode) throws -> Int {
    guard !node.content.isEmpty else {
        throw RorkSignError.invalidSigningIdentity("OCSP integer is empty.")
    }
    guard node.content[0] & 0x80 == 0 else {
        throw RorkSignError.invalidSigningIdentity("Negative OCSP integers are not supported.")
    }

    var value = 0
    for byte in node.content {
        guard value <= (Int.max - Int(byte)) / 256 else {
            throw RorkSignError.invalidSigningIdentity("OCSP integer is too large.")
        }
        value = value * 256 + Int(byte)
    }
    return value
}

/// Decodes an ASN.1 object identifier.
private func objectIdentifierValue(_ node: DERNode) throws -> String {
    guard let first = node.content.first else {
        throw RorkSignError.invalidSigningIdentity("OCSP object identifier is empty.")
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
            throw RorkSignError.invalidSigningIdentity("OCSP object identifier arc is too large.")
        }
        value = (value << 7) | Int(byte & 0x7f)
        hasContinuation = byte & 0x80 != 0
        if !hasContinuation {
            arcs.append(value)
            value = 0
        }
    }
    guard !hasContinuation else {
        throw RorkSignError.invalidSigningIdentity("OCSP object identifier is truncated.")
    }
    return arcs.map(String.init).joined(separator: ".")
}

/// Formats a serial number as colon-separated uppercase hex.
private func formattedSerialNumberHex(from serial: Data) -> String {
    var bytes = Array(serial)
    while bytes.count > 1 && bytes.first == 0 {
        bytes.removeFirst()
    }
    return bytes
        .map { String(format: "%02X", $0) }
        .joined(separator: ":")
}

/// Parses OCSP `GeneralizedTime` values with `Z` or numeric offsets.
private func parseGeneralizedTime(_ node: DERNode) throws -> Date {
    guard let value = String(data: node.content, encoding: .ascii) else {
        throw RorkSignError.invalidSigningIdentity("OCSP GeneralizedTime is not ASCII.")
    }
    guard let zoneStart = value.firstIndex(where: { $0 == "Z" || $0 == "+" || $0 == "-" }) else {
        throw RorkSignError.invalidSigningIdentity("OCSP GeneralizedTime has no time zone.")
    }

    var timestamp = String(value[..<zoneStart])
    if let fractionalStart = timestamp.firstIndex(of: ".") {
        timestamp = String(timestamp[..<fractionalStart])
    }
    let zone = String(value[zoneStart...])
    guard timestamp.count == 10 || timestamp.count == 12 || timestamp.count == 14 else {
        throw RorkSignError.invalidSigningIdentity("OCSP GeneralizedTime has an unsupported precision.")
    }

    let year = try integerPrefix(timestamp, offset: 0, count: 4)
    let month = try integerPrefix(timestamp, offset: 4, count: 2)
    let day = try integerPrefix(timestamp, offset: 6, count: 2)
    let hour = try integerPrefix(timestamp, offset: 8, count: 2)
    let minute = timestamp.count >= 12 ? try integerPrefix(timestamp, offset: 10, count: 2) : 0
    let second = timestamp.count == 14 ? try integerPrefix(timestamp, offset: 12, count: 2) : 0
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
        throw RorkSignError.invalidSigningIdentity("OCSP GeneralizedTime is invalid.")
    }
    return date
}

private func integerPrefix(_ value: String, offset: Int, count: Int) throws -> Int {
    let start = value.index(value.startIndex, offsetBy: offset)
    let end = value.index(start, offsetBy: count)
    guard let integer = Int(value[start..<end]) else {
        throw RorkSignError.invalidSigningIdentity("OCSP GeneralizedTime contains non-digits.")
    }
    return integer
}

private func timeZoneOffsetSeconds(_ zone: String) throws -> Int {
    if zone == "Z" {
        return 0
    }
    guard zone.count == 5,
          let sign = zone.first,
          sign == "+" || sign == "-" else {
        throw RorkSignError.invalidSigningIdentity("OCSP GeneralizedTime timezone is invalid.")
    }
    let hours = try integerPrefix(zone, offset: 1, count: 2)
    let minutes = try integerPrefix(zone, offset: 3, count: 2)
    let seconds = hours * 3600 + minutes * 60
    return sign == "+" ? seconds : -seconds
}
