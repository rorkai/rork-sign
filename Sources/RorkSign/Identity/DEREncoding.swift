import Foundation

/// Definite-length DER primitives shared by identity container formats.
///
/// Identity requests and PKCS#12 exports both need a small subset of ASN.1.
/// Keeping those primitives here avoids coupling public signing APIs to a
/// concrete ASN.1 package while preserving one canonical encoding path.
enum DEREncoding {
    /// Encodes already-formed child values as one ordered ASN.1 sequence.
    static func sequence(_ elements: [Data]) -> Data {
        tagged(0x30, elements.reduce(into: Data()) { $0.append($1) })
    }

    /// Encodes already-formed child values as one canonically ordered ASN.1 set.
    ///
    /// DER requires SET members to be ordered by their complete encoded byte
    /// representation, so callers must not rely on their input order.
    static func set(_ elements: [Data]) -> Data {
        tagged(
            0x31,
            elements.sortedLexicographically().reduce(into: Data()) {
                $0.append($1)
            }
        )
    }

    /// Encodes a nonnegative integer using DER's shortest valid representation.
    ///
    /// This encoder intentionally supports only the nonnegative values needed
    /// by certificate requests and PKCS#12 containers.
    static func integer(_ value: Int) -> Data {
        precondition(value >= 0)
        var remaining = value
        var bytes: [UInt8] = []
        repeat {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        } while remaining > 0
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        return tagged(0x02, Data(bytes))
    }

    /// Encodes a validated dotted-decimal ASN.1 object identifier.
    ///
    /// Object identifiers are constants owned by the package. Invalid arcs are
    /// therefore programmer errors and intentionally fail a precondition.
    static func objectIdentifier(_ value: String) -> Data {
        let components = value.split(
            separator: ".",
            omittingEmptySubsequences: false
        ).map { component in
            guard let value = Int(component) else {
                preconditionFailure("Invalid OID arc: \(component)")
            }
            return value
        }
        precondition(
            components.count >= 2
                && (0...2).contains(components[0])
                && components[1] >= 0
                && (components[0] == 2 || components[1] < 40)
        )

        var content = base128(components[0] * 40 + components[1])
        for component in components.dropFirst(2) {
            precondition(component >= 0)
            content.append(contentsOf: base128(component))
        }
        return tagged(0x06, Data(content))
    }

    /// Returns DER's single canonical representation of ASN.1 NULL.
    static func null() -> Data {
        Data([0x05, 0x00])
    }

    /// Encodes a Swift string as an ASN.1 UTF8String.
    static func utf8String(_ value: String) -> Data {
        tagged(0x0c, Data(value.utf8))
    }

    /// Encodes bytes as an ASN.1 octet string.
    static func octetString(_ value: Data) -> Data {
        tagged(0x04, value)
    }

    /// Encodes whole bytes as an ASN.1 bit string with no unused trailing bits.
    static func bitString(_ value: Data) -> Data {
        tagged(0x03, Data([0]) + value)
    }

    /// Encodes constructed content with a context-specific low-tag-number tag.
    ///
    /// The identity formats used by this package need only tag numbers below
    /// 31, so high-tag-number encoding is deliberately outside this helper's
    /// contract.
    static func contextSpecificConstructed(
        _ tagNumber: UInt8,
        content: Data
    ) -> Data {
        precondition(tagNumber < 31)
        return tagged(0xa0 | tagNumber, content)
    }

    /// Prefixes content with an ASN.1 tag and a definite DER length.
    static func tagged(_ tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + encodedLength(content.count) + content
    }

    /// Encodes a nonnegative content length using DER's definite-length form.
    private static func encodedLength(_ length: Int) -> Data {
        precondition(length >= 0)
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

    /// Encodes one nonnegative object-identifier arc in base-128 form.
    private static func base128(_ value: Int) -> [UInt8] {
        precondition(value >= 0)
        var value = value
        var bytes = [UInt8(value & 0x7f)]
        value >>= 7
        while value > 0 {
            bytes.insert(UInt8(value & 0x7f) | 0x80, at: 0)
            value >>= 7
        }
        return bytes
    }
}
