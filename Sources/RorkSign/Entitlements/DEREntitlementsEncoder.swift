import Foundation

/// Encodes entitlement plists into Apple's DER entitlement slot format.
///
/// Modern Apple signatures usually carry both the original XML entitlement plist
/// and a DER-encoded entitlement blob. The DER format here is intentionally
/// narrow: it supports the value shapes Apple entitlements actually use
/// (`String`, integer, boolean, array, and dictionary), sorts dictionary keys for
/// stable output, and rejects ambiguous values instead of guessing.
enum DEREntitlementsEncoder {
    /// Converts an XML property-list entitlement dictionary into a DER blob.
    ///
    /// The returned data is the payload for `CSSLOT_DER_ENTITLEMENTS`; the
    /// code-signature wrapper magic is added by `CodeSignatureBuilder`.
    static func encodeXML(_ xml: String) throws -> Data {
        guard let xmlData = xml.data(using: .utf8) else {
            throw RorkSignError.invalidEntitlements("Entitlements XML is not valid UTF-8.")
        }

        let plist = try PropertyListSerialization.propertyList(from: xmlData, options: [], format: nil)
        guard let dictionary = plist as? [String: Any] else {
            throw RorkSignError.invalidEntitlements("Entitlements XML must contain a dictionary.")
        }

        var content = try encodeInteger(1)
        content.append(try encodeDictionary(dictionary))
        return encode(tag: 0x70, content: content)
    }

    /// Encodes a dictionary as Apple's context-specific entitlement dictionary.
    ///
    /// Entries are sorted by key so the same entitlements always produce the
    /// same signature bytes, which matters for reproducible tests and caching.
    private static func encodeDictionary(_ dictionary: [String: Any]) throws -> Data {
        var content = Data()
        for key in dictionary.keys.sorted() {
            var entry = encodeString(key)
            entry.append(try encodeValue(dictionary[key] as Any))
            content.append(encode(tag: 0x30, content: entry))
        }
        return encode(tag: 0xb0, content: content)
    }

    /// Encodes entitlement arrays as ordered DER sequences.
    private static func encodeArray(_ array: [Any]) throws -> Data {
        var content = Data()
        for value in array {
            content.append(try encodeValue(value))
        }
        return encode(tag: 0x30, content: content)
    }

    /// Dispatches a property-list value to its DER representation.
    ///
    /// `NSNumber` can represent both integer and boolean plist values. Swift can
    /// also bridge integer `NSNumber(1)` to `Bool`, so the `NSNumber` path must
    /// run before the direct `Bool` pattern.
    private static func encodeValue(_ value: Any) throws -> Data {
        switch value {
        case let number as NSNumber:
            if isBooleanNumber(number) {
                return encodeBool(number.boolValue)
            }
            return try encodeInteger(number.int64Value)
        case let bool as Bool:
            return encodeBool(bool)
        case let string as String:
            return encodeString(string)
        case let array as [Any]:
            return try encodeArray(array)
        case let dictionary as [String: Any]:
            return try encodeDictionary(dictionary)
        default:
            throw RorkSignError.invalidEntitlements("Entitlement value type is not supported for DER encoding.")
        }
    }

    /// Returns true for Foundation's bridged `CFBoolean` representation.
    private static func isBooleanNumber(_ number: NSNumber) -> Bool {
        String(cString: number.objCType) == "c"
    }

    private static func encodeString(_ value: String) -> Data {
        encode(tag: 0x0c, content: Data(value.utf8))
    }

    private static func encodeBool(_ value: Bool) -> Data {
        encode(tag: 0x01, content: Data([value ? 0xff : 0x00]))
    }

    /// Encodes non-negative DER integers using the shortest two's-complement
    /// representation accepted by Apple's entitlement parser.
    private static func encodeInteger(_ value: Int64) throws -> Data {
        guard value >= 0 else {
            throw RorkSignError.invalidEntitlements("Negative integer entitlements are not supported.")
        }

        var remaining = UInt64(value)
        var bytes = [UInt8]()
        repeat {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        } while remaining > 0

        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        return encode(tag: 0x02, content: Data(bytes))
    }

    /// Writes a DER tag, canonical length, and payload.
    private static func encode(tag: UInt8, content: Data) -> Data {
        var output = Data([tag])
        output.append(encodeLength(content.count))
        output.append(content)
        return output
    }

    /// Encodes short-form and long-form DER lengths.
    private static func encodeLength(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }

        var remaining = length
        var bytes = [UInt8]()
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}
