import Foundation

/// Serializes property-list values without relying on Foundation's stream writer.
///
/// Swift Foundation's WASI implementation currently rejects arrays while
/// writing property lists. Keeping the XML implementation platform-neutral lets
/// native tests protect the browser signing path without changing RorkSign's
/// public API.
enum XMLPropertyListEncoder {
    /// Encodes one property-list root as deterministic XML data.
    static func encode(_ propertyList: Any) throws -> Data {
        var xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">

        """
        try append(propertyList, indentation: 0, to: &xml)
        xml.append("\n</plist>\n")
        return Data(xml.utf8)
    }

    /// Appends one supported property-list value using its canonical XML node.
    ///
    /// Foundation bridges booleans and integers through `NSNumber`, so concrete
    /// Swift value types are matched first to preserve their property-list kind.
    private static func append(
        _ value: Any,
        indentation: Int,
        to xml: inout String
    ) throws {
        let prefix = String(repeating: "\t", count: indentation)

        switch value {
        case let value as Bool:
            xml.append("\(prefix)<\(value ? "true" : "false")/>")

        case let value as String:
            xml.append("\(prefix)<string>\(try escaped(value))</string>")

        case let value as Data:
            xml.append("\(prefix)<data>\(value.base64EncodedString())</data>")

        case let value as Date:
            xml.append("\(prefix)<date>\(formatted(value))</date>")

        case let value as [String: Any]:
            try append(value, indentation: indentation, to: &xml)

        case let value as [Any]:
            try append(value, indentation: indentation, to: &xml)

        case let value as NSNumber:
            try append(value, prefix: prefix, to: &xml)

        case let value as Int:
            xml.append("\(prefix)<integer>\(value)</integer>")
        case let value as Int8:
            xml.append("\(prefix)<integer>\(value)</integer>")
        case let value as Int16:
            xml.append("\(prefix)<integer>\(value)</integer>")
        case let value as Int32:
            xml.append("\(prefix)<integer>\(value)</integer>")
        case let value as Int64:
            xml.append("\(prefix)<integer>\(value)</integer>")
        case let value as UInt:
            xml.append("\(prefix)<integer>\(value)</integer>")
        case let value as UInt8:
            xml.append("\(prefix)<integer>\(value)</integer>")
        case let value as UInt16:
            xml.append("\(prefix)<integer>\(value)</integer>")
        case let value as UInt32:
            xml.append("\(prefix)<integer>\(value)</integer>")
        case let value as UInt64:
            xml.append("\(prefix)<integer>\(value)</integer>")

        case let value as Float:
            try append(real: Double(value), prefix: prefix, to: &xml)
        case let value as Double:
            try append(real: value, prefix: prefix, to: &xml)

        default:
            throw RorkSignError.unsupported(
                "Property lists cannot encode values of type \(String(describing: type(of: value)))."
            )
        }
    }

    /// Appends dictionary keys in lexical order.
    ///
    /// Dictionary iteration order is not part of the property-list value, so
    /// sorting avoids host-dependent bytes without changing semantics.
    private static func append(
        _ dictionary: [String: Any],
        indentation: Int,
        to xml: inout String
    ) throws {
        let prefix = String(repeating: "\t", count: indentation)
        guard !dictionary.isEmpty else {
            xml.append("\(prefix)<dict/>")
            return
        }

        xml.append("\(prefix)<dict>\n")
        for (key, value) in dictionary.sorted(by: { $0.key < $1.key }) {
            xml.append(
                "\(String(repeating: "\t", count: indentation + 1))<key>\(try escaped(key))</key>\n"
            )
            try append(
                value,
                indentation: indentation + 1,
                to: &xml
            )
            xml.append("\n")
        }
        xml.append("\(prefix)</dict>")
    }

    /// Appends array elements in caller-provided order.
    ///
    /// Property-list arrays are ordered data, so sorting them for determinism
    /// would change the value rather than only its serialization.
    private static func append(
        _ array: [Any],
        indentation: Int,
        to xml: inout String
    ) throws {
        let prefix = String(repeating: "\t", count: indentation)
        guard !array.isEmpty else {
            xml.append("\(prefix)<array/>")
            return
        }

        xml.append("\(prefix)<array>\n")
        for value in array {
            try append(value, indentation: indentation + 1, to: &xml)
            xml.append("\n")
        }
        xml.append("\(prefix)</array>")
    }

    /// Preserves an `NSNumber`'s integer-versus-real representation.
    ///
    /// Numeric magnitude alone cannot distinguish values such as `1` and `1.0`;
    /// the Objective-C type encoding retains the property-list kind.
    private static func append(
        _ number: NSNumber,
        prefix: String,
        to xml: inout String
    ) throws {
        switch String(cString: number.objCType) {
        case "f", "d":
            try append(real: number.doubleValue, prefix: prefix, to: &xml)
        default:
            xml.append("\(prefix)<integer>\(number.stringValue)</integer>")
        }
    }

    /// Appends a finite XML property-list real value.
    ///
    /// Property lists have no portable representation for NaN or infinity, so
    /// rejecting them avoids producing XML that Foundation cannot read back.
    private static func append(
        real: Double,
        prefix: String,
        to xml: inout String
    ) throws {
        guard real.isFinite else {
            throw RorkSignError.unsupported(
                "Property lists cannot encode non-finite real numbers."
            )
        }
        xml.append("\(prefix)<real>\(real)</real>")
    }

    /// Formats dates in the canonical UTC representation used by XML plists.
    ///
    /// Pinning the timezone prevents identical values from producing different
    /// signed resources on different hosts.
    private static func formatted(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }

    /// Escapes XML markup and rejects scalars forbidden by XML 1.0.
    ///
    /// Carriage returns use a character reference because XML parsers otherwise
    /// normalize them to line feeds and change the decoded property-list value.
    private static func escaped(_ string: String) throws -> String {
        var result = ""
        result.reserveCapacity(string.utf8.count)

        for scalar in string.unicodeScalars {
            switch scalar.value {
            case 0x09, 0x0A:
                result.unicodeScalars.append(scalar)
            case 0x0D:
                result.append("&#13;")
            case 0x20...0xD7FF, 0xE000...0xFFFD, 0x10000...0x10FFFF:
                switch scalar {
                case "&":
                    result.append("&amp;")
                case "<":
                    result.append("&lt;")
                case ">":
                    result.append("&gt;")
                default:
                    result.unicodeScalars.append(scalar)
                }
            default:
                throw RorkSignError.unsupported(
                    "Property list strings cannot contain XML 1.0 control characters."
                )
            }
        }
        return result
    }
}

/// Selects the property-list writer supported by the current runtime.
enum PropertyListWriter {
    /// Serializes one property-list root in the requested representation.
    static func data(
        from propertyList: Any,
        format: PropertyListSerialization.PropertyListFormat
    ) throws -> Data {
        #if os(WASI)
        // XML remains valid wherever the signer previously requested a binary
        // plist, and avoids Foundation's unsupported WASI stream writer.
        _ = format
        return try XMLPropertyListEncoder.encode(propertyList)
        #else
        return try PropertyListSerialization.data(
            fromPropertyList: propertyList,
            format: format,
            options: 0
        )
        #endif
    }
}
