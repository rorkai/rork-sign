import Foundation

/// Validates and adapts Foundation's open property-list object graph for
/// `PropertyListEncoder`.
///
/// Existing bundle metadata is intentionally read as `[String: Any]` because
/// arbitrary entitlement and Info.plist keys cannot be modeled by a closed
/// `Codable` schema. Converting that graph before encoding keeps unsupported
/// runtime values out of Foundation's serializer without reimplementing the
/// property-list format.
private indirect enum PropertyListValue: Encodable {
    case dictionary([String: PropertyListValue])
    case array([PropertyListValue])
    case data(Data)
    case date(Date)
    case string(String)
    case boolean(Bool)
    case signedInteger(Int64)
    case unsignedInteger(UInt64)
    case real(Double)

    private static let booleanNumberType = ObjectIdentifier(
        type(of: NSNumber(value: true))
    )

    /// Distinguishes Foundation's Boolean box from numeric zero and one.
    ///
    /// `objCType` cannot identify this safely because Boolean and signed-byte
    /// values may both report `"c"`. Comparing against the runtime's own
    /// Boolean type avoids naming Foundation's private concrete subclass.
    private static func isBoolean(_ number: NSNumber) -> Bool {
        ObjectIdentifier(type(of: number)) == Self.booleanNumberType
    }

    /// Converts one Foundation property-list node into a validated value tree.
    ///
    /// Validation happens before Foundation starts encoding so callers receive
    /// the package's domain errors directly instead of errors nested inside an
    /// `EncodingError`.
    init(validating value: Any) throws {
        switch value {
        case let dictionary as [String: Any]:
            self = .dictionary(
                try dictionary.mapValues {
                    try PropertyListValue(validating: $0)
                }
            )
        case let array as [Any]:
            self = .array(
                try array.map {
                    try PropertyListValue(validating: $0)
                }
            )
        case let data as Data:
            self = .data(data)
        case let date as Date:
            self = .date(date)
        case let string as String:
            self = .string(string)
        case let number as NSNumber:
            self = try PropertyListValue(validating: number)
        default:
            throw RorkSignError.unsupported(
                "Property lists cannot encode values of type \(String(describing: type(of: value)))."
            )
        }
    }

    /// Preserves the property-list kind hidden behind `NSNumber` bridging.
    ///
    /// Swift permits numeric zero and one to bridge to `Bool`, so testing with
    /// `as? Bool` would silently turn decoded integer nodes into booleans.
    private init(validating number: NSNumber) throws {
        if Self.isBoolean(number) {
            self = .boolean(number.boolValue)
            return
        }

        switch String(cString: number.objCType) {
        case "f", "d":
            guard number.doubleValue.isFinite else {
                throw RorkSignError.unsupported(
                    "Property lists cannot encode non-finite real numbers."
                )
            }
            self = .real(number.doubleValue)
        case "C", "S", "I", "L", "Q":
            self = .unsignedInteger(number.uint64Value)
        case "c", "s", "i", "l", "q":
            self = .signedInteger(number.int64Value)
        default:
            throw RorkSignError.unsupported(
                "Property lists cannot encode NSNumber values with Objective-C type \(String(cString: number.objCType))."
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        switch self {
        case .dictionary(let dictionary):
            var container = encoder.container(keyedBy: PropertyListKey.self)
            for (key, value) in dictionary {
                try container.encode(value, forKey: PropertyListKey(key))
            }
        case .array(let array):
            var container = encoder.unkeyedContainer()
            for value in array {
                try container.encode(value)
            }
        case .data(let data):
            var container = encoder.singleValueContainer()
            try container.encode(data)
        case .date(let date):
            var container = encoder.singleValueContainer()
            try container.encode(date)
        case .string(let string):
            var container = encoder.singleValueContainer()
            try container.encode(string)
        case .boolean(let boolean):
            var container = encoder.singleValueContainer()
            try container.encode(boolean)
        case .signedInteger(let integer):
            var container = encoder.singleValueContainer()
            try container.encode(integer)
        case .unsignedInteger(let integer):
            var container = encoder.singleValueContainer()
            try container.encode(integer)
        case .real(let real):
            var container = encoder.singleValueContainer()
            try container.encode(real)
        }
    }
}

/// Represents property-list dictionary keys for Foundation's keyed encoder.
///
/// Property lists permit arbitrary string keys but never integer keys, so the
/// integer initializer intentionally rejects every value.
private struct PropertyListKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init(_ stringValue: String) {
        self.stringValue = stringValue
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        return nil
    }
}

/// Serializes the dynamic property-list graphs used by signing resources.
///
/// RorkSign keeps decoded bundle metadata open-ended because applications may
/// contain entitlement and Info.plist keys unknown to the library. The writer
/// validates that graph through `PropertyListValue`, then delegates the actual
/// XML or binary representation to Foundation's `PropertyListEncoder`.
enum PropertyListWriter {
    /// Encodes one property-list root using Foundation's requested format.
    ///
    /// - Parameters:
    ///   - propertyList: A dictionary containing supported property-list
    ///     values.
    ///   - format: The XML or binary representation to produce.
    /// - Returns: Foundation-encoded property-list data.
    /// - Throws: `RorkSignError.unsupported` when the graph contains a value that
    ///   property lists cannot represent, or a Foundation encoding error.
    static func data(
        from propertyList: [String: Any],
        format: PropertyListSerialization.PropertyListFormat
    ) throws -> Data {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = format
        return try encoder.encode(PropertyListValue(validating: propertyList))
    }
}
