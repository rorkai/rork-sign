import Foundation

/// Collection operations shared by DER encoders in this package.
extension Array where Element == Data {
    /// Returns DER-encoded values in the bytewise order required for SET values.
    ///
    /// DER canonicalization compares each complete encoded value rather than
    /// its decoded ASN.1 payload. Keeping this operation at the collection
    /// boundary prevents individual encoders from implementing subtly
    /// different ordering rules.
    func sortedLexicographically() -> [Data] {
        sorted { lhs, rhs in
            lhs.lexicographicallyPrecedes(rhs)
        }
    }
}
