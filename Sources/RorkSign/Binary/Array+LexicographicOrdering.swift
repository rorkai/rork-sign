/// Lexicographic ordering shared by canonical encoders in this package.
extension Array where Element: Sequence, Element.Element: Comparable {
    /// Returns a copy ordered by comparing each element as a sequence.
    ///
    /// Canonical binary formats compare complete encoded values element by
    /// element. Centralizing that rule here keeps individual encoders from
    /// implementing subtly different ordering behavior.
    func sortedLexicographically() -> Self {
        sorted { lhs, rhs in
            lhs.lexicographicallyPrecedes(rhs)
        }
    }
}
