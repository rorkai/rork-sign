import Foundation

extension Data {
    /// Replaces one file using the strongest write guarantee the platform offers.
    ///
    /// Native Foundation can stage the bytes in a temporary sibling before
    /// replacing the destination. WASI explicitly lacks that temporary-file
    /// primitive, so browser signing writes directly inside its isolated,
    /// disposable workspace.
    func writeReplacingItem(at url: URL) throws {
        #if os(WASI)
        try write(to: url)
        #else
        try write(to: url, options: .atomic)
        #endif
    }

    /// Returns whether `offset..<offset + length` is wholly inside the buffer.
    ///
    /// Binary parsers should use this before every integer load so malformed
    /// Mach-O or code-signature blobs fail with a controlled error instead of
    /// relying on `Data` subscript traps.
    func containsRange(offset: Int, length: Int) -> Bool {
        offset >= 0 && length >= 0 && offset <= count && length <= count - offset
    }

    /// Reads the byte at `offset`, or `nil` when it lies past the buffer.
    func readUInt8(at offset: Int) -> UInt8? {
        guard containsRange(offset: offset, length: 1) else {
            return nil
        }
        return self[offset]
    }

    /// Reads a little-endian `UInt32` at `offset`, or `nil` when the four bytes
    /// would extend past the buffer.
    func readUInt32LE(at offset: Int) -> UInt32? {
        guard containsRange(offset: offset, length: 4) else {
            return nil
        }
        return self[offset ..< (offset + 4)].enumerated().reduce(UInt32(0)) { result, item in
            result | (UInt32(item.element) << UInt32(item.offset * 8))
        }
    }

    /// Reads a big-endian `UInt32` at `offset`, or `nil` when the four bytes
    /// would extend past the buffer.
    func readUInt32BE(at offset: Int) -> UInt32? {
        guard containsRange(offset: offset, length: 4) else {
            return nil
        }
        return self[offset ..< (offset + 4)].reduce(UInt32(0)) { result, byte in
            (result << 8) | UInt32(byte)
        }
    }

    /// Reads a little-endian `UInt64` at `offset`, or `nil` when the eight bytes
    /// would extend past the buffer.
    func readUInt64LE(at offset: Int) -> UInt64? {
        guard containsRange(offset: offset, length: 8) else {
            return nil
        }
        return self[offset ..< (offset + 8)].enumerated().reduce(UInt64(0)) { result, item in
            result | (UInt64(item.element) << UInt64(item.offset * 8))
        }
    }

    /// Reads a big-endian `UInt64` at `offset`, or `nil` when the eight bytes
    /// would extend past the buffer.
    func readUInt64BE(at offset: Int) -> UInt64? {
        guard containsRange(offset: offset, length: 8) else {
            return nil
        }
        return self[offset ..< (offset + 8)].reduce(UInt64(0)) { result, byte in
            (result << 8) | UInt64(byte)
        }
    }

    /// Overwrites four bytes at `offset` with `value` in little-endian order.
    ///
    /// - Throws: ``RorkSignError/invalidMachO(_:)`` when the write extends past
    ///   the buffer.
    mutating func writeUInt32LE(_ value: UInt32, at offset: Int) throws {
        try replaceBytes(at: offset, with: value.littleEndianBytes)
    }

    /// Overwrites four bytes at `offset` with `value` in big-endian order.
    ///
    /// - Throws: ``RorkSignError/invalidMachO(_:)`` when the write extends past
    ///   the buffer.
    mutating func writeUInt32BE(_ value: UInt32, at offset: Int) throws {
        try replaceBytes(at: offset, with: value.bigEndianBytes)
    }

    /// Overwrites eight bytes at `offset` with `value` in little-endian order.
    ///
    /// - Throws: ``RorkSignError/invalidMachO(_:)`` when the write extends past
    ///   the buffer.
    mutating func writeUInt64LE(_ value: UInt64, at offset: Int) throws {
        try replaceBytes(at: offset, with: value.littleEndianBytes)
    }

    /// Overwrites eight bytes at `offset` with `value` in big-endian order.
    ///
    /// - Throws: ``RorkSignError/invalidMachO(_:)`` when the write extends past
    ///   the buffer.
    mutating func writeUInt64BE(_ value: UInt64, at offset: Int) throws {
        try replaceBytes(at: offset, with: value.bigEndianBytes)
    }

    /// Overwrites `bytes.count` bytes starting at `offset` with `bytes`.
    ///
    /// - Throws: ``RorkSignError/invalidMachO(_:)`` when the write extends past
    ///   the buffer.
    mutating func replaceBytes(at offset: Int, with bytes: [UInt8]) throws {
        guard containsRange(offset: offset, length: bytes.count) else {
            throw RorkSignError.invalidMachO("Write extends past the file.")
        }
        replaceSubrange(offset ..< (offset + bytes.count), with: bytes)
    }

    /// Appends a single byte to the end of the buffer.
    mutating func appendUInt8(_ value: UInt8) {
        append(contentsOf: [value])
    }

    /// Appends `value` as four big-endian bytes to the end of the buffer.
    mutating func appendUInt32BE(_ value: UInt32) {
        append(contentsOf: value.bigEndianBytes)
    }

    /// Appends `value` as eight big-endian bytes to the end of the buffer.
    mutating func appendUInt64BE(_ value: UInt64) {
        append(contentsOf: value.bigEndianBytes)
    }
}

private extension FixedWidthInteger {
    /// The value's bytes in little-endian order.
    var littleEndianBytes: [UInt8] {
        withUnsafeBytes(of: littleEndian) { Array($0) }
    }

    /// The value's bytes in big-endian order.
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian) { Array($0) }
    }
}
