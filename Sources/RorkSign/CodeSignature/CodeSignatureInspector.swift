#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// Extracts embedded code-signature SuperBlob data from Mach-O containers.
///
/// Signing code already knows how to create these blobs. This inspector keeps
/// the inverse operation intentionally narrow: it validates enough Mach-O and
/// SuperBlob structure to return safe byte ranges, but it does not try to parse
/// every CodeDirectory field or make trust decisions.
enum CodeSignatureInspector {
    /// Reads every embedded signature declared by a thin or universal Mach-O.
    static func readEmbeddedSignatures(in data: Data) throws -> [MachOEmbeddedCodeSignature] {
        try readEmbeddedSignatureContexts(in: data).map(\.signature)
    }

    /// Reads every embedded signature together with its owning thin slice.
    static func readEmbeddedSignatureContexts(in data: Data) throws -> [MachOEmbeddedCodeSignatureContext] {
        guard data.count >= 4 else {
            throw RorkSignError.invalidMachO("Input is too small to contain a Mach-O magic.")
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            if let signature = try readThinEmbeddedSignatureContext(in: data, architectureIndex: 0) {
                return [signature]
            }
            return []
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            let slices = try readUniversalSlices(in: data, magic: bigMagic)
            return try slices.compactMap { slice in
                try readThinEmbeddedSignatureContext(
                    in: slice.data,
                    architectureIndex: slice.architectureIndex
                )
            }
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }

    /// Validates every CodeDirectory slot in one embedded signature context.
    static func validateCodeDirectories(
        in context: MachOEmbeddedCodeSignatureContext
    ) throws -> [CodeDirectoryValidationReport] {
        var slotsByIndex: [UInt32: Data] = [:]
        for slot in context.signature.slots where slotsByIndex[slot.slot] == nil {
            slotsByIndex[slot.slot] = slot.data
        }
        let codeDirectorySlots = context.signature.slots
            .filter { slot in
                slot.slot == Constants.csslotCodeDirectory
                    || (slot.slot >= Constants.csslotAlternateCodeDirectories
                        && slot.slot < Constants.csslotSignature)
            }
            .filter { $0.data.readUInt32BE(at: 0) == Constants.csMagicCodeDirectory }
            .sorted { $0.slot < $1.slot }

        return try codeDirectorySlots.map { slot in
            try validateCodeDirectory(
                slot: slot.slot,
                data: slot.data,
                sliceData: context.sliceData,
                slotsByIndex: slotsByIndex
            )
        }
    }

    /// Reads one thin slice's embedded signature context, if the slice declares one.
    private static func readThinEmbeddedSignatureContext(
        in data: Data,
        architectureIndex: Int
    ) throws -> MachOEmbeddedCodeSignatureContext? {
        let info = try MachOSigner.inspect(data)
        guard info.hasCodeSignature, info.codeSignatureSize > 0 else {
            return nil
        }

        let signatureOffset = Int(info.codeSignatureOffset)
        let signatureSize = Int(info.codeSignatureSize)
        guard data.containsRange(offset: signatureOffset, length: signatureSize) else {
            throw RorkSignError.invalidMachO("LC_CODE_SIGNATURE points outside the file.")
        }

        return MachOEmbeddedCodeSignatureContext(
            signature: try parseSuperBlob(
                data.subdata(in: signatureOffset..<(signatureOffset + signatureSize)),
                architectureIndex: architectureIndex
            ),
            sliceData: data,
            codeSignatureOffset: signatureOffset
        )
    }

    /// Parses an embedded-signature SuperBlob and copies each indexed slot.
    private static func parseSuperBlob(
        _ superBlob: Data,
        architectureIndex: Int
    ) throws -> MachOEmbeddedCodeSignature {
        guard let magic = superBlob.readUInt32BE(at: 0),
              magic == Constants.csMagicEmbeddedSignature else {
            throw RorkSignError.invalidMachO("LC_CODE_SIGNATURE does not point at an embedded SuperBlob.")
        }
        guard let length = superBlob.readUInt32BE(at: 4),
              let count = superBlob.readUInt32BE(at: 8),
              length >= UInt32(Constants.superBlobHeaderSize),
              Int(length) <= superBlob.count else {
            throw RorkSignError.invalidMachO("Embedded code-signature SuperBlob is malformed.")
        }

        let tableLength = Int(count) * Constants.superBlobIndexSize
        guard Int(count) <= (Int(length) - Constants.superBlobHeaderSize) / Constants.superBlobIndexSize,
              superBlob.containsRange(offset: Constants.superBlobHeaderSize, length: tableLength) else {
            throw RorkSignError.invalidMachO("Embedded code-signature index is malformed.")
        }

        var slots: [MachOCodeSignatureSlot] = []
        slots.reserveCapacity(Int(count))
        for index in 0..<Int(count) {
            let indexOffset = Constants.superBlobHeaderSize + index * Constants.superBlobIndexSize
            guard let slot = superBlob.readUInt32BE(at: indexOffset),
                  let blobOffsetValue = superBlob.readUInt32BE(at: indexOffset + 4) else {
                throw RorkSignError.invalidMachO("Embedded code-signature index is malformed.")
            }

            let blobOffset = Int(blobOffsetValue)
            guard let blobLength = superBlob.readUInt32BE(at: blobOffset + 4),
                  blobLength >= UInt32(Constants.blobHeaderSize),
                  blobOffset <= Int(length),
                  Int(blobLength) <= Int(length) - blobOffset,
                  superBlob.containsRange(offset: blobOffset, length: Int(blobLength)) else {
                throw RorkSignError.invalidMachO("Embedded code-signature slot is malformed.")
            }

            slots.append(
                MachOCodeSignatureSlot(
                    slot: slot,
                    data: superBlob.subdata(in: blobOffset..<(blobOffset + Int(blobLength)))
                )
            )
        }

        return MachOEmbeddedCodeSignature(
            architectureIndex: architectureIndex,
            superBlob: superBlob.subdata(in: 0..<Int(length)),
            slots: slots
        )
    }

    /// Reads universal Mach-O slice ranges without interpreting slice contents.
    private static func readUniversalSlices(
        in data: Data,
        magic: UInt32
    ) throws -> [UniversalSlice] {
        guard let count = data.readUInt32BE(at: 4), count > 0 else {
            throw RorkSignError.invalidMachO("Universal Mach-O has no architectures.")
        }

        let fat64 = magic == Constants.fatMagic64
        let archSize = fat64 ? Constants.fatArch64Size : Constants.fatArch32Size
        guard Int(count) <= (data.count - Swift.min(data.count, Constants.fatHeaderSize)) / archSize,
              data.containsRange(offset: Constants.fatHeaderSize, length: Int(count) * archSize) else {
            throw RorkSignError.invalidMachO("Universal Mach-O architecture table is truncated.")
        }

        var slices: [UniversalSlice] = []
        slices.reserveCapacity(Int(count))
        for index in 0..<Int(count) {
            let entryOffset = Constants.fatHeaderSize + index * archSize
            let offset: UInt64?
            let size: UInt64?
            if fat64 {
                offset = data.readUInt64BE(at: entryOffset + 8)
                size = data.readUInt64BE(at: entryOffset + 16)
            } else {
                offset = data.readUInt32BE(at: entryOffset + 8).map(UInt64.init)
                size = data.readUInt32BE(at: entryOffset + 12).map(UInt64.init)
            }

            guard let offset,
                  let size,
                  offset <= UInt64(data.count),
                  size <= UInt64(data.count) - offset else {
                throw RorkSignError.invalidMachO("Universal Mach-O architecture slice is outside the file.")
            }

            slices.append(
                UniversalSlice(
                    architectureIndex: index,
                    data: data.subdata(in: Int(offset)..<Int(offset + size))
                )
            )
        }
        return slices
    }
}

struct MachOEmbeddedCodeSignatureContext {
    let signature: MachOEmbeddedCodeSignature
    let sliceData: Data
    let codeSignatureOffset: Int
}

private struct UniversalSlice {
    let architectureIndex: Int
    let data: Data
}

private enum Constants {
    static let mhMagic: UInt32 = 0xfeedface
    static let mhMagic64: UInt32 = 0xfeedfacf
    static let fatMagic: UInt32 = 0xcafebabe
    static let fatMagic64: UInt32 = 0xcafebabf
    static let csMagicCodeDirectory: UInt32 = 0xfade0c02
    static let csMagicEmbeddedSignature: UInt32 = 0xfade0cc0

    static let csslotCodeDirectory: UInt32 = 0
    static let csslotAlternateCodeDirectories: UInt32 = 0x1000
    static let csslotSignature: UInt32 = 0x10000

    static let fatHeaderSize = 8
    static let fatArch32Size = 20
    static let fatArch64Size = 32
    static let superBlobHeaderSize = 12
    static let superBlobIndexSize = 8
    static let blobHeaderSize = 8
}

private struct ParsedCodeDirectory {
    let version: UInt32
    let flags: UInt32
    let hashOffset: Int
    let identifierOffset: Int
    let specialSlotCount: Int
    let codeSlotCount: Int
    let codeLimit: UInt64
    let hashSize: Int
    let hashType: UInt8
    let pageShift: UInt8
    let identifier: String
}

/// Parses and validates one CodeDirectory against a thin Mach-O slice.
private func validateCodeDirectory(
    slot: UInt32,
    data: Data,
    sliceData: Data,
    slotsByIndex: [UInt32: Data]
) throws -> CodeDirectoryValidationReport {
    let codeDirectory = try parseCodeDirectory(data)
    let hashAlgorithm = codeDirectoryHashAlgorithm(from: codeDirectory.hashType)
    let expectedCodeSlotCount = expectedCodeSlotCount(
        codeLimit: codeDirectory.codeLimit,
        pageShift: codeDirectory.pageShift
    )
    let canDigest = digest(Data(), hashType: codeDirectory.hashType) != nil
    let codeSlotsValid = canDigest
        && expectedCodeSlotCount == UInt32(codeDirectory.codeSlotCount)
        && validateCodeSlots(codeDirectory, in: data, sliceData: sliceData)
    let specialSlotsValid = canDigest
        && validateSpecialSlots(codeDirectory, in: data, slotsByIndex: slotsByIndex)

    return CodeDirectoryValidationReport(
        slot: slot,
        identifier: codeDirectory.identifier,
        version: codeDirectory.version,
        flags: codeDirectory.flags,
        hashAlgorithm: hashAlgorithm,
        codeLimit: codeDirectory.codeLimit,
        declaredCodeSlotCount: UInt32(codeDirectory.codeSlotCount),
        expectedCodeSlotCount: expectedCodeSlotCount,
        codeSlotsValid: codeSlotsValid,
        specialSlotsValid: specialSlotsValid
    )
}

/// Parses CodeDirectory fields used for local hash validation.
private func parseCodeDirectory(_ data: Data) throws -> ParsedCodeDirectory {
    guard let magic = data.readUInt32BE(at: 0),
          magic == Constants.csMagicCodeDirectory,
          let length = data.readUInt32BE(at: 4),
          length >= 44,
          Int(length) <= data.count else {
        throw RorkSignError.invalidMachO("CodeDirectory blob is malformed.")
    }

    guard let version = data.readUInt32BE(at: 8),
          let flags = data.readUInt32BE(at: 12),
          let hashOffset = data.readUInt32BE(at: 16),
          let identifierOffset = data.readUInt32BE(at: 20),
          let specialSlotCount = data.readUInt32BE(at: 24),
          let codeSlotCount = data.readUInt32BE(at: 28),
          let codeLimit32 = data.readUInt32BE(at: 32) else {
        throw RorkSignError.invalidMachO("CodeDirectory header is truncated.")
    }

    let hashSize = Int(data[36])
    let hashType = data[37]
    let pageShift = data[39]
    let codeLimit64 = data.readUInt64BE(at: 56) ?? 0
    let codeLimit = codeLimit64 == 0 ? UInt64(codeLimit32) : codeLimit64
    let lengthInt = Int(length)
    let hashOffsetInt = Int(hashOffset)
    let identifierOffsetInt = Int(identifierOffset)
    let specialSlotCountInt = Int(specialSlotCount)
    let codeSlotCountInt = Int(codeSlotCount)

    guard hashSize > 0,
          hashOffsetInt <= lengthInt,
          identifierOffsetInt < lengthInt,
          specialSlotCountInt <= hashOffsetInt / hashSize,
          codeSlotCountInt <= (lengthInt - hashOffsetInt) / hashSize else {
        throw RorkSignError.invalidMachO("CodeDirectory hash layout is malformed.")
    }

    return ParsedCodeDirectory(
        version: version,
        flags: flags,
        hashOffset: hashOffsetInt,
        identifierOffset: identifierOffsetInt,
        specialSlotCount: specialSlotCountInt,
        codeSlotCount: codeSlotCountInt,
        codeLimit: codeLimit,
        hashSize: hashSize,
        hashType: hashType,
        pageShift: pageShift,
        identifier: nullTerminatedString(in: data, offset: identifierOffsetInt, limit: lengthInt)
    )
}

/// Recomputes every code-page hash declared by `codeDirectory`.
private func validateCodeSlots(
    _ codeDirectory: ParsedCodeDirectory,
    in codeDirectoryData: Data,
    sliceData: Data
) -> Bool {
    guard codeDirectory.codeLimit <= UInt64(sliceData.count),
          let pageSize = pageSize(fromShift: codeDirectory.pageShift) else {
        return false
    }

    let codeLimit = Int(codeDirectory.codeLimit)
    for index in 0..<codeDirectory.codeSlotCount {
        let pageStart = index * pageSize
        let pageEnd = min(pageStart + pageSize, codeLimit)
        guard pageStart < pageEnd || codeLimit == 0 else {
            return false
        }

        let page = pageStart < pageEnd
            ? codeDirectoryDataRange(sliceData, pageStart..<pageEnd)
            : Data()
        guard let pageDigest = digest(page, hashType: codeDirectory.hashType),
              pageDigest == storedCodeHash(index, in: codeDirectoryData, codeDirectory: codeDirectory) else {
            return false
        }
    }
    return true
}

/// Recomputes hashes for the non-code SuperBlob children referenced by a CodeDirectory.
private func validateSpecialSlots(
    _ codeDirectory: ParsedCodeDirectory,
    in codeDirectoryData: Data,
    slotsByIndex: [UInt32: Data]
) -> Bool {
    for slot in 1...codeDirectory.specialSlotCount {
        let expected = storedSpecialHash(UInt32(slot), in: codeDirectoryData, codeDirectory: codeDirectory)
        let zeroHash = Data(repeating: 0, count: codeDirectory.hashSize)

        guard let slotData = slotsByIndex[UInt32(slot)] else {
            if expected != zeroHash {
                return false
            }
            continue
        }

        guard let actual = digest(slotData, hashType: codeDirectory.hashType),
              actual == expected else {
            return false
        }
    }
    return true
}

/// Returns the stored hash for one special slot.
private func storedSpecialHash(
    _ slot: UInt32,
    in codeDirectoryData: Data,
    codeDirectory: ParsedCodeDirectory
) -> Data {
    let storageIndex = codeDirectory.specialSlotCount - Int(slot)
    let offset = codeDirectory.hashOffset - codeDirectory.specialSlotCount * codeDirectory.hashSize
        + storageIndex * codeDirectory.hashSize
    return codeDirectoryData.subdata(in: offset..<(offset + codeDirectory.hashSize))
}

/// Returns the stored hash for one code slot.
private func storedCodeHash(
    _ index: Int,
    in codeDirectoryData: Data,
    codeDirectory: ParsedCodeDirectory
) -> Data {
    let offset = codeDirectory.hashOffset + index * codeDirectory.hashSize
    return codeDirectoryData.subdata(in: offset..<(offset + codeDirectory.hashSize))
}

/// Maps CodeDirectory hash-type bytes to the public enum.
private func codeDirectoryHashAlgorithm(from hashType: UInt8) -> CodeDirectoryHashAlgorithm {
    switch hashType {
    case 1:
        return .sha1
    case 2:
        return .sha256
    default:
        return .unsupported(hashType)
    }
}

/// Hashes data with a CodeDirectory hash-type byte.
private func digest(_ data: Data, hashType: UInt8) -> Data? {
    switch hashType {
    case 1:
        return Data(Insecure.SHA1.hash(data: data))
    case 2:
        return Data(SHA256.hash(data: data))
    default:
        return nil
    }
}

/// Computes the number of code slots required for one code limit and page size.
private func expectedCodeSlotCount(codeLimit: UInt64, pageShift: UInt8) -> UInt32 {
    guard let pageSize = pageSize(fromShift: pageShift) else {
        return 0
    }
    let pageSize64 = UInt64(pageSize)
    return UInt32((codeLimit + pageSize64 - 1) / pageSize64)
}

/// Converts CodeDirectory page-shift bits into a bounded page size.
private func pageSize(fromShift pageShift: UInt8) -> Int? {
    guard pageShift < 31 else {
        return nil
    }
    return 1 << Int(pageShift)
}

/// Copies a slice range before hashing it.
private func codeDirectoryDataRange(_ data: Data, _ range: Range<Int>) -> Data {
    data.subdata(in: range)
}

/// Reads a null-terminated UTF-8 string bounded by `limit`.
private func nullTerminatedString(in data: Data, offset: Int, limit: Int) -> String {
    guard offset >= 0, offset < limit else {
        return ""
    }
    let end = data[offset..<limit].firstIndex(of: 0) ?? limit
    return String(decoding: data[offset..<end], as: UTF8.self)
}
