import Foundation

/// One indexed blob inside an embedded Mach-O code-signature SuperBlob.
///
/// The `slot` value is Apple's raw `CSSLOT_*` index. Known examples include
/// `0` for the primary CodeDirectory, `2` for requirements, `5` for XML
/// entitlements, `7` for DER entitlements, `0x1000` for alternate
/// CodeDirectories, and `0x10000` for the CMS signature wrapper.
public struct MachOCodeSignatureSlot: Equatable {
    /// Raw `CSSLOT_*` index from the SuperBlob table.
    public let slot: UInt32

    /// Complete slot blob, including its eight-byte magic/length header.
    public let data: Data
}

/// Embedded code signature extracted from one Mach-O architecture.
///
/// Thin Mach-O files return one value with `architectureIndex == 0`.
/// Universal Mach-O files return one value per architecture slice that carries
/// `LC_CODE_SIGNATURE`, in fat-header order.
public struct MachOEmbeddedCodeSignature: Equatable {
    /// Zero-based architecture index in the thin or universal Mach-O input.
    public let architectureIndex: Int

    /// Complete embedded-signature SuperBlob declared by `LC_CODE_SIGNATURE`.
    public let superBlob: Data

    /// Indexed blobs referenced by the SuperBlob table.
    public let slots: [MachOCodeSignatureSlot]

    /// Returns the first slot with the supplied raw `CSSLOT_*` index.
    public func firstSlot(_ slot: UInt32) -> MachOCodeSignatureSlot? {
        slots.first { $0.slot == slot }
    }
}

public extension RorkSigner {
    /// Reads embedded code signatures from a thin or universal Mach-O file.
    ///
    /// The parser does not verify cryptographic validity. It only follows
    /// `LC_CODE_SIGNATURE`, validates the embedded SuperBlob bounds, and returns
    /// the raw slot bytes callers need for diagnostics, debug dumps, or tests.
    static func readEmbeddedCodeSignatures(in data: Data) throws -> [MachOEmbeddedCodeSignature] {
        try CodeSignatureInspector.readEmbeddedSignatures(in: data)
    }
}
