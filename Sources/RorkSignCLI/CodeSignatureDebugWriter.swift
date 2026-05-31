import Foundation
import RorkSign

/// Writes ZSign-style code-signature debug artifacts.
///
/// ZSign's `-d` flag writes the newly generated SuperBlob and selected slots
/// into `./.zsign_debug`. Keeping the same filenames makes it easy to compare
/// this Swift signer against existing debug workflows while the library API
/// remains a structured byte extractor.
enum CodeSignatureDebugWriter {
    /// Writes debug artifacts for every embedded signature in `machOData`.
    ///
    /// Thin binaries write directly into `directory`. Universal binaries write
    /// each architecture into `directory/arch-<index>` so slot files do not
    /// overwrite each other.
    static func writeArtifacts(
        from machOData: Data,
        directory: URL = defaultDirectory()
    ) throws -> [URL] {
        let signatures = try RorkSigner.readEmbeddedCodeSignatures(in: machOData)
        guard !signatures.isEmpty else {
            throw RorkSignError.invalidMachO("Mach-O has no embedded code signature.")
        }

        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        var written: [URL] = []
        if signatures.count == 1, let signature = signatures.first {
            try written.append(contentsOf: write(signature, to: directory))
        } else {
            for signature in signatures {
                let architectureDirectory = directory.appendingPathComponent(
                    "arch-\(signature.architectureIndex)",
                    isDirectory: true
                )
                try FileManager.default.createDirectory(
                    at: architectureDirectory,
                    withIntermediateDirectories: true
                )
                try written.append(contentsOf: write(signature, to: architectureDirectory))
            }
        }
        return written
    }

    /// Returns the default debug output folder in the current working directory.
    static func defaultDirectory() -> URL {
        URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".zsign_debug", isDirectory: true)
    }

    /// Writes one architecture's SuperBlob and known slots.
    private static func write(
        _ signature: MachOEmbeddedCodeSignature,
        to directory: URL
    ) throws -> [URL] {
        var written: [URL] = []
        try written.append(write(signature.superBlob, named: "CodeSignature.blob.new", to: directory))

        for slot in signature.slots {
            switch slot.slot {
            case Slot.requirements:
                try written.append(write(slot.data, named: "Requirements.slot.new", to: directory))
            case Slot.entitlements:
                try written.append(write(slot.data, named: "Entitlements.slot.new", to: directory))
                if let payload = blobPayload(slot.data) {
                    try written.append(write(payload, named: "Entitlements.plist.new", to: directory))
                }
            case Slot.derEntitlements:
                try written.append(write(slot.data, named: "Entitlements.der.slot.new", to: directory))
            case Slot.codeDirectory, Slot.alternateCodeDirectories:
                try written.append(writeCodeDirectory(slot.data, to: directory))
            case Slot.cmsSignature:
                try written.append(write(slot.data, named: "CMSSignature.slot.new", to: directory))
                if let payload = blobPayload(slot.data) {
                    try written.append(write(payload, named: "CMSSignature.der.new", to: directory))
                }
            default:
                continue
            }
        }
        return written
    }

    /// Writes a CodeDirectory slot using the SHA family encoded in its header.
    private static func writeCodeDirectory(_ data: Data, to directory: URL) throws -> URL {
        switch data.byte(at: 37) {
        case .some(1):
            return try write(data, named: "CodeDirectory_SHA1.slot.new", to: directory)
        case .some(2):
            return try write(data, named: "CodeDirectory_SHA256.slot.new", to: directory)
        default:
            return try write(data, named: "CodeDirectory.slot.new", to: directory)
        }
    }

    /// Writes `data` atomically and returns the destination path.
    private static func write(_ data: Data, named name: String, to directory: URL) throws -> URL {
        let url = directory.appendingPathComponent(name)
        try data.write(to: url, options: .atomic)
        return url
    }

    /// Returns a standard code-signing blob payload after the magic/length header.
    private static func blobPayload(_ data: Data) -> Data? {
        guard let length = data.uint32BE(at: 4),
              length >= 8,
              Int(length) <= data.count else {
            return nil
        }
        return data.subdata(in: 8..<Int(length))
    }
}

private enum Slot {
    static let codeDirectory: UInt32 = 0
    static let requirements: UInt32 = 2
    static let entitlements: UInt32 = 5
    static let derEntitlements: UInt32 = 7
    static let alternateCodeDirectories: UInt32 = 0x1000
    static let cmsSignature: UInt32 = 0x10000
}

private extension Data {
    /// Reads one byte from a safe offset.
    func byte(at offset: Int) -> UInt8? {
        guard offset >= 0, offset < count else {
            return nil
        }
        return self[offset]
    }

    /// Reads a big-endian UInt32 from a safe offset.
    func uint32BE(at offset: Int) -> UInt32? {
        guard offset >= 0, offset <= count - 4 else {
            return nil
        }
        return self[offset..<(offset + 4)].reduce(UInt32(0)) { result, byte in
            (result << 8) | UInt32(byte)
        }
    }
}
