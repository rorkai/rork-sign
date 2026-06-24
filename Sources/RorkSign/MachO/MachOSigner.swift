import Foundation

/// Parses and rewrites Mach-O binaries for embedded code signatures.
///
/// The signer only mutates the pieces Apple stores inside the Mach-O itself:
/// `LC_CODE_SIGNATURE`, the appended embedded-signature SuperBlob, and the
/// `__LINKEDIT` file/vm size fields that describe the appended data. It does not
/// try to be a general Mach-O editor.
enum MachOSigner {
    /// Reads metadata used by diagnostics and tests.
    static func inspect(_ data: Data) throws -> MachOInfo {
        guard data.count >= 4 else {
            throw RorkSignError.invalidMachO("Input is too small to contain a Mach-O magic.")
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            return try readThinMachOInfo(data)
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            return try readUniversalInfo(data)
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }

    /// Extracts the XML entitlement plist from the existing embedded signature.
    ///
    /// Standalone app signing uses the provisioning profile as the authority for
    /// what can be signed, but it still needs the guest app's old entitlement
    /// shape to avoid accidentally granting profile capabilities the executable
    /// never requested. Universal binaries are expected to carry equivalent
    /// entitlements in every slice, so the first non-empty entitlement slot is
    /// used.
    static func readEntitlementsXML(_ data: Data) throws -> String {
        guard data.count >= 4 else {
            throw RorkSignError.invalidMachO("Input is too small to contain a Mach-O magic.")
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            return try readThinEntitlementsXML(data)
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            for record in try readFatArchRecords(data) {
                let entitlements = try readThinEntitlementsXML(record.data)
                if !entitlements.isEmpty {
                    return entitlements
                }
            }
            return ""
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }

    /// Reads dynamic-library load commands without mutating the Mach-O.
    static func dylibLoadCommands(_ data: Data) throws -> [MachODylibLoadCommand] {
        guard data.count >= 4 else {
            throw RorkSignError.invalidMachO("Input is too small to contain a Mach-O magic.")
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            return try readThinDylibLoadCommands(data)
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            return try readFatArchRecords(data).flatMap { record in
                try readThinDylibLoadCommands(record.data)
            }
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }

    /// Adds an `LC_LOAD_DYLIB` or `LC_LOAD_WEAK_DYLIB` command.
    static func injectDylibLoadCommand(_ data: Data, path: String, weak: Bool) throws -> Data {
        guard data.count >= 4 else {
            throw RorkSignError.invalidMachO("Input is too small to contain a Mach-O magic.")
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            return try injectThinDylibLoadCommand(data, path: path, weak: weak)
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            var records = try readFatArchRecords(data)
            for index in records.indices {
                records[index].data = try injectThinDylibLoadCommand(records[index].data, path: path, weak: weak)
            }
            return try rebuildUniversalMachO(magic: bigMagic, records: records)
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }

    /// Removes matching dynamic-library load commands.
    static func removeDylibLoadCommands(_ data: Data, matching paths: [String]) throws -> Data {
        guard data.count >= 4 else {
            throw RorkSignError.invalidMachO("Input is too small to contain a Mach-O magic.")
        }

        let matchSet = dylibRemovalMatchSet(paths)
        guard !matchSet.isEmpty else {
            return data
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            return try removeThinDylibLoadCommands(data, matching: matchSet)
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            var records = try readFatArchRecords(data)
            for index in records.indices {
                records[index].data = try removeThinDylibLoadCommands(records[index].data, matching: matchSet)
            }
            return try rebuildUniversalMachO(magic: bigMagic, records: records)
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }

    /// Returns the deterministic Mach-O bytes that feed cache keys for signing.
    ///
    /// Existing embedded signatures are stripped before hashing, and the
    /// `LC_CODE_SIGNATURE` / `__LINKEDIT` bookkeeping is normalized to the
    /// zero-signature layout used at the start of signing. This lets a bundle
    /// that was already signed hit the same cache entry as its unsigned input
    /// when the executable code and load commands are otherwise unchanged.
    static func signingCacheInput(_ data: Data) throws -> Data {
        guard data.count >= 4 else {
            throw RorkSignError.invalidMachO("Input is too small to contain a Mach-O magic.")
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            return try thinSigningCacheInput(data)
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            var records = try readFatArchRecords(data)
            for index in records.indices {
                records[index].data = try thinSigningCacheInput(records[index].data)
            }
            return try rebuildUniversalMachO(magic: bigMagic, records: records)
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }

    /// Rewrites a Mach-O with an ad-hoc embedded signature.
    ///
    /// Thin 64-bit binaries are signed directly. Universal binaries are rebuilt
    /// by signing each contained thin slice and then updating the fat-archive
    /// offsets and sizes.
    static func signAdHoc(
        _ data: Data,
        bundleIdentifier: String,
        entitlementsXML: String,
        entitlementsDER: Data,
        infoPlist: Data,
        resourceDirectory: Data,
        codeDirectoryHashingMode: CodeDirectoryHashingMode
    ) throws -> Data {
        let options = MachOSigningOptions(
            bundleIdentifier: bundleIdentifier,
            subjectCommonName: "",
            entitlementsXML: entitlementsXML,
            entitlementsDER: entitlementsDER,
            infoPlist: infoPlist,
            resourceDirectory: resourceDirectory,
            cmsSignature: Data(),
            adHoc: true,
            codeDirectoryHashingMode: codeDirectoryHashingMode
        )

        guard data.count >= 4 else {
            throw RorkSignError.invalidMachO("Code signing received empty Mach-O data.")
        }
        guard !bundleIdentifier.isEmpty else {
            throw RorkSignError.invalidMachO("Code signing needs a bundle identifier.")
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            return try signThinMachO(data, options: options)
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            return try signUniversalMachO(data, magic: bigMagic, options: options)
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }

    /// Prepares CodeDirectory blobs for detached CMS signing.
    ///
    /// This performs the same Mach-O layout mutation as final signing, but uses
    /// zero-filled CMS placeholders sized by `cmsSignatureLengthHints`. The
    /// resulting CodeDirectory bytes are what the caller must sign.
    static func prepareCMSCodeDirectories(
        _ data: Data,
        bundleIdentifier: String,
        subjectCommonName: String,
        teamIdentifier: String,
        entitlementsXML: String,
        entitlementsDER: Data,
        infoPlist: Data,
        resourceDirectory: Data,
        cmsSignatureLengthHints: [Int],
        codeDirectoryHashingMode: CodeDirectoryHashingMode
    ) throws -> [MachOCMSCodeDirectory] {
        guard !data.isEmpty else {
            throw RorkSignError.invalidMachO("Code signing received empty Mach-O data.")
        }
        guard !bundleIdentifier.isEmpty else {
            throw RorkSignError.invalidMachO("Code signing needs a bundle identifier.")
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            let hint = try cmsSignatureLengthHint(at: 0, in: cmsSignatureLengthHints)
            let codeDirectories = try prepareThinMachOCMSCodeDirectories(
                data,
                options: MachOSigningOptions(
                    bundleIdentifier: bundleIdentifier,
                    subjectCommonName: subjectCommonName,
                    teamIdentifier: teamIdentifier,
                    entitlementsXML: entitlementsXML,
                    entitlementsDER: entitlementsDER,
                    infoPlist: infoPlist,
                    resourceDirectory: resourceDirectory,
                    cmsSignature: Data(repeating: 0, count: hint),
                    adHoc: false,
                    codeDirectoryHashingMode: codeDirectoryHashingMode
                )
            )
            return [
                MachOCMSCodeDirectory(
                    architectureIndex: 0,
                    codeDirectory: codeDirectories.primary,
                    alternateCodeDirectory: codeDirectories.alternate
                ),
            ]
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            let records = try readFatArchRecords(data)
            return try records.enumerated().map { index, record in
                let hint = try cmsSignatureLengthHint(at: index, in: cmsSignatureLengthHints)
                let codeDirectories = try prepareThinMachOCMSCodeDirectories(
                    record.data,
                    options: MachOSigningOptions(
                        bundleIdentifier: bundleIdentifier,
                        subjectCommonName: subjectCommonName,
                        teamIdentifier: teamIdentifier,
                        entitlementsXML: entitlementsXML,
                        entitlementsDER: entitlementsDER,
                        infoPlist: infoPlist,
                        resourceDirectory: resourceDirectory,
                        cmsSignature: Data(repeating: 0, count: hint),
                        adHoc: false,
                        codeDirectoryHashingMode: codeDirectoryHashingMode
                    )
                )
                return MachOCMSCodeDirectory(
                    architectureIndex: index,
                    codeDirectory: codeDirectories.primary,
                    alternateCodeDirectory: codeDirectories.alternate
                )
            }
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }

    /// Embeds detached CMS blobs into thin or universal Mach-O signatures.
    static func signWithCMSBlobs(
        _ data: Data,
        bundleIdentifier: String,
        subjectCommonName: String,
        teamIdentifier: String,
        entitlementsXML: String,
        entitlementsDER: Data,
        infoPlist: Data,
        resourceDirectory: Data,
        cmsSignatures: [Data],
        cmsSignatureLengthHints: [Int] = [],
        codeDirectoryHashingMode: CodeDirectoryHashingMode
    ) throws -> Data {
        guard !data.isEmpty else {
            throw RorkSignError.invalidMachO("Code signing received empty Mach-O data.")
        }
        guard !bundleIdentifier.isEmpty else {
            throw RorkSignError.invalidMachO("Code signing needs a bundle identifier.")
        }
        guard !cmsSignatures.isEmpty else {
            throw RorkSignError.cmsSigning("CMS signing needs at least one CMS blob.")
        }

        if let littleMagic = data.readUInt32LE(at: 0),
           littleMagic == Constants.mhMagic || littleMagic == Constants.mhMagic64 {
            guard cmsSignatures.count == 1 else {
                throw RorkSignError.cmsSigning("Thin Mach-O signing needs exactly one CMS blob.")
            }
            guard !cmsSignatures[0].isEmpty else {
                throw RorkSignError.cmsSigning("Thin Mach-O signing received an empty CMS blob.")
            }
            return try signThinMachO(
                data,
                options: MachOSigningOptions(
                    bundleIdentifier: bundleIdentifier,
                    subjectCommonName: subjectCommonName,
                    teamIdentifier: teamIdentifier,
                    entitlementsXML: entitlementsXML,
                    entitlementsDER: entitlementsDER,
                    infoPlist: infoPlist,
                    resourceDirectory: resourceDirectory,
                    cmsSignature: cmsSignatures[0],
                    reservedCMSLength: cmsSignatureLengthHints.indices.contains(0)
                        ? try cmsSignatureLengthHint(at: 0, in: cmsSignatureLengthHints)
                        : nil,
                    adHoc: false,
                    codeDirectoryHashingMode: codeDirectoryHashingMode
                )
            )
        }

        if let bigMagic = data.readUInt32BE(at: 0),
           bigMagic == Constants.fatMagic || bigMagic == Constants.fatMagic64 {
            return try signUniversalMachOWithCMSBlobs(
                data,
                magic: bigMagic,
                bundleIdentifier: bundleIdentifier,
                subjectCommonName: subjectCommonName,
                teamIdentifier: teamIdentifier,
                entitlementsXML: entitlementsXML,
                entitlementsDER: entitlementsDER,
                infoPlist: infoPlist,
                resourceDirectory: resourceDirectory,
                cmsSignatures: cmsSignatures,
                cmsSignatureLengthHints: cmsSignatureLengthHints,
                codeDirectoryHashingMode: codeDirectoryHashingMode
            )
        }

        throw RorkSignError.invalidMachO("Input is not a supported Mach-O file.")
    }
}

/// Produces the exact code prefix used for cache-key hashing.
private func thinSigningCacheInput(_ data: Data) throws -> Data {
    let layout = try readThinSigningLayout(data)
    var output = data
    let signatureCommandOffset: Int
    let codeLimit: UInt64

    if let existingSignatureCommandOffset = layout.codeSignatureCommandOffset {
        guard Int(layout.codeSignatureDataOffset) <= output.count else {
            throw RorkSignError.invalidMachO("Existing LC_CODE_SIGNATURE points past the file.")
        }
        signatureCommandOffset = existingSignatureCommandOffset
        codeLimit = UInt64(layout.codeSignatureDataOffset)
        output.removeSubrange(Int(codeLimit)..<output.count)
    } else {
        guard let firstContentOffset = layout.firstContentOffset,
              firstContentOffset >= layout.commandRegionEnd,
              firstContentOffset - layout.commandRegionEnd >= Constants.linkeditDataCommandSize else {
            throw RorkSignError.invalidMachO("Mach-O has no LC_CODE_SIGNATURE and no load-command space to add one.")
        }

        signatureCommandOffset = layout.commandRegionEnd
        try output.writeUInt32LE(Constants.lcCodeSignature, at: signatureCommandOffset)
        try output.writeUInt32LE(UInt32(Constants.linkeditDataCommandSize), at: signatureCommandOffset + 4)
        try output.writeUInt32LE(layout.header.commandCount + 1, at: 16)
        try output.writeUInt32LE(layout.header.commandSize + UInt32(Constants.linkeditDataCommandSize), at: 20)
        codeLimit = alignUp(UInt64(output.count), alignment: 16)
        output.append(Data(repeating: 0, count: Int(codeLimit) - output.count))
    }

    let newLength = codeLimit
    guard codeLimit <= UInt64(UInt32.max) else {
        throw RorkSignError.invalidMachO("Signed Mach-O is too large.")
    }
    try output.writeUInt32LE(UInt32(codeLimit), at: signatureCommandOffset + 8)
    try output.writeUInt32LE(0, at: signatureCommandOffset + 12)

    if let linkeditCommandOffset = layout.linkeditCommandOffset,
       layout.linkeditFileOffset < newLength {
        let linkeditFileSize = newLength - layout.linkeditFileOffset
        try output.writeUInt64LE(alignUp(linkeditFileSize, alignment: 4096), at: linkeditCommandOffset + 32)
        try output.writeUInt64LE(linkeditFileSize, at: linkeditCommandOffset + 48)
    }

    return output.subdata(in: 0..<Int(codeLimit))
}

private struct MachOSigningOptions {
    let bundleIdentifier: String
    let subjectCommonName: String
    let teamIdentifier: String
    let entitlementsXML: String
    let entitlementsDER: Data
    let infoPlist: Data
    let resourceDirectory: Data
    let cmsSignature: Data
    let reservedCMSLength: Int?
    let adHoc: Bool
    let codeDirectoryHashingMode: CodeDirectoryHashingMode

    init(
        bundleIdentifier: String,
        subjectCommonName: String,
        teamIdentifier: String = "",
        entitlementsXML: String,
        entitlementsDER: Data,
        infoPlist: Data,
        resourceDirectory: Data,
        cmsSignature: Data,
        reservedCMSLength: Int? = nil,
        adHoc: Bool,
        codeDirectoryHashingMode: CodeDirectoryHashingMode
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.subjectCommonName = subjectCommonName
        let trimmedTeamIdentifier = teamIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        self.teamIdentifier = trimmedTeamIdentifier.isEmpty
            ? CodeSignatureBuilder.inferTeamIdentifier(from: entitlementsXML)
            : trimmedTeamIdentifier
        self.entitlementsXML = entitlementsXML
        self.entitlementsDER = entitlementsDER
        self.infoPlist = infoPlist
        self.resourceDirectory = resourceDirectory
        self.cmsSignature = cmsSignature
        self.reservedCMSLength = reservedCMSLength
        self.adHoc = adHoc
        self.codeDirectoryHashingMode = codeDirectoryHashingMode
    }
}

private enum Constants {
    static let mhMagic: UInt32 = 0xfeedface
    static let mhMagic64: UInt32 = 0xfeedfacf
    static let fatMagic: UInt32 = 0xcafebabe
    static let fatMagic64: UInt32 = 0xcafebabf
    static let lcSegment64: UInt32 = 0x19
    static let lcCodeSignature: UInt32 = 0x1d
    static let lcLoadDylib: UInt32 = 0xc
    static let lcLoadWeakDylib: UInt32 = 0x80000018
    static let mhExecuteFileType: UInt32 = 2

    static let machHeader32Size = 28
    static let machHeader64Size = 32
    static let loadCommandSize = 8
    static let dylibCommandSize = 24
    static let linkeditDataCommandSize = 16
    static let segmentCommand64Size = 72
    static let section64Size = 80
    static let fatHeaderSize = 8
    static let fatArch32Size = 20
    static let fatArch64Size = 32
    static let csMagicEmbeddedSignature: UInt32 = 0xfade0cc0
    static let csMagicEmbeddedEntitlements: UInt32 = 0xfade7171
    static let csSlotEntitlements: UInt32 = 5
    static let csExecSegMainBinary: UInt64 = 0x1
    static let csExecSegAllowUnsigned: UInt64 = 0x10
}

private struct ThinHeader {
    let magic: UInt32
    let fileType: UInt32
    let commandCount: UInt32
    let commandSize: UInt32
    let is64Bit: Bool
}

private struct ThinSigningLayout {
    let header: ThinHeader
    let headerSize: Int
    let commandRegionEnd: Int
    var firstContentOffset: Int?
    var codeSignatureCommandOffset: Int?
    var codeSignatureDataOffset: UInt32 = 0
    var codeSignatureDataSize: UInt32 = 0
    var linkeditCommandOffset: Int?
    var linkeditFileOffset: UInt64 = 0
    var executableSegmentLimit: UInt64 = 0
    var embeddedInfoPlist: Data = Data()

    /// Returns the CodeDirectory executable-segment flags for this image.
    ///
    /// The flags are intentionally derived from the final entitlement XML, not
    /// from the old signature, because standalone signing can replace the
    /// entitlement set while keeping the Mach-O bytes otherwise unchanged.
    func executableSegmentFlags(entitlementsXML: String) -> UInt64 {
        guard header.fileType == Constants.mhExecuteFileType else {
            return 0
        }

        var flags = Constants.csExecSegMainBinary
        if entitlementBooleanValue(entitlementsXML, key: "get-task-allow") {
            flags |= Constants.csExecSegAllowUnsigned
        }
        return flags
    }

    /// Builds the CodeDirectory input after applying Mach-O-type signing policy.
    ///
    /// Non-`MH_EXECUTE` images omit XML and DER entitlement slots and clear
    /// executable-only flags. The original entitlement XML still feeds
    /// `teamIdentifier` through `MachOSigningOptions`, keeping the Team ID in
    /// CodeDirectory while treating dylibs and helper images as non-app code.
    func codeSignatureInput(
        code: Data,
        options: MachOSigningOptions,
        infoPlist: Data,
        cmsSignature: Data,
        adHoc: Bool
    ) -> CodeSignatureInput {
        let isMainExecutable = header.fileType == Constants.mhExecuteFileType
        let effectiveEntitlementsXML = isMainExecutable
            ? options.entitlementsXML
            : ""
        let effectiveEntitlementsDER = isMainExecutable
            ? options.entitlementsDER
            : Data()

        return CodeSignatureInput(
            code: code,
            bundleIdentifier: options.bundleIdentifier,
            subjectCommonName: options.subjectCommonName,
            teamIdentifier: options.teamIdentifier,
            entitlementsXML: effectiveEntitlementsXML,
            entitlementsDER: effectiveEntitlementsDER,
            infoPlist: infoPlist,
            resourceDirectory: options.resourceDirectory,
            executableSegmentLimit: executableSegmentLimit,
            executableSegmentFlags: executableSegmentFlags(entitlementsXML: effectiveEntitlementsXML),
            cmsSignature: cmsSignature,
            adHoc: adHoc,
            codeDirectoryHashingMode: options.codeDirectoryHashingMode
        )
    }
}

private struct FatArchRecord {
    var header: Data
    var data: Data
    var offset: UInt64
    var size: UInt64
    let alignPower: UInt32
}

private struct LoadCommandRecord {
    let offset: Int
    let command: UInt32
    let commandSize: Int
    let data: Data
}

/// Returns a non-negative placeholder CMS size for an architecture.
private func cmsSignatureLengthHint(at index: Int, in hints: [Int]) throws -> Int {
    guard hints.indices.contains(index) else {
        return 0
    }
    guard hints[index] >= 0 else {
        throw RorkSignError.cmsSigning("CMS signature length hints must be non-negative.")
    }
    return hints[index]
}

/// Parses the fixed Mach-O header and validates the declared load-command span.
private func readThinHeader(_ data: Data) throws -> ThinHeader {
    guard let magic = data.readUInt32LE(at: 0),
          magic == Constants.mhMagic || magic == Constants.mhMagic64 else {
        throw RorkSignError.invalidMachO("Unsupported Mach-O magic.")
    }

    let is64Bit = magic == Constants.mhMagic64
    let headerSize = is64Bit ? Constants.machHeader64Size : Constants.machHeader32Size
    guard data.containsRange(offset: 0, length: headerSize) else {
        throw RorkSignError.invalidMachO("Mach-O header is truncated.")
    }

    guard let fileType = data.readUInt32LE(at: 12),
          let commandCount = data.readUInt32LE(at: 16),
          let commandSize = data.readUInt32LE(at: 20) else {
        throw RorkSignError.invalidMachO("Mach-O header is malformed.")
    }
    guard data.containsRange(offset: headerSize, length: Int(commandSize)) else {
        throw RorkSignError.invalidMachO("Mach-O load-command region extends past the file.")
    }

    return ThinHeader(
        magic: magic,
        fileType: fileType,
        commandCount: commandCount,
        commandSize: commandSize,
        is64Bit: is64Bit
    )
}

/// Reads a thin Mach-O's high-level code-signature metadata.
private func readThinMachOInfo(_ data: Data) throws -> MachOInfo {
    let header = try readThinHeader(data)
    var hasCodeSignature = false
    var codeSignatureOffset: UInt32 = 0
    var codeSignatureSize: UInt32 = 0

    try forEachLoadCommand(in: data, header: header) { offset, command, commandSize in
        if command == Constants.lcCodeSignature {
            guard commandSize >= Constants.linkeditDataCommandSize else {
                throw RorkSignError.invalidMachO("LC_CODE_SIGNATURE command is truncated.")
            }
            guard let dataOffset = data.readUInt32LE(at: offset + 8),
                  let dataSize = data.readUInt32LE(at: offset + 12) else {
                throw RorkSignError.invalidMachO("LC_CODE_SIGNATURE payload is malformed.")
            }
            hasCodeSignature = true
            codeSignatureOffset = dataOffset
            codeSignatureSize = dataSize
        }
    }

    return MachOInfo(
        kind: header.is64Bit ? .machO64 : .machO32,
        magic: header.magic,
        fileType: header.fileType,
        architectureCount: 1,
        hasCodeSignature: hasCodeSignature,
        codeSignatureOffset: codeSignatureOffset,
        codeSignatureSize: codeSignatureSize
    )
}

/// Reads dynamic-library load commands from one thin Mach-O.
private func readThinDylibLoadCommands(_ data: Data) throws -> [MachODylibLoadCommand] {
    let header = try readThinHeader(data)
    var commands: [MachODylibLoadCommand] = []
    try forEachLoadCommand(in: data, header: header) { offset, command, commandSize in
        guard command == Constants.lcLoadDylib || command == Constants.lcLoadWeakDylib else {
            return
        }
        commands.append(
            MachODylibLoadCommand(
                path: try dylibPath(in: data, commandOffset: offset, commandSize: commandSize),
                weak: command == Constants.lcLoadWeakDylib
            )
        )
    }
    return commands
}

/// Adds one dynamic-library load command to a thin 64-bit Mach-O.
private func injectThinDylibLoadCommand(_ data: Data, path: String, weak: Bool) throws -> Data {
    let installName = try normalizedDylibInstallName(path)
    let existingCommands = try readThinDylibLoadCommands(data)
    if existingCommands.contains(where: { $0.path == installName }) {
        return data
    }

    let layout = try readThinSigningLayout(data)
    let command = try makeDylibCommand(path: installName, weak: weak)
    guard let firstContentOffset = layout.firstContentOffset,
          firstContentOffset >= layout.commandRegionEnd,
          firstContentOffset - layout.commandRegionEnd >= command.count else {
        throw RorkSignError.invalidMachO("Mach-O has no load-command space to add a dylib command.")
    }
    guard layout.header.commandCount < UInt32.max,
          UInt64(layout.header.commandSize) + UInt64(command.count) <= UInt64(UInt32.max) else {
        throw RorkSignError.invalidMachO("Mach-O load-command table is too large.")
    }

    var output = data
    output.replaceSubrange(layout.commandRegionEnd..<(layout.commandRegionEnd + command.count), with: command)
    try output.writeUInt32LE(layout.header.commandCount + 1, at: 16)
    try output.writeUInt32LE(layout.header.commandSize + UInt32(command.count), at: 20)
    return output
}

/// Removes matching dynamic-library load commands from one thin Mach-O.
private func removeThinDylibLoadCommands(_ data: Data, matching paths: Set<String>) throws -> Data {
    let header = try readThinHeader(data)
    let headerSize = header.is64Bit ? Constants.machHeader64Size : Constants.machHeader32Size
    let records = try loadCommandRecords(in: data, header: header)
    let keptRecords = try records.filter { record in
        guard record.command == Constants.lcLoadDylib || record.command == Constants.lcLoadWeakDylib else {
            return true
        }
        return !paths.contains(try dylibPath(in: data, commandOffset: record.offset, commandSize: record.commandSize))
    }
    guard keptRecords.count != records.count else {
        return data
    }

    let newCommandSize = keptRecords.reduce(0) { $0 + $1.commandSize }
    guard newCommandSize <= Int(header.commandSize) else {
        throw RorkSignError.invalidMachO("Mach-O load-command table is malformed.")
    }
    guard UInt32(exactly: keptRecords.count) != nil else {
        throw RorkSignError.invalidMachO("Mach-O load-command table is too large.")
    }

    var output = data
    var newCommands = Data()
    for record in keptRecords {
        newCommands.append(record.data)
    }
    output.replaceSubrange(headerSize..<(headerSize + newCommandSize), with: newCommands)
    output.replaceSubrange(
        (headerSize + newCommandSize)..<(headerSize + Int(header.commandSize)),
        with: Data(repeating: 0, count: Int(header.commandSize) - newCommandSize)
    )
    try output.writeUInt32LE(UInt32(keptRecords.count), at: 16)
    try output.writeUInt32LE(UInt32(newCommandSize), at: 20)
    return output
}

/// Copies load commands into independent records for table rebuilding.
private func loadCommandRecords(in data: Data, header: ThinHeader) throws -> [LoadCommandRecord] {
    var records: [LoadCommandRecord] = []
    try forEachLoadCommand(in: data, header: header) { offset, command, commandSize in
        records.append(
            LoadCommandRecord(
                offset: offset,
                command: command,
                commandSize: commandSize,
                data: data.subdata(in: offset..<(offset + commandSize))
            )
        )
    }
    return records
}

/// Builds the bytes for an `LC_LOAD_DYLIB`-family command.
private func makeDylibCommand(path: String, weak: Bool) throws -> Data {
    let pathBytes = Array(path.utf8)
    let rawSize = Constants.dylibCommandSize + pathBytes.count + 1
    let commandSize = Int(alignUp(UInt64(rawSize), alignment: 8))
    guard UInt32(exactly: commandSize) != nil else {
        throw RorkSignError.invalidMachO("Dylib load command is too large.")
    }

    var command = Data(repeating: 0, count: commandSize)
    try command.writeUInt32LE(weak ? Constants.lcLoadWeakDylib : Constants.lcLoadDylib, at: 0)
    try command.writeUInt32LE(UInt32(commandSize), at: 4)
    try command.writeUInt32LE(UInt32(Constants.dylibCommandSize), at: 8)
    command.replaceSubrange(
        Constants.dylibCommandSize..<(Constants.dylibCommandSize + pathBytes.count),
        with: pathBytes
    )
    return command
}

/// Reads the install name from an `LC_LOAD_DYLIB`-family command.
private func dylibPath(in data: Data, commandOffset: Int, commandSize: Int) throws -> String {
    guard commandSize >= Constants.dylibCommandSize,
          let nameOffsetValue = data.readUInt32LE(at: commandOffset + 8) else {
        throw RorkSignError.invalidMachO("Dylib load command is malformed.")
    }
    let nameOffset = Int(nameOffsetValue)
    guard nameOffset >= Constants.dylibCommandSize,
          nameOffset < commandSize,
          data.containsRange(offset: commandOffset + nameOffset, length: commandSize - nameOffset) else {
        throw RorkSignError.invalidMachO("Dylib load command name is outside the command.")
    }

    let start = commandOffset + nameOffset
    let end = commandOffset + commandSize
    let stringEnd = data[start..<end].firstIndex(of: 0) ?? end
    guard let path = String(data: data.subdata(in: start..<stringEnd), encoding: .utf8),
          !path.isEmpty else {
        throw RorkSignError.invalidMachO("Dylib load command name is not valid UTF-8.")
    }
    return path
}

/// Normalizes caller input for a load-command install name.
private func normalizedDylibInstallName(_ path: String) throws -> String {
    let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
        throw RorkSignError.invalidMachO("Dylib install name is empty.")
    }
    guard !trimmed.contains("\u{0}") else {
        throw RorkSignError.invalidMachO("Dylib install name contains a NUL byte.")
    }
    return trimmed
}

/// Builds the exact and convenience forms accepted for dylib removal.
private func dylibRemovalMatchSet(_ paths: [String]) -> Set<String> {
    var result: Set<String> = []
    for path in paths {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            continue
        }
        result.insert(trimmed)
        if !trimmed.contains("/") {
            result.insert("@executable_path/" + trimmed)
        }
    }
    return result
}

/// Returns the XML entitlement payload from a thin Mach-O, or an empty string
/// when the signature has no entitlement slot.
private func readThinEntitlementsXML(_ data: Data) throws -> String {
    let info = try readThinMachOInfo(data)
    guard info.hasCodeSignature, info.codeSignatureSize > 0 else {
        return ""
    }

    let signatureOffset = Int(info.codeSignatureOffset)
    let signatureSize = Int(info.codeSignatureSize)
    guard data.containsRange(offset: signatureOffset, length: signatureSize) else {
        throw RorkSignError.invalidMachO("LC_CODE_SIGNATURE points outside the file.")
    }

    let signature = data.subdata(in: signatureOffset..<(signatureOffset + signatureSize))
    guard let magic = signature.readUInt32BE(at: 0),
          magic == Constants.csMagicEmbeddedSignature else {
        return ""
    }
    guard let length = signature.readUInt32BE(at: 4),
          let count = signature.readUInt32BE(at: 8),
          length >= 12,
          Int(length) <= signature.count,
          signature.containsRange(offset: 12, length: Int(count) * 8),
          12 + Int(count) * 8 <= Int(length) else {
        throw RorkSignError.invalidMachO("Embedded code-signature SuperBlob is malformed.")
    }

    for index in 0..<Int(count) {
        let entryOffset = 12 + index * 8
        guard let slot = signature.readUInt32BE(at: entryOffset),
              let blobOffsetValue = signature.readUInt32BE(at: entryOffset + 4) else {
            throw RorkSignError.invalidMachO("Embedded code-signature index is malformed.")
        }
        guard slot == Constants.csSlotEntitlements else {
            continue
        }

        let blobOffset = Int(blobOffsetValue)
        guard let blobMagic = signature.readUInt32BE(at: blobOffset),
              let blobLength = signature.readUInt32BE(at: blobOffset + 4),
              blobMagic == Constants.csMagicEmbeddedEntitlements,
              blobLength >= 8,
              signature.containsRange(offset: blobOffset, length: Int(blobLength)),
              blobOffset + Int(blobLength) <= Int(length) else {
            throw RorkSignError.invalidMachO("Embedded entitlement blob is malformed.")
        }

        let payload = signature.subdata(in: (blobOffset + 8)..<(blobOffset + Int(blobLength)))
        guard let xml = String(data: payload, encoding: .utf8) else {
            throw RorkSignError.invalidEntitlements("Embedded entitlement XML is not valid UTF-8.")
        }
        return xml
    }

    return ""
}

/// Computes the places a thin 64-bit Mach-O needs mutated during signing.
private func readThinSigningLayout(_ data: Data) throws -> ThinSigningLayout {
    let header = try readThinHeader(data)
    guard header.is64Bit else {
        throw RorkSignError.invalidMachO("Code signing currently supports thin 64-bit Mach-O files.")
    }

    var layout = ThinSigningLayout(
        header: header,
        headerSize: Constants.machHeader64Size,
        commandRegionEnd: Constants.machHeader64Size + Int(header.commandSize)
    )

    try forEachLoadCommand(in: data, header: header) { offset, command, commandSize in
        if command == Constants.lcCodeSignature {
            guard commandSize >= Constants.linkeditDataCommandSize else {
                throw RorkSignError.invalidMachO("LC_CODE_SIGNATURE command is truncated.")
            }
            guard let dataOffset = data.readUInt32LE(at: offset + 8),
                  let dataSize = data.readUInt32LE(at: offset + 12) else {
                throw RorkSignError.invalidMachO("LC_CODE_SIGNATURE payload is malformed.")
            }
            layout.codeSignatureCommandOffset = offset
            layout.codeSignatureDataOffset = dataOffset
            layout.codeSignatureDataSize = dataSize
        } else if command == Constants.lcSegment64 && commandSize >= Constants.segmentCommand64Size {
            try readSegmentLayout(data, commandOffset: offset, commandSize: commandSize, layout: &layout)
        }
    }

    return layout
}

/// Iterates load commands with progress and bounds checks.
private func forEachLoadCommand(
    in data: Data,
    header: ThinHeader,
    body: (_ offset: Int, _ command: UInt32, _ commandSize: Int) throws -> Void
) throws {
    let headerSize = header.is64Bit ? Constants.machHeader64Size : Constants.machHeader32Size
    var offset = headerSize
    var consumed = 0
    let totalCommandSize = Int(header.commandSize)

    for _ in 0..<header.commandCount {
        guard consumed <= totalCommandSize,
              totalCommandSize - consumed >= Constants.loadCommandSize else {
            throw RorkSignError.invalidMachO("Mach-O load-command table ended early.")
        }

        guard let command = data.readUInt32LE(at: offset),
              let commandSizeValue = data.readUInt32LE(at: offset + 4) else {
            throw RorkSignError.invalidMachO("Mach-O load command is malformed.")
        }
        let commandSize = Int(commandSizeValue)
        guard commandSize >= Constants.loadCommandSize else {
            throw RorkSignError.invalidMachO("Mach-O load command has an invalid size.")
        }
        guard commandSize <= totalCommandSize - consumed,
              data.containsRange(offset: offset, length: commandSize) else {
            throw RorkSignError.invalidMachO("Mach-O load command extends past the command region.")
        }

        try body(offset, command, commandSize)
        offset += commandSize
        consumed += commandSize
    }
}

/// Extracts `LC_SEGMENT_64` metadata used by code signing.
///
/// The signer needs three independent pieces of segment state: the first file
/// content offset so it can add `LC_CODE_SIGNATURE` into available load-command
/// padding, the `__LINKEDIT` command so appended signatures update its file/vm
/// sizes, and the `__TEXT,__info_plist` section so standalone Mach-O signing can
/// still bind an embedded Info.plist through CSSLOT_INFOSLOT.
private func readSegmentLayout(
    _ data: Data,
    commandOffset: Int,
    commandSize: Int,
    layout: inout ThinSigningLayout
) throws {
    guard let vmSize = data.readUInt64LE(at: commandOffset + 32),
          let fileOffset = data.readUInt64LE(at: commandOffset + 40),
          let fileSize = data.readUInt64LE(at: commandOffset + 48),
          let sectionCount = data.readUInt32LE(at: commandOffset + 64) else {
        throw RorkSignError.invalidMachO("LC_SEGMENT_64 command is malformed.")
    }

    let isTextSegment = fixedNameEquals(data, offset: commandOffset + 8, name: "__TEXT")
    if fileOffset > UInt64(layout.commandRegionEnd), fileSize > 0 {
        layout.firstContentOffset = minimum(layout.firstContentOffset, Int(fileOffset))
    }
    if isTextSegment {
        layout.executableSegmentLimit = vmSize
    }
    if fixedNameEquals(data, offset: commandOffset + 8, name: "__LINKEDIT") {
        layout.linkeditCommandOffset = commandOffset
        layout.linkeditFileOffset = fileOffset
    }

    let sectionCapacity = (commandSize - Constants.segmentCommand64Size) / Constants.section64Size
    guard sectionCount <= UInt32(sectionCapacity) else {
        throw RorkSignError.invalidMachO("LC_SEGMENT_64 section table is truncated.")
    }

    let sectionTableOffset = commandOffset + Constants.segmentCommand64Size
    for sectionIndex in 0..<Int(sectionCount) {
        let sectionOffset = sectionTableOffset + sectionIndex * Constants.section64Size
        guard let sectionFileOffset = data.readUInt32LE(at: sectionOffset + 48),
              let sectionSize = data.readUInt64LE(at: sectionOffset + 40) else {
            throw RorkSignError.invalidMachO("LC_SEGMENT_64 section is malformed.")
        }
        if sectionFileOffset > UInt32(layout.commandRegionEnd), sectionSize > 0 {
            layout.firstContentOffset = minimum(layout.firstContentOffset, Int(sectionFileOffset))
        }
        if isTextSegment,
           fixedNameEquals(data, offset: sectionOffset, name: "__info_plist"),
           sectionSize <= UInt64(Int.max),
           data.containsRange(offset: Int(sectionFileOffset), length: Int(sectionSize)) {
            let infoOffset = Int(sectionFileOffset)
            let infoLength = Int(sectionSize)
            layout.embeddedInfoPlist = data.subdata(in: infoOffset..<(infoOffset + infoLength))
        }
    }
}

/// Reads only the fat header; slice details are validated when signing.
private func readUniversalInfo(_ data: Data) throws -> MachOInfo {
    guard let magic = data.readUInt32BE(at: 0),
          (magic == Constants.fatMagic || magic == Constants.fatMagic64),
          let count = data.readUInt32BE(at: 4) else {
        throw RorkSignError.invalidMachO("Unsupported universal Mach-O magic.")
    }

    let archSize = magic == Constants.fatMagic64 ? Constants.fatArch64Size : Constants.fatArch32Size
    guard count > 0 else {
        throw RorkSignError.invalidMachO("Universal Mach-O has no architectures.")
    }
    guard Int(count) <= (data.count - Swift.min(data.count, Constants.fatHeaderSize)) / archSize,
          data.containsRange(offset: Constants.fatHeaderSize, length: Int(count) * archSize) else {
        throw RorkSignError.invalidMachO("Universal Mach-O architecture table is truncated.")
    }

    return MachOInfo(
        kind: .universal,
        magic: magic,
        fileType: 0,
        architectureCount: count,
        hasCodeSignature: false,
        codeSignatureOffset: 0,
        codeSignatureSize: 0
    )
}

/// Rewrites one 64-bit Mach-O slice and appends a fresh SuperBlob.
private func signThinMachO(_ data: Data, options: MachOSigningOptions) throws -> Data {
    guard !data.isEmpty else {
        throw RorkSignError.invalidMachO("Code signing received empty Mach-O data.")
    }
    guard !options.bundleIdentifier.isEmpty else {
        throw RorkSignError.invalidMachO("Code signing needs a bundle identifier.")
    }

    let layout = try readThinSigningLayout(data)
    var output = data
    let signatureCommandOffset: Int
    let codeLimit: UInt64

    if let existingSignatureCommandOffset = layout.codeSignatureCommandOffset {
        guard Int(layout.codeSignatureDataOffset) <= output.count else {
            throw RorkSignError.invalidMachO("Existing LC_CODE_SIGNATURE points past the file.")
        }
        signatureCommandOffset = existingSignatureCommandOffset
        codeLimit = UInt64(layout.codeSignatureDataOffset)
        output.removeSubrange(Int(codeLimit)..<output.count)
    } else {
        guard let firstContentOffset = layout.firstContentOffset,
              firstContentOffset >= layout.commandRegionEnd,
              firstContentOffset - layout.commandRegionEnd >= Constants.linkeditDataCommandSize else {
            throw RorkSignError.invalidMachO("Mach-O has no LC_CODE_SIGNATURE and no load-command space to add one.")
        }

        signatureCommandOffset = layout.commandRegionEnd
        try output.writeUInt32LE(Constants.lcCodeSignature, at: signatureCommandOffset)
        try output.writeUInt32LE(UInt32(Constants.linkeditDataCommandSize), at: signatureCommandOffset + 4)
        try output.writeUInt32LE(layout.header.commandCount + 1, at: 16)
        try output.writeUInt32LE(layout.header.commandSize + UInt32(Constants.linkeditDataCommandSize), at: 20)
        codeLimit = alignUp(UInt64(output.count), alignment: 16)
        output.append(Data(repeating: 0, count: Int(codeLimit) - output.count))
    }

    func buildSignature(cmsSignature: Data = options.cmsSignature) throws -> Data {
        try CodeSignatureBuilder.buildCodeSignature(
            layout.codeSignatureInput(
                code: output.subdata(in: 0..<Int(codeLimit)),
                options: options,
                infoPlist: options.infoPlist.isEmpty ? layout.embeddedInfoPlist : options.infoPlist,
                cmsSignature: cmsSignature,
                adHoc: options.adHoc
            )
        )
    }

    let reservedSignatureSize: Int?
    if let reservedCMSLength = options.reservedCMSLength {
        guard reservedCMSLength >= options.cmsSignature.count else {
            throw RorkSignError.cmsSigning("Reserved CMS length is smaller than the CMS blob.")
        }
        reservedSignatureSize = try buildSignature(
            cmsSignature: Data(repeating: 0, count: reservedCMSLength)
        ).count
    } else {
        reservedSignatureSize = nil
    }

    let compatibleMinimumSize = try compatibleCodeSignatureReservationSize(codeLimit: codeLimit)

    func layoutSignatureSize(for signatureSize: Int) -> Int {
        let existingSignatureSize = Int(layout.codeSignatureDataSize)
        let requestedSignatureSize = reservedSignatureSize ?? 0
        return max(signatureSize, requestedSignatureSize, existingSignatureSize, compatibleMinimumSize)
    }

    /// Keeps `LC_CODE_SIGNATURE` and `__LINKEDIT` consistent with the signature
    /// reservation used for the next signing pass.
    ///
    /// Exact-width checks prevent a valid 64-bit file offset from being
    /// truncated when this code runs with 32-bit `Int` on WebAssembly.
    func writeSignatureLayout(signatureSize: Int) throws {
        let newLength = codeLimit + UInt64(signatureSize)
        guard UInt32(exactly: codeLimit) != nil,
              UInt32(exactly: signatureSize) != nil else {
            throw RorkSignError.invalidMachO("Signed Mach-O is too large.")
        }
        try output.writeUInt32LE(UInt32(codeLimit), at: signatureCommandOffset + 8)
        try output.writeUInt32LE(UInt32(signatureSize), at: signatureCommandOffset + 12)

        if let linkeditCommandOffset = layout.linkeditCommandOffset,
           layout.linkeditFileOffset < newLength {
            let linkeditFileSize = newLength - layout.linkeditFileOffset
            try output.writeUInt64LE(alignUp(linkeditFileSize, alignment: 4096), at: linkeditCommandOffset + 32)
            try output.writeUInt64LE(linkeditFileSize, at: linkeditCommandOffset + 48)
        }
    }

    try writeSignatureLayout(signatureSize: 0)
    var signature = try buildSignature()
    let firstLayoutSize = layoutSignatureSize(for: signature.count)
    guard firstLayoutSize >= signature.count else {
        throw RorkSignError.cmsSigning("Reserved code-signature size is smaller than the generated signature.")
    }
    guard codeLimit + UInt64(signature.count) <= UInt64(UInt32.max) else {
        throw RorkSignError.invalidMachO("Signed Mach-O is too large.")
    }
    try writeSignatureLayout(signatureSize: firstLayoutSize)
    signature = try buildSignature()

    let finalLayoutSize = layoutSignatureSize(for: signature.count)
    guard finalLayoutSize >= signature.count else {
        throw RorkSignError.cmsSigning("Reserved code-signature size is smaller than the generated signature.")
    }

    let newLength = codeLimit + UInt64(finalLayoutSize)
    guard newLength <= UInt64(UInt32.max) else {
        throw RorkSignError.invalidMachO("Signed Mach-O is too large.")
    }
    output.append(Data(repeating: 0, count: Int(newLength) - output.count))
    output.replaceSubrange(Int(codeLimit)..<(Int(codeLimit) + signature.count), with: signature)
    try writeSignatureLayout(signatureSize: finalLayoutSize)

    return output
}

/// Produces the CodeDirectories for CMS signing with a placeholder CMS size.
private func prepareThinMachOCMSCodeDirectories(
    _ data: Data,
    options: MachOSigningOptions
) throws -> CodeSignatureBuilder.CodeDirectories {
    guard !data.isEmpty else {
        throw RorkSignError.invalidMachO("Code signing received empty Mach-O data.")
    }
    guard !options.bundleIdentifier.isEmpty else {
        throw RorkSignError.invalidMachO("Code signing needs a bundle identifier.")
    }

    let layout = try readThinSigningLayout(data)
    var output = data
    let signatureCommandOffset: Int
    let codeLimit: UInt64

    if let existingSignatureCommandOffset = layout.codeSignatureCommandOffset {
        guard Int(layout.codeSignatureDataOffset) <= output.count else {
            throw RorkSignError.invalidMachO("Existing LC_CODE_SIGNATURE points past the file.")
        }
        signatureCommandOffset = existingSignatureCommandOffset
        codeLimit = UInt64(layout.codeSignatureDataOffset)
        output.removeSubrange(Int(codeLimit)..<output.count)
    } else {
        guard let firstContentOffset = layout.firstContentOffset,
              firstContentOffset >= layout.commandRegionEnd,
              firstContentOffset - layout.commandRegionEnd >= Constants.linkeditDataCommandSize else {
            throw RorkSignError.invalidMachO("Mach-O has no LC_CODE_SIGNATURE and no load-command space to add one.")
        }

        signatureCommandOffset = layout.commandRegionEnd
        try output.writeUInt32LE(Constants.lcCodeSignature, at: signatureCommandOffset)
        try output.writeUInt32LE(UInt32(Constants.linkeditDataCommandSize), at: signatureCommandOffset + 4)
        try output.writeUInt32LE(layout.header.commandCount + 1, at: 16)
        try output.writeUInt32LE(layout.header.commandSize + UInt32(Constants.linkeditDataCommandSize), at: 20)
        codeLimit = alignUp(UInt64(output.count), alignment: 16)
        output.append(Data(repeating: 0, count: Int(codeLimit) - output.count))
    }

    func buildPlaceholderSignature() throws -> Data {
        try CodeSignatureBuilder.buildCodeSignature(
            layout.codeSignatureInput(
                code: output.subdata(in: 0..<Int(codeLimit)),
                options: options,
                infoPlist: options.infoPlist.isEmpty ? layout.embeddedInfoPlist : options.infoPlist,
                cmsSignature: options.cmsSignature,
                adHoc: false
            )
        )
    }

    let compatibleMinimumSize = try compatibleCodeSignatureReservationSize(codeLimit: codeLimit)

    func layoutSignatureSize(for signatureSize: Int) -> Int {
        max(signatureSize, Int(layout.codeSignatureDataSize), compatibleMinimumSize)
    }

    /// Keeps `LC_CODE_SIGNATURE` and `__LINKEDIT` consistent with the ad-hoc
    /// signature reservation used for the next signing pass.
    ///
    /// Exact-width checks prevent a valid 64-bit file offset from being
    /// truncated when this code runs with 32-bit `Int` on WebAssembly.
    func writeSignatureLayout(signatureSize: Int) throws {
        let newLength = codeLimit + UInt64(signatureSize)
        guard UInt32(exactly: codeLimit) != nil,
              UInt32(exactly: signatureSize) != nil else {
            throw RorkSignError.invalidMachO("Signed Mach-O is too large.")
        }
        try output.writeUInt32LE(UInt32(codeLimit), at: signatureCommandOffset + 8)
        try output.writeUInt32LE(UInt32(signatureSize), at: signatureCommandOffset + 12)

        if let linkeditCommandOffset = layout.linkeditCommandOffset,
           layout.linkeditFileOffset < newLength {
            let linkeditFileSize = newLength - layout.linkeditFileOffset
            try output.writeUInt64LE(alignUp(linkeditFileSize, alignment: 4096), at: linkeditCommandOffset + 32)
            try output.writeUInt64LE(linkeditFileSize, at: linkeditCommandOffset + 48)
        }
    }

    try writeSignatureLayout(signatureSize: 0)
    let placeholderSignature = try buildPlaceholderSignature()
    try writeSignatureLayout(signatureSize: layoutSignatureSize(for: placeholderSignature.count))

    return try CodeSignatureBuilder.buildCodeDirectories(
        layout.codeSignatureInput(
            code: output.subdata(in: 0..<Int(codeLimit)),
            options: options,
            infoPlist: options.infoPlist.isEmpty ? layout.embeddedInfoPlist : options.infoPlist,
            cmsSignature: Data(),
            adHoc: false
        )
    )
}

/// Reads a boolean entitlement from XML without requiring the caller to parse
/// entitlements separately before signing.
private func entitlementBooleanValue(_ entitlementsXML: String, key: String) -> Bool {
    guard !entitlementsXML.isEmpty,
          let data = entitlementsXML.data(using: .utf8),
          let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
          let dictionary = plist as? [String: Any] else {
        return false
    }
    return dictionary[key] as? Bool == true
}

/// Signs each thin slice in a universal binary and rebuilds the fat container.
private func signUniversalMachO(
    _ data: Data,
    magic: UInt32,
    options: MachOSigningOptions
) throws -> Data {
    guard options.adHoc, options.cmsSignature.isEmpty else {
        throw RorkSignError.cmsSigning("Universal CMS signing must use per-architecture CMS blobs.")
    }

    var records = try readFatArchRecords(data)
    for index in records.indices {
        records[index].data = try signThinMachO(records[index].data, options: options)
    }
    return try rebuildUniversalMachO(magic: magic, records: records)
}

/// Signs each universal Mach-O slice with its corresponding CMS blob.
private func signUniversalMachOWithCMSBlobs(
    _ data: Data,
    magic: UInt32,
    bundleIdentifier: String,
    subjectCommonName: String,
    teamIdentifier: String,
    entitlementsXML: String,
    entitlementsDER: Data,
    infoPlist: Data,
    resourceDirectory: Data,
    cmsSignatures: [Data],
    cmsSignatureLengthHints: [Int],
    codeDirectoryHashingMode: CodeDirectoryHashingMode
) throws -> Data {
    var records = try readFatArchRecords(data)
    guard cmsSignatures.count == records.count else {
        throw RorkSignError.cmsSigning("Universal Mach-O signing needs one CMS blob per architecture.")
    }

    for index in records.indices {
        guard !cmsSignatures[index].isEmpty else {
            throw RorkSignError.cmsSigning("Universal Mach-O signing received an empty CMS blob.")
        }
        records[index].data = try signThinMachO(
            records[index].data,
            options: MachOSigningOptions(
                bundleIdentifier: bundleIdentifier,
                subjectCommonName: subjectCommonName,
                teamIdentifier: teamIdentifier,
                entitlementsXML: entitlementsXML,
                entitlementsDER: entitlementsDER,
                infoPlist: infoPlist,
                resourceDirectory: resourceDirectory,
                cmsSignature: cmsSignatures[index],
                reservedCMSLength: cmsSignatureLengthHints.indices.contains(index)
                    ? try cmsSignatureLengthHint(at: index, in: cmsSignatureLengthHints)
                    : nil,
                adHoc: false,
                codeDirectoryHashingMode: codeDirectoryHashingMode
            )
        )
    }
    return try rebuildUniversalMachO(magic: magic, records: records)
}

/// Reads fat-archive entries and copies each slice into an independent buffer.
private func readFatArchRecords(_ data: Data) throws -> [FatArchRecord] {
    guard let magic = data.readUInt32BE(at: 0),
          (magic == Constants.fatMagic || magic == Constants.fatMagic64),
          let count = data.readUInt32BE(at: 4) else {
        throw RorkSignError.invalidMachO("Unsupported universal Mach-O magic.")
    }

    let fat64 = magic == Constants.fatMagic64
    let archSize = fat64 ? Constants.fatArch64Size : Constants.fatArch32Size
    guard count > 0 else {
        throw RorkSignError.invalidMachO("Universal Mach-O has no architectures.")
    }
    guard Int(count) <= (data.count - Swift.min(data.count, Constants.fatHeaderSize)) / archSize,
          data.containsRange(offset: Constants.fatHeaderSize, length: Int(count) * archSize) else {
        throw RorkSignError.invalidMachO("Universal Mach-O architecture table is truncated.")
    }

    var records: [FatArchRecord] = []
    records.reserveCapacity(Int(count))
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
              let alignPower = data.readUInt32BE(at: entryOffset + (fat64 ? 24 : 16)) else {
            throw RorkSignError.invalidMachO("Universal Mach-O architecture record is malformed.")
        }
        guard offset <= UInt64(data.count), size <= UInt64(data.count) - offset else {
            throw RorkSignError.invalidMachO("Universal Mach-O architecture slice is outside the file.")
        }

        let header = data.subdata(in: entryOffset..<(entryOffset + archSize))
        let slice = data.subdata(in: Int(offset)..<Int(offset + size))
        records.append(
            FatArchRecord(
                header: header,
                data: slice,
                offset: offset,
                size: size,
                alignPower: alignPower
            )
        )
    }
    return records
}

/// Rebuilds a universal Mach-O after per-slice sizes changed.
private func rebuildUniversalMachO(magic: UInt32, records: [FatArchRecord]) throws -> Data {
    let fat64 = magic == Constants.fatMagic64
    let archSize = fat64 ? Constants.fatArch64Size : Constants.fatArch32Size
    let headerSize = UInt64(Constants.fatHeaderSize + records.count * archSize)
    var rewrittenRecords = records
    var nextOffset = headerSize

    for index in rewrittenRecords.indices {
        let alignPower = rewrittenRecords[index].alignPower
        guard alignPower < 63 else {
            throw RorkSignError.invalidMachO("Universal Mach-O architecture alignment is too large.")
        }
        let alignment = UInt64(1) << alignPower
        nextOffset = alignUp(nextOffset, alignment: alignment)

        guard fat64 || (
            UInt32(exactly: nextOffset) != nil
                && UInt32(exactly: rewrittenRecords[index].data.count) != nil
        ) else {
            throw RorkSignError.invalidMachO("Signed universal Mach-O is too large for 32-bit fat headers.")
        }

        rewrittenRecords[index].offset = nextOffset
        rewrittenRecords[index].size = UInt64(rewrittenRecords[index].data.count)
        guard rewrittenRecords[index].size <= UInt64.max - nextOffset else {
            throw RorkSignError.invalidMachO("Signed universal Mach-O size overflowed.")
        }
        nextOffset += rewrittenRecords[index].size
    }

    guard nextOffset <= UInt64(Int.max) else {
        throw RorkSignError.invalidMachO("Signed universal Mach-O is too large for this platform.")
    }

    var output = Data(repeating: 0, count: Int(nextOffset))
    try output.writeUInt32BE(magic, at: 0)
    try output.writeUInt32BE(UInt32(rewrittenRecords.count), at: 4)

    for (index, record) in rewrittenRecords.enumerated() {
        let entryOffset = Constants.fatHeaderSize + index * archSize
        output.replaceSubrange(entryOffset..<(entryOffset + record.header.count), with: record.header)
        if fat64 {
            try output.writeUInt64BE(record.offset, at: entryOffset + 8)
            try output.writeUInt64BE(record.size, at: entryOffset + 16)
        } else {
            try output.writeUInt32BE(UInt32(record.offset), at: entryOffset + 8)
            try output.writeUInt32BE(UInt32(record.size), at: entryOffset + 12)
        }
        output.replaceSubrange(Int(record.offset)..<Int(record.offset + record.size), with: record.data)
    }

    return output
}

private func alignUp(_ value: UInt64, alignment: UInt64) -> UInt64 {
    guard alignment != 0 else {
        return value
    }
    let remainder = value % alignment
    return remainder == 0 ? value : value + alignment - remainder
}

/// Returns a conservative `LC_CODE_SIGNATURE` reservation for resigned code.
///
/// The embedded SuperBlob is usually smaller than this region. Keeping spare
/// zero padding preserves the layout shape used by established iOS signing
/// tools and leaves room for hash-table growth when code size changes.
private func compatibleCodeSignatureReservationSize(codeLimit: UInt64) throws -> Int {
    let bytesPerPageHashPair: UInt64 = 20 + 32
    let paddingBudget: UInt64 = 32 * 1024
    let pageCountWithSentinel = (codeLimit / 4096) + 1
    guard pageCountWithSentinel <= UInt64.max / bytesPerPageHashPair else {
        throw RorkSignError.invalidMachO("Code-signature reservation overflowed.")
    }

    let hashBudget = pageCountWithSentinel * bytesPerPageHashPair
    let alignedHashBudget = alignUp(hashBudget, alignment: 4096)
    guard alignedHashBudget <= UInt64(Int.max) - paddingBudget else {
        throw RorkSignError.invalidMachO("Code-signature reservation is too large.")
    }
    return Int(alignedHashBudget + paddingBudget)
}

private func fixedNameEquals(_ data: Data, offset: Int, name: String) -> Bool {
    guard data.containsRange(offset: offset, length: 16) else {
        return false
    }
    var expected = Array(name.utf8.prefix(16))
    if expected.count < 16 {
        expected.append(contentsOf: repeatElement(0, count: 16 - expected.count))
    }
    return Array(data[offset..<(offset + 16)]) == expected
}

private func minimum(_ lhs: Int?, _ rhs: Int) -> Int {
    guard let lhs else {
        return rhs
    }
    return Swift.min(lhs, rhs)
}
