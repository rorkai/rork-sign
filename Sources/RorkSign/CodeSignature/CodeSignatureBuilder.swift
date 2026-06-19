#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

struct CodeSignatureInput {
    /// Bytes that are covered by the CodeDirectory page hashes.
    ///
    /// For embedded Mach-O signatures this is the final executable prefix up to
    /// `LC_CODE_SIGNATURE.dataoff`, after all load-command bookkeeping has been
    /// written and before the SuperBlob is appended.
    let code: Data

    /// Identifier stored in the CodeDirectory and designated requirement.
    let bundleIdentifier: String

    /// Certificate subject common name used in identity-backed requirements.
    ///
    /// Ad-hoc signatures leave this empty, which produces an empty requirements
    /// SuperBlob. Certificate-backed signatures use it to bind the designated
    /// requirement to the selected leaf identity.
    let subjectCommonName: String

    /// Team identifier serialized into the CodeDirectory.
    ///
    /// Most signatures infer this from the entitlement plist. Callers can set
    /// it explicitly when the embedded entitlement shape intentionally differs
    /// from the provisioning-profile entitlement source, such as compatibility
    /// signatures for non-`MH_EXECUTE` images.
    let teamIdentifier: String

    /// XML entitlement plist embedded in CSSLOT_ENTITLEMENTS.
    let entitlementsXML: String

    /// DER entitlement plist embedded in CSSLOT_DER_ENTITLEMENTS.
    let entitlementsDER: Data

    /// Serialized `Info.plist` data hashed into CSSLOT_INFOSLOT for bundle main
    /// executables.
    let infoPlist: Data

    /// Serialized `_CodeSignature/CodeResources` data hashed into
    /// CSSLOT_RESOURCEDIR for bundle main executables.
    let resourceDirectory: Data

    /// CodeDirectory `execSegLimit` field.
    ///
    /// Apple uses the executable segment fields to describe the part of an
    /// executable image that is expected to run as code. For app main
    /// executables this is normally the `__TEXT` segment's virtual size; for
    /// frameworks, dylibs, and synthetic test fixtures it is `0`.
    let executableSegmentLimit: UInt64

    /// CodeDirectory `execSegFlags` field.
    ///
    /// Main executables carry `CS_EXECSEG_MAIN_BINARY`. When a main executable's
    /// entitlement plist contains `get-task-allow = true`, the signer also
    /// records `CS_EXECSEG_ALLOW_UNSIGNED`, matching Apple's development-signing
    /// shape. Non-main Mach-O images keep this field clear.
    let executableSegmentFlags: UInt64

    /// CMS SignedData payload. Empty for ad-hoc signatures.
    let cmsSignature: Data

    /// Whether the CodeDirectory should carry the ad-hoc flag.
    let adHoc: Bool

    /// Digest layout for the CodeDirectory blobs embedded in the SuperBlob.
    let codeDirectoryHashingMode: CodeDirectoryHashingMode
}

/// Builds Apple embedded code-signature blobs.
///
/// This type owns only deterministic Apple format encoding: CodeDirectory,
/// Requirements, XML entitlements, DER entitlements, optional CMS BlobWrapper,
/// and the enclosing SuperBlob. Cryptographic digesting is delegated to Swift
/// Crypto so the formatter stays testable byte-for-byte.
enum CodeSignatureBuilder {
    /// Pair of CodeDirectory blobs embedded into the same SuperBlob.
    ///
    /// The primary directory is the CMS payload. In compatible mode it is SHA-1
    /// and `alternate` is SHA-256; in SHA-256-only mode, `primary` is SHA-256
    /// and `alternate` is empty.
    struct CodeDirectories {
        /// Slot `CSSLOT_CODEDIRECTORY`.
        let primary: Data

        /// Slot `CSSLOT_ALTERNATE_CODEDIRECTORIES`, or empty when the selected
        /// hashing mode emits a single primary CodeDirectory.
        let alternate: Data
    }

    /// Builds just the CodeDirectory blob.
    ///
    /// Identity-backed signing later needs this as the digest input for CMS;
    /// ad-hoc signing usually calls `buildCodeSignature(_:)` instead.
    static func buildCodeDirectory(_ input: CodeSignatureInput) throws -> Data {
        try buildCodeDirectories(input).primary
    }

    /// Builds the primary and alternate CodeDirectories for one signature.
    ///
    /// The selected `CodeDirectoryHashingMode` controls whether this emits the
    /// compatibility pair (SHA-1 primary plus SHA-256 alternate) or a single
    /// SHA-256 primary directory. CMS signing always signs `primary`.
    static func buildCodeDirectories(_ input: CodeSignatureInput) throws -> CodeDirectories {
        guard !input.code.isEmpty else {
            throw RorkSignError.invalidMachO("Code signing needs code bytes.")
        }
        guard !input.bundleIdentifier.isEmpty else {
            throw RorkSignError.invalidMachO("Code signing needs a bundle identifier.")
        }

        let requirements = buildRequirementsBlob(
            bundleIdentifier: input.bundleIdentifier,
            subjectCommonName: input.subjectCommonName
        )
        let entitlements = buildEntitlementsBlob(input.entitlementsXML)
        let derEntitlements = buildDEREntitlementsBlob(input.entitlementsDER)

        let sha256CodeDirectory = buildCodeDirectoryBlob(
            input,
            specialHashes: specialHashes(
                input: input,
                requirements: requirements,
                entitlements: entitlements,
                derEntitlements: derEntitlements,
                hashKind: .sha256
            ),
            hashKind: .sha256
        )

        switch input.codeDirectoryHashingMode {
        case .compatible:
            return CodeDirectories(
                primary: buildCodeDirectoryBlob(
                    input,
                    specialHashes: specialHashes(
                        input: input,
                        requirements: requirements,
                        entitlements: entitlements,
                        derEntitlements: derEntitlements,
                        hashKind: .sha1
                    ),
                    hashKind: .sha1
                ),
                alternate: sha256CodeDirectory
            )
        case .sha256Only:
            return CodeDirectories(
                primary: sha256CodeDirectory,
                alternate: Data()
            )
        }
    }

    static func buildCodeSignature(_ input: CodeSignatureInput) throws -> Data {
        let codeDirectories = try buildCodeDirectories(input)
        let requirements = buildRequirementsBlob(
            bundleIdentifier: input.bundleIdentifier,
            subjectCommonName: input.subjectCommonName
        )
        let entitlements = buildEntitlementsBlob(input.entitlementsXML)
        let derEntitlements = buildDEREntitlementsBlob(input.entitlementsDER)
        let cmsSignature = buildCMSBlob(input.cmsSignature)

        return buildSuperBlob([
            IndexedBlob(slot: Constants.csslotCodeDirectory, data: codeDirectories.primary),
            IndexedBlob(slot: Constants.csslotRequirements, data: requirements),
            IndexedBlob(slot: Constants.csslotEntitlements, data: entitlements),
            IndexedBlob(slot: Constants.csslotDEREntitlements, data: derEntitlements),
            IndexedBlob(slot: Constants.csslotAlternateCodeDirectories, data: codeDirectories.alternate),
            IndexedBlob(slot: Constants.csslotSignature, data: cmsSignature),
        ])
    }

    /// Extracts the Apple team identifier from entitlement XML.
    ///
    /// Provisioning-profile entitlements normally carry
    /// `com.apple.developer.team-identifier`; older or synthetic profiles may
    /// only carry `application-identifier`, whose prefix before the first dot is
    /// the team identifier. Returning an empty string keeps ad-hoc or
    /// entitlement-free signatures compact and matches Apple's zero
    /// `teamOffset` shape.
    static func inferTeamIdentifier(from entitlementsXML: String) -> String {
        guard !entitlementsXML.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let data = entitlementsXML.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dictionary = plist as? [String: Any] else {
            return ""
        }

        if let team = trimmedString(dictionary["com.apple.developer.team-identifier"]) {
            return team
        }
        guard let applicationIdentifier = trimmedString(dictionary["application-identifier"]),
              let dotIndex = applicationIdentifier.firstIndex(of: "."),
              dotIndex > applicationIdentifier.startIndex else {
            return ""
        }
        return String(applicationIdentifier[..<dotIndex])
    }
}

private enum Constants {
    static let csmagicCodeDirectory: UInt32 = 0xfade0c02
    static let csmagicEmbeddedSignature: UInt32 = 0xfade0cc0
    static let csmagicRequirement: UInt32 = 0xfade0c00
    static let csmagicRequirements: UInt32 = 0xfade0c01
    static let csmagicEmbeddedEntitlements: UInt32 = 0xfade7171
    static let csmagicEmbeddedDEREntitlements: UInt32 = 0xfade7172
    static let csmagicBlobWrapper: UInt32 = 0xfade0b01

    static let csslotCodeDirectory: UInt32 = 0
    static let csslotInfo: UInt32 = 1
    static let csslotRequirements: UInt32 = 2
    static let csslotResourceDirectory: UInt32 = 3
    static let csslotEntitlements: UInt32 = 5
    static let csslotDEREntitlements: UInt32 = 7
    static let csslotAlternateCodeDirectories: UInt32 = 0x1000
    static let csslotSignature: UInt32 = 0x10000

    static let secDesignatedRequirementType: UInt32 = 3

    static let csSupportsExecSeg: UInt32 = 0x20400
    static let csAdHoc: UInt32 = 0x0002
}

private struct SpecialSlotHash {
    let slot: UInt32
    let digest: Data
}

private struct IndexedBlob {
    let slot: UInt32
    let data: Data
}

private enum CodeDirectoryHashKind {
    case sha1
    case sha256

    var size: Int {
        switch self {
        case .sha1:
            return 20
        case .sha256:
            return 32
        }
    }

    var type: UInt8 {
        switch self {
        case .sha1:
            return 1
        case .sha256:
            return 2
        }
    }

    func digest(_ data: Data) -> Data {
        switch self {
        case .sha1:
            return Data(Insecure.SHA1.hash(data: data))
        case .sha256:
            return Data(SHA256.hash(data: data))
        }
    }
}

private func specialHashes(
    input: CodeSignatureInput,
    requirements: Data,
    entitlements: Data,
    derEntitlements: Data,
    hashKind: CodeDirectoryHashKind
) -> [SpecialSlotHash] {
    var specialHashes: [SpecialSlotHash] = [
        SpecialSlotHash(slot: Constants.csslotRequirements, digest: hashKind.digest(requirements)),
    ]
    if !input.infoPlist.isEmpty {
        specialHashes.append(SpecialSlotHash(slot: Constants.csslotInfo, digest: hashKind.digest(input.infoPlist)))
    }
    if !input.resourceDirectory.isEmpty {
        specialHashes.append(SpecialSlotHash(slot: Constants.csslotResourceDirectory, digest: hashKind.digest(input.resourceDirectory)))
    }
    if !entitlements.isEmpty {
        specialHashes.append(SpecialSlotHash(slot: Constants.csslotEntitlements, digest: hashKind.digest(entitlements)))
    }
    if !derEntitlements.isEmpty {
        specialHashes.append(SpecialSlotHash(slot: Constants.csslotDEREntitlements, digest: hashKind.digest(derEntitlements)))
    }
    return specialHashes
}

private func buildCodeDirectoryBlob(
    _ input: CodeSignatureInput,
    specialHashes: [SpecialSlotHash],
    hashKind: CodeDirectoryHashKind
) -> Data {
    let hashSize = hashKind.size
    let pageShift: UInt8 = 12
    let pageSize = 1 << Int(pageShift)
    let headerLength = 88

    let fullPages = input.code.count / pageSize
    let remainingBytes = input.code.count % pageSize
    let codeSlots = fullPages + (remainingBytes > 0 ? 1 : 0)
    let specialSlots = Int(specialHashes.map(\.slot).max() ?? 0)
    let explicitTeamIdentifier = input.teamIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
    let teamIdentifier = explicitTeamIdentifier.isEmpty
        ? CodeSignatureBuilder.inferTeamIdentifier(from: input.entitlementsXML)
        : explicitTeamIdentifier
    let identifierOffset = headerLength
    let identifierLength = input.bundleIdentifier.utf8.count + 1
    let teamOffset = teamIdentifier.isEmpty ? 0 : identifierOffset + identifierLength
    let teamLength = teamIdentifier.isEmpty ? 0 : teamIdentifier.utf8.count + 1
    let hashOffset = headerLength + identifierLength + teamLength + specialSlots * hashSize
    let length = hashOffset + codeSlots * hashSize

    var output = Data()
    output.reserveCapacity(length)
    output.appendUInt32BE(Constants.csmagicCodeDirectory)
    output.appendUInt32BE(UInt32(length))
    output.appendUInt32BE(Constants.csSupportsExecSeg)
    output.appendUInt32BE(input.adHoc ? Constants.csAdHoc : 0)
    output.appendUInt32BE(UInt32(hashOffset))
    output.appendUInt32BE(UInt32(identifierOffset))
    output.appendUInt32BE(UInt32(specialSlots))
    output.appendUInt32BE(UInt32(codeSlots))
    output.appendUInt32BE(UInt32(input.code.count))
    output.appendUInt8(UInt8(hashSize))
    output.appendUInt8(hashKind.type)
    output.appendUInt8(0)
    output.appendUInt8(pageShift)
    output.appendUInt32BE(0)
    output.appendUInt32BE(0)
    output.appendUInt32BE(UInt32(teamOffset))
    output.appendUInt32BE(0)
    output.appendUInt64BE(0)
    output.appendUInt64BE(0)
    output.appendUInt64BE(input.executableSegmentLimit)
    output.appendUInt64BE(input.executableSegmentFlags)
    output.append(Data(input.bundleIdentifier.utf8))
    output.appendUInt8(0)
    if !teamIdentifier.isEmpty {
        output.append(Data(teamIdentifier.utf8))
        output.appendUInt8(0)
    }

    var specialSlotStorage = Data(repeating: 0, count: specialSlots * hashSize)
    for hash in specialHashes where hash.slot > 0 && Int(hash.slot) <= specialSlots && hash.digest.count == hashSize {
        let storageIndex = specialSlots - Int(hash.slot)
        specialSlotStorage.replaceSubrange(
            (storageIndex * hashSize)..<((storageIndex + 1) * hashSize),
            with: hash.digest
        )
    }
    output.append(specialSlotStorage)

    for page in 0..<fullPages {
        let start = page * pageSize
        output.append(hashKind.digest(input.code.subdata(in: start..<(start + pageSize))))
    }
    if remainingBytes > 0 {
        let start = fullPages * pageSize
        output.append(hashKind.digest(input.code.subdata(in: start..<(start + remainingBytes))))
    }

    return output
}

private func buildRequirementsBlob(bundleIdentifier: String, subjectCommonName: String) -> Data {
    guard !bundleIdentifier.isEmpty,
          !subjectCommonName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        var empty = Data()
        empty.appendUInt32BE(Constants.csmagicRequirements)
        empty.appendUInt32BE(12)
        empty.appendUInt32BE(0)
        return empty
    }

    var requirementPayload = Data()
    requirementPayload.append(Data([
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x02,
    ]))
    requirementPayload.appendUInt32BE(UInt32(bundleIdentifier.utf8.count))
    requirementPayload.append(paddedStringBytes(bundleIdentifier))
    requirementPayload.append(Data([
        0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x0f,
        0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x0b,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0a,
        0x73, 0x75, 0x62, 0x6a,
        0x65, 0x63, 0x74, 0x2e,
        0x43, 0x4e, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ]))
    requirementPayload.appendUInt32BE(UInt32(subjectCommonName.utf8.count))
    requirementPayload.append(paddedStringBytes(subjectCommonName))
    requirementPayload.append(Data([
        0x00, 0x00, 0x00, 0x0e,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x0a,
        0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x63, 0x64, 0x06,
        0x02, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]))
    while requirementPayload.count % 4 != 0 {
        requirementPayload.appendUInt8(0)
    }

    let requirement = blob(Constants.csmagicRequirement, payload: requirementPayload)
    let count: UInt32 = 1
    let indexOffset: UInt32 = 12
    let requirementOffset = indexOffset + count * 8
    let length = requirementOffset + UInt32(requirement.count)

    var output = Data()
    output.appendUInt32BE(Constants.csmagicRequirements)
    output.appendUInt32BE(length)
    output.appendUInt32BE(count)
    output.appendUInt32BE(Constants.secDesignatedRequirementType)
    output.appendUInt32BE(requirementOffset)
    output.append(requirement)
    return output
}

private func paddedStringBytes(_ value: String) -> Data {
    var output = Data(value.utf8)
    while !output.count.isMultiple(of: 4) {
        output.appendUInt8(0)
    }
    return output
}

private func buildEntitlementsBlob(_ entitlementsXML: String) -> Data {
    guard !entitlementsXML.isEmpty else {
        return Data()
    }
    return blob(Constants.csmagicEmbeddedEntitlements, payload: Data(entitlementsXML.utf8))
}

private func buildDEREntitlementsBlob(_ entitlementsDER: Data) -> Data {
    guard !entitlementsDER.isEmpty else {
        return Data()
    }
    return blob(Constants.csmagicEmbeddedDEREntitlements, payload: entitlementsDER)
}

private func buildCMSBlob(_ cmsSignature: Data) -> Data {
    guard !cmsSignature.isEmpty else {
        return Data()
    }
    return blob(Constants.csmagicBlobWrapper, payload: cmsSignature)
}

private func blob(_ magic: UInt32, payload: Data) -> Data {
    var output = Data()
    output.reserveCapacity(payload.count + 8)
    output.appendUInt32BE(magic)
    output.appendUInt32BE(UInt32(payload.count + 8))
    output.append(payload)
    return output
}

private func buildSuperBlob(_ blobs: [IndexedBlob]) -> Data {
    let filteredBlobs = blobs.filter { !$0.data.isEmpty }
    let headerLength = 12 + filteredBlobs.count * 8
    var offset = headerLength
    let offsets = filteredBlobs.map { blob -> Int in
        defer {
            offset += blob.data.count
        }
        return offset
    }

    var output = Data()
    output.reserveCapacity(offset)
    output.appendUInt32BE(Constants.csmagicEmbeddedSignature)
    output.appendUInt32BE(UInt32(offset))
    output.appendUInt32BE(UInt32(filteredBlobs.count))
    for (index, blob) in filteredBlobs.enumerated() {
        output.appendUInt32BE(blob.slot)
        output.appendUInt32BE(UInt32(offsets[index]))
    }
    for blob in filteredBlobs {
        output.append(blob.data)
    }
    return output
}

private func trimmedString(_ value: Any?) -> String? {
    guard let string = value as? String else {
        return nil
    }
    let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
}
