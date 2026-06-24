import Foundation
import RorkSign

/// CodeDirectory digest layout exposed to Objective-C callers.
///
/// The Objective-C facade uses an `Int`-backed enum because Swift enums with
/// associated values or non-integer raw values cannot be represented in
/// generated Objective-C headers.
@objc(RKCodeDirectoryHashingMode)
public enum CodeDirectoryHashingModeObjC: Int {
    /// Emit a SHA-1 primary CodeDirectory and a SHA-256 alternate CodeDirectory.
    case compatible

    /// Emit one SHA-256 primary CodeDirectory and no alternate CodeDirectory.
    case sha256Only

    var coreValue: RorkSign.CodeDirectoryHashingMode {
        switch self {
        case .compatible:
            return .compatible
        case .sha256Only:
            return .sha256Only
        }
    }
}

/// Signing diagnostic level exposed to Objective-C callbacks.
@objc(RKSigningDiagnosticLevel)
public enum SigningDiagnosticLevelObjC: Int {
    /// High-level signing progress and preflight metadata.
    case info

    /// Detailed path-level events such as sealed bundles and cache hits.
    case debug

    init(_ level: RorkSign.SigningDiagnosticLevel) {
        switch level {
        case .info:
            self = .info
        case .debug:
            self = .debug
        }
    }
}

/// Logging verbosity exposed to Objective-C signing options.
///
/// Objective-C integrations cannot pass SwiftLog's `Logger` struct directly.
/// Instead they choose a facade log level and route matching messages through a
/// block or object conforming to `RKSigningLogger`.
@objc(RKSigningLogLevel)
public enum SigningLogLevelObjC: Int {
    /// Do not emit signing diagnostics.
    case none

    /// Emit high-level signing progress and preflight metadata.
    case info

    /// Emit info logs plus detailed path-level signing events.
    case debug

    func includes(_ level: RorkSign.SigningDiagnosticLevel) -> Bool {
        switch (self, level) {
        case (.none, _):
            return false
        case (.info, .info):
            return true
        case (.info, .debug):
            return false
        case (.debug, _):
            return true
        }
    }
}

/// Objective-C logging sink for signing diagnostics.
///
/// Use this protocol when an integration wants an object-oriented logger rather
/// than a block. Messages are already rendered by the Swift signer.
@objc(RKSigningLogger)
public protocol SigningLoggerObjC: AnyObject {
    /// Receives one rendered signing log line.
    @objc(signingDidLogMessage:level:)
    func signingDidLogMessage(_ message: String, level: SigningDiagnosticLevelObjC)
}

/// Bridges Objective-C logging sinks into the Swift signing diagnostics sink.
private func signingDiagnostics(
    logLevel: SigningLogLevelObjC,
    logHandler: ((SigningDiagnosticLevelObjC, String) -> Void)?,
    logger: SigningLoggerObjC?
) -> RorkSign.SigningDiagnostics {
    guard logLevel != .none, logHandler != nil || logger != nil else {
        return .disabled
    }

    return RorkSign.SigningDiagnostics(eventHandler: { level, message in
        guard logLevel.includes(level) else {
            return
        }

        let objcLevel = SigningDiagnosticLevelObjC(level)
        logHandler?(objcLevel, message)
        logger?.signingDidLogMessage(message, level: objcLevel)
    })
}

/// ZIP compression mode used when writing IPA archives.
@objc(RKArchiveCompressionMode)
public enum ArchiveCompressionModeObjC: Int {
    /// Store files without compression.
    case stored

    /// Compress regular files with ZIP Deflate.
    case deflated

    var coreValue: RorkSign.ArchiveCompressionMode {
        switch self {
        case .stored:
            return .stored
        case .deflated:
            return .deflated
        }
    }
}

/// Persistent cache configuration for bundle and IPA signing.
///
/// Cache entries store fully signed Mach-O outputs keyed by every input that
/// changes the final signature. Set `readExistingEntries` to `false` to force a
/// rebuild while still refreshing the cache for later signing runs.
@objc(RKSigningCacheOptions)
public final class SigningCacheOptionsObjC: NSObject {
    /// Directory where signed Mach-O cache entries are stored.
    @objc public let directoryURL: URL

    /// Whether existing entries may be reused.
    @objc public let readExistingEntries: Bool

    /// Creates cache options for bundle-style signing.
    @objc(initWithDirectoryURL:readExistingEntries:)
    public init(directoryURL: URL, readExistingEntries: Bool) {
        self.directoryURL = directoryURL
        self.readExistingEntries = readExistingEntries
        super.init()
    }

    var coreValue: RorkSign.SigningCacheOptions {
        RorkSign.SigningCacheOptions(directoryURL: directoryURL, readExistingEntries: readExistingEntries)
    }
}

/// A dylib that should be copied into the app and loaded by the root executable.
///
/// This mirrors `BundleDylibInjection` using Objective-C-compatible Foundation
/// types. When `installName` is `nil`, the signer uses
/// `@executable_path/<source basename>`.
@objc(RKDylibInjection)
public final class DylibInjectionObjC: NSObject {
    /// Existing dylib file to copy into the root app bundle.
    @objc public let sourceURL: URL

    /// Install name written into the root executable load command.
    @objc public let installName: String?

    /// Whether the load command should be weak.
    @objc public let isWeak: Bool

    /// Creates a dylib injection request.
    @objc(initWithSourceURL:installName:isWeak:)
    public init(sourceURL: URL, installName: String?, isWeak: Bool) {
        self.sourceURL = sourceURL
        self.installName = installName
        self.isWeak = isWeak
        super.init()
    }

    var coreValue: RorkSign.BundleDylibInjection {
        RorkSign.BundleDylibInjection(sourceURL: sourceURL, installName: installName, weak: isWeak)
    }
}

/// One dynamic-library load command declared by a Mach-O image.
@objc(RKDylibLoadCommand)
public final class DylibLoadCommandObjC: NSObject {
    /// Dynamic-library install name referenced by dyld.
    @objc public let path: String

    /// Whether this is an `LC_LOAD_WEAK_DYLIB` command.
    @objc public let isWeak: Bool

    /// Wraps a Swift dylib load-command report for Objective-C consumers.
    init(_ command: RorkSign.MachODylibLoadCommand) {
        path = command.path
        isWeak = command.weak
        super.init()
    }
}

/// A decoded provisioning profile that can be reused across Objective-C calls.
@objc(RKProvisioningProfile)
public final class ProvisioningProfileObjC: NSObject {
    let coreValue: RorkSign.ProvisioningProfile

    /// Team identifier used for application identifiers and code-signing assets.
    @objc public let teamIdentifier: String

    /// XML plist containing the profile's `Entitlements` dictionary.
    @objc public let entitlementsXML: String

    /// `application-identifier` entitlement, if present.
    @objc public let applicationIdentifier: String?

    /// Profile expiration date, if the plist provides one.
    @objc public let expirationDate: Date?

    /// DER-encoded developer certificates embedded in the profile.
    @objc public let developerCertificatesDER: [Data]

    /// Bundle identifier pattern authorized by the profile's App ID.
    @objc public let authorizedBundleIdentifier: String?

    /// Explicit authorized bundle identifier, or `nil` for wildcard profiles.
    @objc public let explicitAuthorizedBundleIdentifier: String?

    /// Whether the profile uses a wildcard App ID.
    @objc public let usesWildcardBundleIdentifier: Bool

    /// Wraps a decoded Swift provisioning profile without reparsing its plist.
    init(_ profile: RorkSign.ProvisioningProfile) {
        coreValue = profile
        teamIdentifier = profile.teamIdentifier
        entitlementsXML = profile.entitlementsXML
        applicationIdentifier = profile.applicationIdentifier
        expirationDate = profile.expirationDate
        developerCertificatesDER = profile.developerCertificatesDER
        authorizedBundleIdentifier = profile.authorizedBundleIdentifier
        explicitAuthorizedBundleIdentifier = profile.explicitAuthorizedBundleIdentifier
        usesWildcardBundleIdentifier = profile.usesWildcardBundleIdentifier
        super.init()
    }

    /// Returns whether the profile is expired at `date`.
    @objc(isExpiredAtDate:)
    public func isExpired(at date: Date) -> Bool {
        coreValue.isExpired(at: date)
    }

    /// Returns whether the profile authorizes `bundleIdentifier`.
    @objc(supportsBundleIdentifier:)
    public func supportsBundleIdentifier(_ bundleIdentifier: String) -> Bool {
        coreValue.supportsBundleIdentifier(bundleIdentifier)
    }

    /// Returns whether the profile embeds the supplied DER-encoded developer certificate.
    @objc(containsDeveloperCertificateDER:)
    public func containsDeveloperCertificateDER(_ certificateDER: Data) -> Bool {
        coreValue.containsDeveloperCertificateDER(certificateDER)
    }

    /// Returns whether the profile contains the identity's leaf certificate.
    @objc(containsDeveloperCertificateForIdentity:)
    public func containsDeveloperCertificate(for identity: SigningIdentityObjC) -> Bool {
        coreValue.containsDeveloperCertificate(for: identity.coreValue)
    }
}

/// Role of a provisioned bundle found during app-signing inspection.
@objc(RKAppProvisioningKind)
public enum AppProvisioningKindObjC: Int {
    /// The root `.app` bundle passed to the inspector or signer.
    case rootApp

    /// An embedded app extension bundle.
    case appExtension

    /// An embedded Apple Watch app bundle.
    case watchApp

    /// Another embedded `.app` bundle that is not detected as a Watch app.
    case nestedApp

    init(_ kind: RorkSign.AppProvisioningKind) {
        switch kind {
        case .rootApp:
            self = .rootApp
        case .appExtension:
            self = .appExtension
        case .watchApp:
            self = .watchApp
        case .nestedApp:
            self = .nestedApp
        }
    }
}

/// One provisioned bundle that app signing would rewrite.
@objc(RKAppProvisioningRequirement)
public final class AppProvisioningRequirementObjC: NSObject {
    /// Bundle URL on disk.
    @objc public let url: URL

    /// Root-bundle-relative path, or `.` for the root bundle.
    @objc public let relativePath: String

    /// Bundle identifier currently stored in `Info.plist`.
    @objc public let originalBundleIdentifier: String

    /// Bundle identifier app signing would write before signing.
    @objc public let rewrittenBundleIdentifier: String

    /// Provisioning role for this bundle.
    @objc public let kind: AppProvisioningKindObjC

    /// Whether this bundle is detected as an Apple Watch app.
    @objc public let isWatchBundle: Bool

    /// Rewritten associated bundle identifier when the bundle declares one.
    @objc public let associatedBundleIdentifier: String?

    /// `CFBundleExecutable` value, when present.
    @objc public let executableName: String?

    init(_ requirement: RorkSign.AppProvisioningRequirement) {
        url = requirement.url
        relativePath = requirement.relativePath
        originalBundleIdentifier = requirement.originalBundleIdentifier
        rewrittenBundleIdentifier = requirement.rewrittenBundleIdentifier
        kind = AppProvisioningKindObjC(requirement.kind)
        isWatchBundle = requirement.isWatchBundle
        associatedBundleIdentifier = requirement.associatedBundleIdentifier
        executableName = requirement.executableName
        super.init()
    }
}

/// Read-only app-signing inspection report for Objective-C callers.
@objc(RKAppInspectionReport)
public final class AppInspectionReportObjC: NSObject {
    /// Root app bundle that was inspected.
    @objc public let rootBundleURL: URL

    /// Root bundle identifier currently stored in `Info.plist`.
    @objc public let rootBundleIdentifier: String

    /// Replacement root bundle identifier used for the inspection.
    @objc public let replacementBundleIdentifier: String

    /// Provisioned app-style bundles found in app-signing order.
    @objc public let provisioningRequirements: [AppProvisioningRequirementObjC]

    /// Rewritten bundle identifiers that need root/per-bundle profile coverage.
    @objc public let rewrittenBundleIdentifiers: [String]

    /// Rewritten Watch app bundle identifiers that may need a Watch profile.
    @objc public let watchBundleIdentifiers: [String]

    /// Rewritten non-Watch extension identifiers that may need per-bundle profiles.
    @objc public let appExtensionBundleIdentifiers: [String]

    init(_ report: RorkSign.AppInspectionReport) {
        rootBundleURL = report.rootBundleURL
        rootBundleIdentifier = report.rootBundleIdentifier
        replacementBundleIdentifier = report.replacementBundleIdentifier
        provisioningRequirements = report.provisioningRequirements.map(AppProvisioningRequirementObjC.init)
        rewrittenBundleIdentifiers = report.rewrittenBundleIdentifiers
        watchBundleIdentifiers = report.watchBundleIdentifiers
        appExtensionBundleIdentifiers = report.appExtensionBundleIdentifiers
        super.init()
    }
}

/// A signing identity that can be reused by Objective-C callers.
///
/// The object owns the Swift identity material internally. Public properties
/// expose safe diagnostics; private-key bytes are intentionally not surfaced.
@objc(RKSigningIdentity)
public final class SigningIdentityObjC: NSObject {
    let coreValue: RorkSign.SigningIdentity

    /// DER-encoded leaf certificate.
    @objc public var certificateDER: Data {
        coreValue.certificateDER
    }

    /// DER-encoded additional certificates carried by the identity.
    @objc public var additionalCertificatesDER: [Data] {
        coreValue.additionalCertificatesDER
    }

    /// Apple team identifier associated with a provisioning-profile-backed identity.
    @objc public var teamIdentifier: String {
        coreValue.teamIdentifier
    }

    /// Leaf certificate subject common name.
    @objc public var subjectCommonName: String {
        coreValue.subjectCommonName
    }

    /// Leaf certificate expiration date.
    @objc public var certificateExpirationDate: Date {
        coreValue.certificateExpirationDate
    }

    /// Wraps an already-loaded Swift signing identity for Objective-C APIs.
    init(_ identity: RorkSign.SigningIdentity) {
        coreValue = identity
        super.init()
    }

    /// Loads a signing identity from DER/PEM certificate and DER/PEM private-key data.
    @objc(initWithCertificateData:privateKeyData:password:error:)
    public init(certificateData: Data, privateKeyData: Data, password: String?) throws {
        coreValue = try RorkSign.SigningIdentity(
            certificateData: certificateData,
            privateKeyData: privateKeyData,
            privateKeyPassword: password ?? ""
        )
        super.init()
    }

    /// Loads a signing identity from PEM certificate and PEM private-key strings.
    @objc(initWithCertificatePEM:privateKeyPEM:password:error:)
    public init(certificatePEM: String, privateKeyPEM: String, password: String?) throws {
        coreValue = try RorkSign.SigningIdentity(
            certificatePEM: certificatePEM,
            privateKeyPEM: privateKeyPEM,
            privateKeyPassword: password ?? ""
        )
        super.init()
    }

    /// Loads a signing identity from PKCS#12 data.
    @objc(initWithPKCS12Data:password:error:)
    public init(pkcs12Data: Data, password: String?) throws {
        coreValue = try RorkSign.SigningIdentity(pkcs12Data: pkcs12Data, password: password ?? "")
        super.init()
    }

    /// Loads a signing identity by matching a credential against a provisioning profile.
    @objc(initWithProvisioningProfileData:credentialData:password:error:)
    public init(provisioningProfileData: Data, credentialData: Data, password: String?) throws {
        coreValue = try RorkSign.SigningIdentity(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password ?? ""
        )
        super.init()
    }

    /// Loads a signing identity by matching a credential against a decoded profile.
    @objc(initWithProvisioningProfile:credentialData:password:error:)
    public init(provisioningProfile: ProvisioningProfileObjC, credentialData: Data, password: String?) throws {
        coreValue = try RorkSign.SigningIdentity(
            provisioningProfile: provisioningProfile.coreValue,
            credentialData: credentialData,
            password: password ?? ""
        )
        super.init()
    }
}

/// A pure Swift OCSP request model reusable from Objective-C.
@objc(RKOCSPRequest)
public final class OCSPRequestObjC: NSObject {
    let coreValue: RorkSign.OCSPRequest

    /// DER-encoded OCSP request payload.
    @objc public let derRepresentation: Data

    /// Responder URL discovered from Authority Information Access, if known.
    @objc public let responderURL: URL?

    /// Wraps a Swift OCSP request while preserving its DER representation.
    init(_ request: RorkSign.OCSPRequest) {
        coreValue = request
        derRepresentation = request.derRepresentation
        responderURL = request.responderURL
        super.init()
    }
}

/// Validation policy for matching and freshness-checking OCSP responses.
@objc(RKOCSPResponseValidationPolicy)
public final class OCSPResponseValidationPolicyObjC: NSObject {
    /// Date used for freshness and validity-window checks.
    @objc public var validationDate: Date

    /// Allowed clock skew around OCSP validity timestamps.
    @objc public var allowedClockSkew: TimeInterval

    /// Maximum accepted response age, or `nil` to disable the maximum-age check.
    @objc public var maximumAge: NSNumber?

    /// Whether `nextUpdate` must be present on the matching response.
    @objc public var requiresNextUpdate: Bool

    /// Creates the default OCSP validation policy.
    @objc public override init() {
        validationDate = Date()
        allowedClockSkew = 300
        maximumAge = nil
        requiresNextUpdate = false
        super.init()
    }

    var coreValue: RorkSign.OCSPResponseValidationPolicy {
        RorkSign.OCSPResponseValidationPolicy(
            validationDate: validationDate,
            allowedClockSkew: allowedClockSkew,
            maximumAge: maximumAge?.doubleValue,
            requiresNextUpdate: requiresNextUpdate
        )
    }
}

/// HTTP transport options for online OCSP requests.
@objc(RKOCSPHTTPOptions)
public final class OCSPHTTPOptionsObjC: NSObject {
    /// Request timeout in seconds.
    @objc public var timeout: TimeInterval

    /// Optional User-Agent header.
    @objc public var userAgent: String?

    /// Additional HTTP headers keyed by field name.
    @objc public var additionalHeaders: NSDictionary

    /// Creates the default OCSP HTTP options.
    @objc public override init() {
        timeout = 10
        userAgent = nil
        additionalHeaders = [:]
        super.init()
    }

    /// Builds the Swift HTTP options after validating dictionary-backed headers.
    func coreValue() throws -> RorkSign.OCSPHTTPOptions {
        try RorkSign.OCSPHTTPOptions(
            timeout: timeout,
            userAgent: userAgent,
            additionalHeaders: Self.stringDictionary(additionalHeaders, label: "additionalHeaders")
        )
    }

    /// Converts an Objective-C dictionary into the string map expected by Swift.
    private static func stringDictionary(_ dictionary: NSDictionary, label: String) throws -> [String: String] {
        var result: [String: String] = [:]
        for (key, value) in dictionary {
            guard let key = key as? String else {
                throw SignerBridgeError.invalidOption("\(label) contains a non-string key.")
            }
            guard let value = value as? String else {
                throw SignerBridgeError.invalidOption("\(label)[\(key)] is not NSString.")
            }
            result[key] = value
        }
        return result
    }
}

/// CodeDirectory bytes that must be signed for one Mach-O architecture.
@objc(RKMachOCMSCodeDirectory)
public final class MachOCMSCodeDirectoryObjC: NSObject {
    let coreValue: RorkSign.MachOCMSCodeDirectory

    /// Zero-based architecture index in the input.
    @objc public let architectureIndex: Int

    /// Primary CodeDirectory blob, including its header.
    @objc public let codeDirectory: Data

    /// Alternate CodeDirectory blob, if one will be embedded.
    @objc public let alternateCodeDirectory: Data

    /// Wraps a prepared Swift CodeDirectory signing input.
    init(_ value: RorkSign.MachOCMSCodeDirectory) {
        coreValue = value
        architectureIndex = value.architectureIndex
        codeDirectory = value.codeDirectory
        alternateCodeDirectory = value.alternateCodeDirectory
        super.init()
    }
}

/// One indexed blob inside an embedded Mach-O code-signature SuperBlob.
@objc(RKMachOCodeSignatureSlot)
public final class MachOCodeSignatureSlotObjC: NSObject {
    /// Raw `CSSLOT_*` index from the SuperBlob table.
    @objc public let slot: UInt32

    /// Complete slot blob, including its magic/length header.
    @objc public let data: Data

    /// Wraps one embedded code-signature slot extracted by the Swift engine.
    init(_ value: RorkSign.MachOCodeSignatureSlot) {
        slot = value.slot
        data = value.data
        super.init()
    }
}

/// Embedded code signature extracted from one Mach-O architecture.
@objc(RKMachOEmbeddedCodeSignature)
public final class MachOEmbeddedCodeSignatureObjC: NSObject {
    /// Zero-based architecture index in the input.
    @objc public let architectureIndex: Int

    /// Complete embedded-signature SuperBlob.
    @objc public let superBlob: Data

    /// Indexed blobs referenced by the SuperBlob table.
    @objc public let slots: [MachOCodeSignatureSlotObjC]

    /// Wraps one architecture's embedded code signature for Objective-C callers.
    init(_ value: RorkSign.MachOEmbeddedCodeSignature) {
        architectureIndex = value.architectureIndex
        superBlob = value.superBlob
        slots = value.slots.map(MachOCodeSignatureSlotObjC.init)
        super.init()
    }

    /// Returns the first slot with the given `CSSLOT_*` index.
    @objc(firstSlot:)
    public func firstSlot(_ slot: UInt32) -> MachOCodeSignatureSlotObjC? {
        slots.first { candidate in candidate.slot == slot }
    }
}

/// Options for ordinary bundle signing through the Objective-C facade.
///
/// Ordinary bundle signing preserves the bundle identifiers that are already on
/// disk. Use `AppSigningOptionsObjC` when an app must be rewritten
/// under a new root bundle identifier before signing.
@objc(RKBundleSigningOptions)
public final class BundleSigningOptionsObjC: NSObject {
    /// Entitlements applied to the root executable when no identifier-specific entry exists.
    @objc public var defaultEntitlementsXML: String

    /// Provisioning profile for the root bundle when no exact identifier entry exists.
    @objc public var rootProvisioningProfileData: Data?

    /// Entitlement plist XML keyed by `CFBundleIdentifier`.
    ///
    /// Values must be `NSString`.
    @objc public var entitlementsByBundleIdentifier: NSDictionary

    /// Provisioning profiles keyed by `CFBundleIdentifier`.
    ///
    /// Values must be `NSData`.
    @objc public var provisioningProfilesByBundleIdentifier: NSDictionary

    /// Whether selected provisioning profiles should be embedded before sealing resources.
    @objc public var embedProvisioningProfiles: Bool

    /// Compatibility alias for callers that sign with one root provisioning profile.
    @objc public var embedProvisioningProfile: Bool {
        get {
            embedProvisioningProfiles
        }
        set {
            embedProvisioningProfiles = newValue
        }
    }

    /// Identifier written to the root executable's CodeDirectory.
    ///
    /// When `nil`, the signer uses the root bundle's `CFBundleIdentifier`.
    /// The override does not rewrite `Info.plist` or nested-code identifiers.
    /// Surrounding whitespace is ignored; empty values and embedded NUL
    /// characters are rejected before signing.
    @objc public var codeDirectoryIdentifier: String?

    /// CodeDirectory digest layout used for every signed Mach-O.
    @objc public var codeDirectoryHashingMode: CodeDirectoryHashingModeObjC

    /// Dylibs copied into the root app and loaded by the root executable.
    @objc public var dylibInjections: [DylibInjectionObjC]

    /// Existing dylib load commands removed from the root executable before signing.
    @objc public var dylibLoadCommandsToRemove: [String]

    /// Optional persistent cache for signed Mach-O outputs.
    @objc public var signingCache: SigningCacheOptionsObjC?

    /// Minimum signing log level emitted through `logHandler` and `logger`.
    ///
    /// The default is `.none`, which keeps the library silent.
    @objc public var logLevel: SigningLogLevelObjC

    /// Optional block sink for rendered signing log lines.
    ///
    /// Set `logLevel` to `.info` or `.debug` to enable this callback.
    @objc public var logHandler: ((SigningDiagnosticLevelObjC, String) -> Void)?

    /// Optional object sink for rendered signing log lines.
    ///
    /// Set `logLevel` to `.info` or `.debug` to enable this logger.
    @objc public weak var logger: SigningLoggerObjC?

    /// Compatibility alias for the original diagnostic block.
    ///
    /// New callers should use `logLevel` plus `logHandler` or `logger`.
    @available(*, deprecated, message: "Use logLevel with logHandler or logger.")
    @objc public var diagnosticHandler: ((SigningDiagnosticLevelObjC, String) -> Void)? {
        get {
            logHandler
        }
        set {
            logHandler = newValue
            if newValue != nil, logLevel == .none {
                logLevel = .debug
            }
        }
    }

    /// Creates default options matching Swift `BundleSigningOptions`.
    @objc public override init() {
        defaultEntitlementsXML = ""
        rootProvisioningProfileData = nil
        entitlementsByBundleIdentifier = [:]
        provisioningProfilesByBundleIdentifier = [:]
        embedProvisioningProfiles = true
        codeDirectoryIdentifier = nil
        codeDirectoryHashingMode = .compatible
        dylibInjections = []
        dylibLoadCommandsToRemove = []
        signingCache = nil
        logLevel = .none
        logHandler = nil
        logger = nil
        super.init()
    }

    /// Builds Swift bundle-signing options after validating dictionary fields.
    func coreValue(rootProvisioningProfile: Data? = nil) throws -> RorkSign.BundleSigningOptions {
        try RorkSign.BundleSigningOptions(
            defaultEntitlementsXML: defaultEntitlementsXML,
            rootProvisioningProfile: rootProvisioningProfile ?? rootProvisioningProfileData,
            entitlementsByBundleIdentifier: BridgeDictionaries.stringByStringKey(
                entitlementsByBundleIdentifier,
                label: "entitlementsByBundleIdentifier"
            ),
            provisioningProfilesByBundleIdentifier: BridgeDictionaries.dataByStringKey(
                provisioningProfilesByBundleIdentifier,
                label: "provisioningProfilesByBundleIdentifier"
            ),
            embedProvisioningProfiles: embedProvisioningProfiles,
            codeDirectoryIdentifier: codeDirectoryIdentifier,
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue,
            dylibInjections: dylibInjections.map(\.coreValue),
            dylibLoadCommandsToRemove: dylibLoadCommandsToRemove,
            signingCache: signingCache?.coreValue,
            diagnostics: signingDiagnostics(
                logLevel: logLevel,
                logHandler: logHandler,
                logger: logger
            )
        )
    }

    /// Returns the preserve-identifier credential-signing defaults used by Swift.
    static func preserveIdentifierCredentialDefaults() -> BundleSigningOptionsObjC {
        let options = BundleSigningOptionsObjC()
        options.embedProvisioningProfiles = false
        options.codeDirectoryHashingMode = .sha256Only
        return options
    }

    /// Returns the defaults used by hosted bundle signing.
    static func hostedDefaults() -> BundleSigningOptionsObjC {
        let options = BundleSigningOptionsObjC()
        options.embedProvisioningProfiles = false
        options.codeDirectoryHashingMode = .compatible
        return options
    }
}

/// Options for signing a standalone `.framework` bundle through Objective-C.
///
/// Framework signing seals the framework resources and signs the framework
/// executable. It does not embed provisioning profiles or derive app
/// entitlements from provisioning profiles; set `entitlementsXML` only when the
/// framework intentionally needs entitlement input and its Mach-O type can
/// carry entitlement slots.
@objc(RKFrameworkSigningOptions)
public final class FrameworkSigningOptionsObjC: NSObject {
    /// Entitlement plist XML supplied for the framework executable.
    @objc public var entitlementsXML: String

    /// The identifier written to the framework executable's CodeDirectory.
    ///
    /// When `nil`, the signer uses the framework's `CFBundleIdentifier`.
    /// The override does not rewrite `Info.plist` or nested-code identifiers.
    /// Surrounding whitespace is ignored; empty values and embedded NUL
    /// characters are rejected before signing.
    @objc public var codeDirectoryIdentifier: String?

    /// CodeDirectory digest layout used for every signed Mach-O.
    @objc public var codeDirectoryHashingMode: CodeDirectoryHashingModeObjC

    /// Optional persistent cache for signed Mach-O outputs.
    @objc public var signingCache: SigningCacheOptionsObjC?

    /// Minimum signing log level emitted through `logHandler` and `logger`.
    ///
    /// The default is `.none`, which keeps the library silent.
    @objc public var logLevel: SigningLogLevelObjC

    /// Optional block sink for rendered signing log lines.
    ///
    /// Set `logLevel` to `.info` or `.debug` to enable this callback.
    @objc public var logHandler: ((SigningDiagnosticLevelObjC, String) -> Void)?

    /// Optional object sink for rendered signing log lines.
    ///
    /// Set `logLevel` to `.info` or `.debug` to enable this logger.
    @objc public weak var logger: SigningLoggerObjC?

    /// Compatibility alias matching the other signing option objects.
    ///
    /// New callers should use `logLevel` plus `logHandler` or `logger`.
    @available(*, deprecated, message: "Use logLevel with logHandler or logger.")
    @objc public var diagnosticHandler: ((SigningDiagnosticLevelObjC, String) -> Void)? {
        get {
            logHandler
        }
        set {
            logHandler = newValue
            if newValue != nil, logLevel == .none {
                logLevel = .debug
            }
        }
    }

    /// Creates default framework-signing options.
    @objc public override init() {
        entitlementsXML = ""
        codeDirectoryIdentifier = nil
        codeDirectoryHashingMode = .compatible
        signingCache = nil
        logLevel = .none
        logHandler = nil
        logger = nil
        super.init()
    }

    /// Builds Swift framework-signing options from Objective-C-compatible fields.
    func coreValue() -> RorkSign.FrameworkSigningOptions {
        var options = RorkSign.FrameworkSigningOptions(
            entitlementsXML: entitlementsXML,
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue,
            signingCache: signingCache?.coreValue,
            diagnostics: signingDiagnostics(
                logLevel: logLevel,
                logHandler: logHandler,
                logger: logger
            )
        )
        options.codeDirectoryIdentifier = codeDirectoryIdentifier
        return options
    }
}

/// Options for hosted bundle signing through the Objective-C facade.
///
/// Hosted signing temporarily copies an already-installed host executable into
/// a guest bundle, signs that copy as the root executable under the host bundle
/// identifier, signs the original guest executable under the same identifier,
/// then restores the guest `Info.plist` and removes the temporary stub. The
/// output is for hosted runtime loading, not standalone installation.
@objc(RKHostedBundleSigningOptions)
public final class HostedBundleSigningOptionsObjC: NSObject {
    /// Host executable copied into the bundle as a temporary signing stub.
    @objc public var hostExecutableURL: URL

    /// Host identifier used by the temporary stub and original guest executable.
    @objc public var hostBundleIdentifier: String

    /// Plain filename for the copied host executable inside the guest bundle.
    @objc public var stubExecutableName: String

    /// Full bundle-signing options used during the temporary signing pass.
    ///
    /// The default options do not embed provisioning profiles. The credential
    /// signing method supplies its `provisioningProfileData` as the root
    /// provisioning profile when this nested option object leaves it empty.
    /// Hosted signing replaces its root CodeDirectory identifier with
    /// `hostBundleIdentifier`.
    @objc public var bundleSigningOptions: BundleSigningOptionsObjC

    /// Creates hosted bundle-signing options.
    @objc(initWithHostExecutableURL:hostBundleIdentifier:)
    public init(hostExecutableURL: URL, hostBundleIdentifier: String) {
        self.hostExecutableURL = hostExecutableURL
        self.hostBundleIdentifier = hostBundleIdentifier
        stubExecutableName = "HostedSigningStub"
        bundleSigningOptions = BundleSigningOptionsObjC.hostedDefaults()
        super.init()
    }

    /// Builds Swift hosted-bundle signing options from Objective-C-compatible fields.
    func coreValue(rootProvisioningProfile: Data? = nil) throws -> RorkSign.HostedBundleSigningOptions {
        try RorkSign.HostedBundleSigningOptions(
            hostExecutableURL: hostExecutableURL,
            hostBundleIdentifier: hostBundleIdentifier,
            stubExecutableName: stubExecutableName,
            bundleSigningOptions: bundleSigningOptions.coreValue(rootProvisioningProfile: rootProvisioningProfile)
        )
    }
}

/// Options for rewriting and signing an app bundle for installation.
///
/// App signing re-homes the app under `bundleIdentifier`, rewrites nested
/// bundle identifiers, embeds the selected profiles, seals resources, and then
/// signs code inside-out.
@objc(RKAppSigningOptions)
public final class AppSigningOptionsObjC: NSObject {
    /// Replacement bundle identifier for the root app.
    @objc public var bundleIdentifier: String

    /// Provisioning profiles keyed by rewritten `CFBundleIdentifier`.
    ///
    /// Values must be `NSData`. Objective-C exposes this as `NSDictionary`
    /// because generated Swift headers cannot express the full
    /// `[String: Data]` generic shape as a stable Objective-C contract.
    @objc public var provisioningProfilesByBundleIdentifier: NSDictionary

    /// Fallback provisioning profile for embedded Apple Watch apps.
    @objc public var watchProvisioningProfileData: Data?

    /// App-group identifiers forced into non-Watch app entitlements.
    @objc public var appGroupIdentifiers: [String]

    /// Explicit entitlement plist XML for the rewritten root executable.
    @objc public var rootEntitlementsXML: String

    /// Bundle-local entitlements plist filename for unsigned artifacts.
    @objc public var entitlementsResourceName: String?

    /// Replacement display name for the root app.
    @objc public var displayName: String?

    /// Replacement version written to both bundle-version fields.
    @objc public var bundleVersion: String?

    /// Replacement `MinimumOSVersion` for the root app.
    @objc public var minimumOSVersion: String?

    /// Enables iOS Files app document browser integration in the root app.
    @objc public var enableDocuments: Bool

    /// Removes root `PlugIns` and `Extensions` directories before signing.
    @objc public var removeExtensions: Bool

    /// Removes embedded Watch app directories before signing.
    @objc public var removeWatchApps: Bool

    /// Removes `UISupportedDevices` from the root app's `Info.plist`.
    @objc public var removeUISupportedDevices: Bool

    /// Files written relative to the root app bundle before resources are sealed.
    ///
    /// Keys must be safe bundle-relative paths and values must be `NSData`.
    /// Existing files at the same paths are replaced.
    @objc public var additionalBundleFiles: NSDictionary

    /// Whether selected provisioning profiles should be embedded before sealing resources.
    @objc public var embedProvisioningProfiles: Bool

    /// Dylibs copied into the root app and loaded by the root executable.
    @objc public var dylibInjections: [DylibInjectionObjC]

    /// Existing dylib load commands removed from the root executable before signing.
    @objc public var dylibLoadCommandsToRemove: [String]

    /// CodeDirectory digest layout used for every signed Mach-O.
    @objc public var codeDirectoryHashingMode: CodeDirectoryHashingModeObjC

    /// Optional persistent cache for signed Mach-O outputs.
    @objc public var signingCache: SigningCacheOptionsObjC?

    /// Minimum signing log level emitted through `logHandler` and `logger`.
    ///
    /// The default is `.none`, which keeps the library silent.
    @objc public var logLevel: SigningLogLevelObjC

    /// Optional block sink for rendered signing log lines.
    ///
    /// Set `logLevel` to `.info` or `.debug` to enable this callback.
    @objc public var logHandler: ((SigningDiagnosticLevelObjC, String) -> Void)?

    /// Optional object sink for rendered signing log lines.
    ///
    /// Set `logLevel` to `.info` or `.debug` to enable this logger.
    @objc public weak var logger: SigningLoggerObjC?

    /// Compatibility alias for the original diagnostic block.
    ///
    /// New callers should use `logLevel` plus `logHandler` or `logger`.
    @available(*, deprecated, message: "Use logLevel with logHandler or logger.")
    @objc public var diagnosticHandler: ((SigningDiagnosticLevelObjC, String) -> Void)? {
        get {
            logHandler
        }
        set {
            logHandler = newValue
            if newValue != nil, logLevel == .none {
                logLevel = .debug
            }
        }
    }

    /// Creates app-signing options for the required replacement bundle identifier.
    @objc(initWithBundleIdentifier:)
    public init(bundleIdentifier: String) {
        self.bundleIdentifier = bundleIdentifier
        provisioningProfilesByBundleIdentifier = [:]
        watchProvisioningProfileData = nil
        appGroupIdentifiers = []
        rootEntitlementsXML = ""
        entitlementsResourceName = nil
        displayName = nil
        bundleVersion = nil
        minimumOSVersion = nil
        enableDocuments = false
        removeExtensions = false
        removeWatchApps = false
        removeUISupportedDevices = false
        additionalBundleFiles = [:]
        embedProvisioningProfiles = true
        dylibInjections = []
        dylibLoadCommandsToRemove = []
        codeDirectoryHashingMode = .sha256Only
        signingCache = nil
        logLevel = .none
        logHandler = nil
        logger = nil
        super.init()
    }

    /// Builds Swift app-signing options after validating profile maps.
    func coreValue(rootProvisioningProfile: Data? = nil) throws -> RorkSign.AppSigningOptions {
        try RorkSign.AppSigningOptions(
            bundleIdentifier: bundleIdentifier,
            rootProvisioningProfile: rootProvisioningProfile,
            watchProvisioningProfile: watchProvisioningProfileData,
            provisioningProfilesByBundleIdentifier: BridgeDictionaries.dataByStringKey(
                provisioningProfilesByBundleIdentifier,
                label: "provisioningProfilesByBundleIdentifier"
            ),
            appGroupIdentifiers: appGroupIdentifiers,
            rootEntitlementsXML: rootEntitlementsXML,
            entitlementsResourceName: entitlementsResourceName,
            displayName: displayName,
            bundleVersion: bundleVersion,
            minimumOSVersion: minimumOSVersion,
            enableDocuments: enableDocuments,
            removeExtensions: removeExtensions,
            removeWatchApps: removeWatchApps,
            removeUISupportedDevices: removeUISupportedDevices,
            additionalBundleFiles: BridgeDictionaries.dataByStringKey(
                additionalBundleFiles,
                label: "additionalBundleFiles"
            ),
            embedProvisioningProfiles: embedProvisioningProfiles,
            dylibInjections: dylibInjections.map(\.coreValue),
            dylibLoadCommandsToRemove: dylibLoadCommandsToRemove,
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue,
            signingCache: signingCache?.coreValue,
            diagnostics: signingDiagnostics(
                logLevel: logLevel,
                logHandler: logHandler,
                logger: logger
            )
        )
    }
}

/// Summary of filesystem artifacts touched while signing a bundle.
@objc(RKBundleSigningReport)
public final class BundleSigningReportObjC: NSObject {
    /// Bundles whose `_CodeSignature/CodeResources` file was written, in sign order.
    @objc public let sealedBundleURLs: [URL]

    /// Bundles whose `embedded.mobileprovision` file was written, in sign order.
    @objc public let embeddedProvisioningProfileURLs: [URL]

    /// Mach-O files rewritten with embedded signatures, in sign order.
    @objc public let signedCodeURLs: [URL]

    /// Mach-O files restored from the signing cache.
    @objc public let cachedCodeURLs: [URL]

    /// Wraps a Swift bundle-signing report with Objective-C property names.
    init(_ report: RorkSign.BundleSigningReport) {
        sealedBundleURLs = report.sealedBundles
        embeddedProvisioningProfileURLs = report.embeddedProvisioningProfiles
        signedCodeURLs = report.signedCode
        cachedCodeURLs = report.cachedCode
        super.init()
    }
}

/// Summary of one IPA archive signing operation.
@objc(RKIPAArchiveSigningReport)
public final class IPAArchiveSigningReportObjC: NSObject {
    /// Destination IPA written by the signer.
    @objc public let outputArchiveURL: URL

    /// App bundle path inside the IPA, usually `Payload/AppName.app`.
    @objc public let appBundlePath: String

    /// Bundle paths whose `_CodeSignature/CodeResources` file was written.
    @objc public let sealedBundlePaths: [String]

    /// Bundle paths whose `embedded.mobileprovision` file was written.
    @objc public let embeddedProvisioningProfilePaths: [String]

    /// Mach-O paths rewritten with embedded signatures.
    @objc public let signedCodePaths: [String]

    /// Mach-O paths restored from the signing cache.
    @objc public let cachedCodePaths: [String]

    /// Wraps a Swift IPA archive signing report with Objective-C property names.
    init(_ report: RorkSign.IPAArchiveSigningReport) {
        outputArchiveURL = report.outputArchiveURL
        appBundlePath = report.appBundlePath
        sealedBundlePaths = report.sealedBundlePaths
        embeddedProvisioningProfilePaths = report.embeddedProvisioningProfilePaths
        signedCodePaths = report.signedCodePaths
        cachedCodePaths = report.cachedCodePaths
        super.init()
    }
}

/// Objective-C-friendly signing facade backed by the Swift `RorkSign` engine.
///
/// The facade intentionally exposes typed methods and option objects instead of
/// a dictionary dispatcher. Objective-C and Objective-C++ callers pass
/// `NSURL`, `NSData`, `NSString`, and small `NSObject` option models; the actual
/// Mach-O, CMS, provisioning-profile, and bundle-signing work stays in Swift.
@objc(RKSigner)
public final class Signer: NSObject {
    /// Returns the underlying Swift signer version.
    @objc(signerVersion)
    public static func signerVersion() -> String {
        RorkSigner.version
    }

    /// Creates a signer facade.
    @objc public override init() {
        super.init()
    }

    /// Reads high-level Mach-O metadata from bytes.
    @objc(inspectMachOData:error:)
    public func inspectMachO(_ data: Data) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.inspectMachO(data))
    }

    /// Reads high-level Mach-O metadata from a file.
    @objc(inspectMachOAtURL:error:)
    public func inspectMachO(at url: URL) throws -> NSDictionary {
        guard url.isFileURL else {
            throw SignerBridgeError.invalidOption("inspectMachO(at:) requires a file URL.")
        }
        return try inspectMachO(Data(contentsOf: url))
    }

    /// Extracts ZSign-compatible metadata from an app bundle.
    @objc(extractBundleMetadataAtURL:outputDirectoryURL:sourceArchiveURL:timestamp:error:)
    public func extractBundleMetadata(
        at bundleURL: URL,
        outputDirectoryURL: URL?,
        sourceArchiveURL: URL?,
        timestamp: Date?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.extractBundleMetadata(
                at: bundleURL,
                outputDirectory: outputDirectoryURL,
                sourceArchiveURL: sourceArchiveURL,
                timestamp: timestamp ?? Date()
            )
        )
    }

    /// Extracts ZSign-compatible metadata from the app inside an IPA archive.
    @objc(extractIPAMetadataAtURL:outputDirectoryURL:timestamp:temporaryDirectoryURL:error:)
    public func extractIPAMetadata(
        at archiveURL: URL,
        outputDirectoryURL: URL?,
        timestamp: Date?,
        temporaryDirectoryURL: URL?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.extractIPAMetadata(
                at: archiveURL,
                outputDirectory: outputDirectoryURL,
                timestamp: timestamp ?? Date(),
                temporaryDirectory: temporaryDirectoryURL
            )
        )
    }

    /// Checks the first DER or PEM-encoded X.509 certificate.
    @objc(checkCertificateData:error:)
    public func checkCertificate(_ data: Data) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.checkCertificate(data))
    }

    /// Checks the first DER or PEM-encoded X.509 certificate from disk.
    @objc(checkCertificateAtURL:error:)
    public func checkCertificate(at url: URL) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.checkCertificate(at: url))
    }

    /// Checks every certificate in a DER certificate or PEM certificate chain.
    @objc(checkCertificateChainData:error:)
    public func checkCertificateChain(_ data: Data) throws -> [NSDictionary] {
        try RorkSigner.checkCertificateChain(data).map(ReportBridge.dictionary(from:))
    }

    /// Checks every certificate in a DER certificate or PEM certificate chain from disk.
    @objc(checkCertificateChainAtURL:error:)
    public func checkCertificateChain(at url: URL) throws -> [NSDictionary] {
        try RorkSigner.checkCertificateChain(at: url).map(ReportBridge.dictionary(from:))
    }

    /// Locally validates a DER certificate or PEM certificate chain.
    @objc(validateCertificateChainData:validationDate:error:)
    public func validateCertificateChain(_ data: Data, validationDate: Date?) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.validateCertificateChain(data, validationDate: validationDate ?? Date())
        )
    }

    /// Locally validates a certificate chain from disk.
    @objc(validateCertificateChainAtURL:validationDate:error:)
    public func validateCertificateChain(at url: URL, validationDate: Date?) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.validateCertificateChain(at: url, validationDate: validationDate ?? Date())
        )
    }

    /// Locally validates the certificate chain carried by a signing identity.
    @objc(validateCertificateChainForIdentity:validationDate:error:)
    public func validateCertificateChain(
        identity: SigningIdentityObjC,
        validationDate: Date?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.validateCertificateChain(
                identity: identity.coreValue,
                validationDate: validationDate ?? Date()
            )
        )
    }

    /// Builds a pure Swift OCSP request for a leaf certificate and issuer.
    @objc(makeOCSPRequestWithCertificateData:issuerCertificateData:error:)
    public func makeOCSPRequest(
        certificateData: Data,
        issuerCertificateData: Data
    ) throws -> OCSPRequestObjC {
        try OCSPRequestObjC(
            RorkSigner.makeOCSPRequest(
                certificateData: certificateData,
                issuerCertificateData: issuerCertificateData
            )
        )
    }

    /// Builds a pure Swift OCSP request for certificate files on disk.
    @objc(makeOCSPRequestWithCertificateURL:issuerCertificateURL:error:)
    public func makeOCSPRequest(
        certificateURL: URL,
        issuerCertificateURL: URL
    ) throws -> OCSPRequestObjC {
        try OCSPRequestObjC(
            RorkSigner.makeOCSPRequest(
                certificateAt: certificateURL,
                issuerCertificateAt: issuerCertificateURL
            )
        )
    }

    /// Parses an OCSP response DER payload.
    @objc(parseOCSPResponseData:error:)
    public func parseOCSPResponse(_ data: Data) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.parseOCSPResponse(data))
    }

    /// Parses an OCSP response DER payload from disk.
    @objc(parseOCSPResponseAtURL:error:)
    public func parseOCSPResponse(at url: URL) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.parseOCSPResponse(at: url))
    }

    /// Verifies an OCSP BasicOCSPResponse signature.
    @objc(verifyOCSPResponseSignatureData:responderCertificateData:error:)
    public func verifyOCSPResponseSignature(
        _ data: Data,
        responderCertificateData: Data?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.verifyOCSPResponseSignature(
                data,
                responderCertificateData: responderCertificateData
            )
        )
    }

    /// Verifies an OCSP BasicOCSPResponse signature from disk.
    @objc(verifyOCSPResponseSignatureAtURL:responderCertificateURL:error:)
    public func verifyOCSPResponseSignature(
        at responseURL: URL,
        responderCertificateURL: URL?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.verifyOCSPResponseSignature(
                at: responseURL,
                responderCertificateAt: responderCertificateURL
            )
        )
    }

    /// Verifies, matches, and freshness-checks an OCSP response for one request.
    @objc(validateOCSPResponseData:request:responderCertificateData:issuerCertificateData:policy:error:)
    public func validateOCSPResponse(
        _ data: Data,
        request: OCSPRequestObjC,
        responderCertificateData: Data?,
        issuerCertificateData: Data?,
        policy: OCSPResponseValidationPolicyObjC?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.validateOCSPResponse(
                data,
                matching: request.coreValue,
                responderCertificateData: responderCertificateData,
                issuerCertificateData: issuerCertificateData,
                policy: (policy ?? OCSPResponseValidationPolicyObjC()).coreValue
            )
        )
    }

    /// Verifies, matches, and freshness-checks an OCSP response from disk.
    @objc(validateOCSPResponseAtURL:request:responderCertificateURL:issuerCertificateURL:policy:error:)
    public func validateOCSPResponse(
        at responseURL: URL,
        request: OCSPRequestObjC,
        responderCertificateURL: URL?,
        issuerCertificateURL: URL?,
        policy: OCSPResponseValidationPolicyObjC?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.validateOCSPResponse(
                at: responseURL,
                matching: request.coreValue,
                responderCertificateAt: responderCertificateURL,
                issuerCertificateAt: issuerCertificateURL,
                policy: (policy ?? OCSPResponseValidationPolicyObjC()).coreValue
            )
        )
    }

    /// Builds the RFC 6960 HTTP POST request for an OCSP query.
    @objc(makeOCSPURLRequest:options:error:)
    public func makeOCSPURLRequest(
        _ request: OCSPRequestObjC,
        options: OCSPHTTPOptionsObjC?
    ) throws -> NSURLRequest {
        try RorkSigner.makeOCSPURLRequest(
            request.coreValue,
            options: (options ?? OCSPHTTPOptionsObjC()).coreValue()
        ) as NSURLRequest
    }

    /// Sends an OCSP request to its responder URL and returns the transport report.
    @objc(fetchOCSPResponse:options:completionHandler:)
    public func fetchOCSPResponse(
        _ request: OCSPRequestObjC,
        options: OCSPHTTPOptionsObjC?,
        completionHandler: @escaping (NSDictionary?, NSError?) -> Void
    ) {
        let coreRequest = request.coreValue
        let optionsResult = Result {
            try (options ?? OCSPHTTPOptionsObjC()).coreValue()
        }
        completeReport(completionHandler) {
            try await RorkSigner.fetchOCSPResponse(
                coreRequest,
                options: try optionsResult.get()
            )
        }
    }

    /// Performs an online OCSP status check for one certificate and issuer.
    @objc(checkOCSPStatusWithCertificateData:issuerCertificateData:responderCertificateData:responderURL:policy:httpOptions:completionHandler:)
    public func checkOCSPStatus(
        certificateData: Data,
        issuerCertificateData: Data,
        responderCertificateData: Data?,
        responderURL: URL?,
        policy: OCSPResponseValidationPolicyObjC?,
        httpOptions: OCSPHTTPOptionsObjC?,
        completionHandler: @escaping (NSDictionary?, NSError?) -> Void
    ) {
        let corePolicy = (policy ?? OCSPResponseValidationPolicyObjC()).coreValue
        let httpOptionsResult = Result {
            try (httpOptions ?? OCSPHTTPOptionsObjC()).coreValue()
        }
        completeReport(completionHandler) {
            try await RorkSigner.checkOCSPStatus(
                certificateData: certificateData,
                issuerCertificateData: issuerCertificateData,
                responderCertificateData: responderCertificateData,
                responderURL: responderURL,
                policy: corePolicy,
                httpOptions: try httpOptionsResult.get()
            )
        }
    }

    /// Performs an online OCSP status check from a PEM/DER certificate chain.
    @objc(checkOCSPStatusWithCertificateChainData:responderURL:policy:httpOptions:completionHandler:)
    public func checkOCSPStatus(
        certificateChainData: Data,
        responderURL: URL?,
        policy: OCSPResponseValidationPolicyObjC?,
        httpOptions: OCSPHTTPOptionsObjC?,
        completionHandler: @escaping (NSDictionary?, NSError?) -> Void
    ) {
        let corePolicy = (policy ?? OCSPResponseValidationPolicyObjC()).coreValue
        let httpOptionsResult = Result {
            try (httpOptions ?? OCSPHTTPOptionsObjC()).coreValue()
        }
        completeReport(completionHandler) {
            try await RorkSigner.checkOCSPStatus(
                certificateChainData: certificateChainData,
                responderURL: responderURL,
                policy: corePolicy,
                httpOptions: try httpOptionsResult.get()
            )
        }
    }

    /// Performs an online OCSP status check for a signing identity.
    @objc(checkOCSPStatusWithIdentity:responderURL:policy:httpOptions:completionHandler:)
    public func checkOCSPStatus(
        identity: SigningIdentityObjC,
        responderURL: URL?,
        policy: OCSPResponseValidationPolicyObjC?,
        httpOptions: OCSPHTTPOptionsObjC?,
        completionHandler: @escaping (NSDictionary?, NSError?) -> Void
    ) {
        let coreIdentity = identity.coreValue
        let corePolicy = (policy ?? OCSPResponseValidationPolicyObjC()).coreValue
        let httpOptionsResult = Result {
            try (httpOptions ?? OCSPHTTPOptionsObjC()).coreValue()
        }
        completeReport(completionHandler) {
            try await RorkSigner.checkOCSPStatus(
                identity: coreIdentity,
                responderURL: responderURL,
                policy: corePolicy,
                httpOptions: try httpOptionsResult.get()
            )
        }
    }

    /// Decodes a provisioning profile from raw data.
    @objc(decodeProvisioningProfileData:error:)
    public func decodeProvisioningProfile(_ data: Data) throws -> ProvisioningProfileObjC {
        try ProvisioningProfileObjC(RorkSigner.decodeProvisioningProfile(data))
    }

    /// Decodes a provisioning profile from disk.
    @objc(decodeProvisioningProfileAtURL:error:)
    public func decodeProvisioningProfile(at url: URL) throws -> ProvisioningProfileObjC {
        try ProvisioningProfileObjC(RorkSigner.decodeProvisioningProfile(at: url))
    }

    /// Returns the team identifier from a provisioning profile payload.
    ///
    /// This only decodes the profile; it does not validate a signing credential,
    /// certificate trust, expiration, or revocation.
    @objc(teamIdentifierForProvisioningProfileData:error:)
    public func teamIdentifierForProvisioningProfileData(_ data: Data) throws -> String {
        try RorkSigner.teamIdentifier(provisioningProfileData: data)
    }

    /// Returns the team identifier from a provisioning profile file.
    @objc(teamIdentifierForProvisioningProfileAtURL:error:)
    public func teamIdentifierForProvisioningProfile(at url: URL) throws -> String {
        try RorkSigner.teamIdentifier(provisioningProfileAt: url)
    }

    /// Returns the team identifier from an already-decoded provisioning profile.
    @objc(teamIdentifierForProvisioningProfile:)
    public func teamIdentifier(for provisioningProfile: ProvisioningProfileObjC) -> String {
        RorkSigner.teamIdentifier(provisioningProfile: provisioningProfile.coreValue)
    }

    /// Returns the bundle identifier pattern authorized by a provisioning profile payload.
    @objc(authorizedBundleIdentifierForProvisioningProfileData:error:)
    public func authorizedBundleIdentifierForProvisioningProfileData(
        _ data: Data,
        error: NSErrorPointer
    ) -> String? {
        nullableObjCReturn(error) {
            try RorkSigner.authorizedBundleIdentifier(provisioningProfileData: data)
        }
    }

    /// Returns the bundle identifier pattern authorized by a provisioning profile file.
    @objc(authorizedBundleIdentifierForProvisioningProfileAtURL:error:)
    public func authorizedBundleIdentifierForProvisioningProfile(
        at url: URL,
        error: NSErrorPointer
    ) -> String? {
        nullableObjCReturn(error) {
            try RorkSigner.authorizedBundleIdentifier(provisioningProfileAt: url)
        }
    }

    /// Returns the bundle identifier pattern authorized by an already-decoded profile.
    @objc(authorizedBundleIdentifierForProvisioningProfile:)
    public func authorizedBundleIdentifier(for provisioningProfile: ProvisioningProfileObjC) -> String? {
        RorkSigner.authorizedBundleIdentifier(provisioningProfile: provisioningProfile.coreValue)
    }

    /// Returns the explicit authorized bundle identifier, or `nil` for wildcard profiles.
    @objc(explicitAuthorizedBundleIdentifierForProvisioningProfileData:error:)
    public func explicitAuthorizedBundleIdentifierForProvisioningProfileData(
        _ data: Data,
        error: NSErrorPointer
    ) -> String? {
        nullableObjCReturn(error) {
            try RorkSigner.explicitAuthorizedBundleIdentifier(provisioningProfileData: data)
        }
    }

    /// Returns the explicit authorized bundle identifier from a profile file.
    @objc(explicitAuthorizedBundleIdentifierForProvisioningProfileAtURL:error:)
    public func explicitAuthorizedBundleIdentifierForProvisioningProfile(
        at url: URL,
        error: NSErrorPointer
    ) -> String? {
        nullableObjCReturn(error) {
            try RorkSigner.explicitAuthorizedBundleIdentifier(provisioningProfileAt: url)
        }
    }

    /// Returns the explicit authorized bundle identifier from an already-decoded profile.
    @objc(explicitAuthorizedBundleIdentifierForProvisioningProfile:)
    public func explicitAuthorizedBundleIdentifier(for provisioningProfile: ProvisioningProfileObjC) -> String? {
        RorkSigner.explicitAuthorizedBundleIdentifier(provisioningProfile: provisioningProfile.coreValue)
    }

    /// Checks a provisioning profile's plist payload and embedded certificates.
    @objc(checkProvisioningProfileData:error:)
    public func checkProvisioningProfile(_ data: Data) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.checkProvisioningProfile(data))
    }

    /// Checks a provisioning profile from disk.
    @objc(checkProvisioningProfileAtURL:error:)
    public func checkProvisioningProfile(at url: URL) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.checkProvisioningProfile(at: url))
    }

    /// Checks an already-decoded provisioning profile.
    @objc(checkProvisioningProfile:error:)
    public func checkProvisioningProfile(_ profile: ProvisioningProfileObjC) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.checkProvisioningProfile(profile.coreValue))
    }

    /// Checks a PKCS#12 signing identity.
    @objc(checkPKCS12IdentityData:password:error:)
    public func checkPKCS12Identity(_ data: Data, password: String?) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.checkPKCS12Identity(data, password: password ?? ""))
    }

    /// Checks a PKCS#12 signing identity from disk.
    @objc(checkPKCS12IdentityAtURL:password:error:)
    public func checkPKCS12Identity(at url: URL, password: String?) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.checkPKCS12Identity(at: url, password: password ?? ""))
    }

    /// Checks a certificate/private-key pair.
    @objc(checkSigningIdentityWithCertificateData:privateKeyData:password:error:)
    public func checkSigningIdentity(
        certificateData: Data,
        privateKeyData: Data,
        password: String?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.checkSigningIdentity(
                certificateData: certificateData,
                privateKeyData: privateKeyData,
                password: password ?? ""
            )
        )
    }

    /// Checks a provisioning profile against a private-key credential.
    @objc(checkProfileCredentialWithProvisioningProfileData:credentialData:password:error:)
    public func checkProfileCredential(
        provisioningProfileData: Data,
        credentialData: Data,
        password: String?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.checkProfileCredential(
                provisioningProfileData: provisioningProfileData,
                credentialData: credentialData,
                password: password ?? ""
            )
        )
    }

    /// Checks a decoded provisioning profile against a private-key credential.
    @objc(checkProfileCredentialWithProvisioningProfile:credentialData:password:error:)
    public func checkProfileCredential(
        provisioningProfile: ProvisioningProfileObjC,
        credentialData: Data,
        password: String?
    ) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.checkProfileCredential(
                provisioningProfile: provisioningProfile.coreValue,
                credentialData: credentialData,
                password: password ?? ""
            )
        )
    }

    /// Checks embedded Mach-O code signatures for local metadata.
    @objc(checkMachOCodeSignaturesData:error:)
    public func checkMachOCodeSignatures(_ data: Data) throws -> [NSDictionary] {
        try RorkSigner.checkMachOCodeSignatures(data).map(ReportBridge.dictionary(from:))
    }

    /// Checks embedded Mach-O code signatures from disk.
    @objc(checkMachOCodeSignaturesAtURL:error:)
    public func checkMachOCodeSignatures(at url: URL) throws -> [NSDictionary] {
        try RorkSigner.checkMachOCodeSignatures(at: url).map(ReportBridge.dictionary(from:))
    }

    /// Reads embedded code signatures from a thin or universal Mach-O file.
    @objc(readEmbeddedCodeSignaturesInData:error:)
    public func readEmbeddedCodeSignatures(in data: Data) throws -> [MachOEmbeddedCodeSignatureObjC] {
        try RorkSigner.readEmbeddedCodeSignatures(in: data).map(MachOEmbeddedCodeSignatureObjC.init)
    }

    /// Reads dynamic-library load commands from a thin or universal Mach-O.
    @objc(dylibLoadCommandsInData:error:)
    public func dylibLoadCommands(in data: Data) throws -> [DylibLoadCommandObjC] {
        try RorkSigner.dylibLoadCommands(in: data).map(DylibLoadCommandObjC.init)
    }

    /// Adds a dynamic-library load command to a thin or universal Mach-O.
    @objc(injectDylibLoadCommandIntoData:path:isWeak:error:)
    public func injectDylibLoadCommand(
        into data: Data,
        path: String,
        isWeak: Bool
    ) throws -> Data {
        try RorkSigner.injectDylibLoadCommand(into: data, path: path, weak: isWeak)
    }

    /// Removes matching dynamic-library load commands from a thin or universal Mach-O.
    @objc(removeDylibLoadCommandsFromData:matchingPaths:error:)
    public func removeDylibLoadCommands(from data: Data, matching paths: [String]) throws -> Data {
        try RorkSigner.removeDylibLoadCommands(from: data, matching: paths)
    }

    /// Rewrites a supported Mach-O with an ad-hoc embedded signature.
    @objc(signMachOAdHocData:bundleIdentifier:entitlementsXML:infoPlistData:resourceDirectoryData:codeDirectoryHashingMode:error:)
    public func signMachOAdHoc(
        _ data: Data,
        bundleIdentifier: String,
        entitlementsXML: String?,
        infoPlistData: Data?,
        resourceDirectoryData: Data?,
        codeDirectoryHashingMode: CodeDirectoryHashingModeObjC
    ) throws -> Data {
        try RorkSigner.signMachOAdHoc(
            data,
            bundleIdentifier: bundleIdentifier,
            entitlementsXML: entitlementsXML ?? "",
            infoPlist: infoPlistData ?? Data(),
            resourceDirectory: resourceDirectoryData ?? Data(),
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue
        )
    }

    /// Prepares CodeDirectory bytes that must be CMS-signed.
    @objc(prepareMachOCMSCodeDirectoriesForData:bundleIdentifier:subjectCommonName:entitlementsXML:infoPlistData:resourceDirectoryData:cmsSignatureLengthHints:codeDirectoryHashingMode:error:)
    public func prepareMachOCMSCodeDirectories(
        for data: Data,
        bundleIdentifier: String,
        subjectCommonName: String,
        entitlementsXML: String?,
        infoPlistData: Data?,
        resourceDirectoryData: Data?,
        cmsSignatureLengthHints: [NSNumber],
        codeDirectoryHashingMode: CodeDirectoryHashingModeObjC
    ) throws -> [MachOCMSCodeDirectoryObjC] {
        try RorkSigner.prepareMachOCMSCodeDirectories(
            data,
            bundleIdentifier: bundleIdentifier,
            subjectCommonName: subjectCommonName,
            entitlementsXML: entitlementsXML ?? "",
            infoPlist: infoPlistData ?? Data(),
            resourceDirectory: resourceDirectoryData ?? Data(),
            cmsSignatureLengthHints: cmsSignatureLengthHints.map(\.intValue),
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue
        ).map(MachOCMSCodeDirectoryObjC.init)
    }

    /// Prepares CodeDirectory bytes with an explicit team identifier.
    @objc(prepareMachOCMSCodeDirectoriesForData:bundleIdentifier:subjectCommonName:teamIdentifier:entitlementsXML:infoPlistData:resourceDirectoryData:cmsSignatureLengthHints:codeDirectoryHashingMode:error:)
    public func prepareMachOCMSCodeDirectories(
        for data: Data,
        bundleIdentifier: String,
        subjectCommonName: String,
        teamIdentifier: String,
        entitlementsXML: String?,
        infoPlistData: Data?,
        resourceDirectoryData: Data?,
        cmsSignatureLengthHints: [NSNumber],
        codeDirectoryHashingMode: CodeDirectoryHashingModeObjC
    ) throws -> [MachOCMSCodeDirectoryObjC] {
        try RorkSigner.prepareMachOCMSCodeDirectories(
            data,
            bundleIdentifier: bundleIdentifier,
            subjectCommonName: subjectCommonName,
            teamIdentifier: teamIdentifier,
            entitlementsXML: entitlementsXML ?? "",
            infoPlist: infoPlistData ?? Data(),
            resourceDirectory: resourceDirectoryData ?? Data(),
            cmsSignatureLengthHints: cmsSignatureLengthHints.map(\.intValue),
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue
        ).map(MachOCMSCodeDirectoryObjC.init)
    }

    /// Embeds caller-supplied CMS blobs into a Mach-O signature.
    @objc(signMachOWithCMSBlobsData:bundleIdentifier:cmsSignatures:subjectCommonName:entitlementsXML:infoPlistData:resourceDirectoryData:codeDirectoryHashingMode:error:)
    public func signMachOWithCMSBlobs(
        _ data: Data,
        bundleIdentifier: String,
        cmsSignatures: [Data],
        subjectCommonName: String,
        entitlementsXML: String?,
        infoPlistData: Data?,
        resourceDirectoryData: Data?,
        codeDirectoryHashingMode: CodeDirectoryHashingModeObjC
    ) throws -> Data {
        try RorkSigner.signMachOWithCMSBlobs(
            data,
            bundleIdentifier: bundleIdentifier,
            cmsSignatures: cmsSignatures,
            subjectCommonName: subjectCommonName,
            entitlementsXML: entitlementsXML ?? "",
            infoPlist: infoPlistData ?? Data(),
            resourceDirectory: resourceDirectoryData ?? Data(),
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue
        )
    }

    /// Embeds caller-supplied CMS blobs using an explicit team identifier.
    @objc(signMachOWithCMSBlobsData:bundleIdentifier:cmsSignatures:subjectCommonName:teamIdentifier:entitlementsXML:infoPlistData:resourceDirectoryData:codeDirectoryHashingMode:error:)
    public func signMachOWithCMSBlobs(
        _ data: Data,
        bundleIdentifier: String,
        cmsSignatures: [Data],
        subjectCommonName: String,
        teamIdentifier: String,
        entitlementsXML: String?,
        infoPlistData: Data?,
        resourceDirectoryData: Data?,
        codeDirectoryHashingMode: CodeDirectoryHashingModeObjC
    ) throws -> Data {
        try RorkSigner.signMachOWithCMSBlobs(
            data,
            bundleIdentifier: bundleIdentifier,
            cmsSignatures: cmsSignatures,
            subjectCommonName: subjectCommonName,
            teamIdentifier: teamIdentifier,
            entitlementsXML: entitlementsXML ?? "",
            infoPlist: infoPlistData ?? Data(),
            resourceDirectory: resourceDirectoryData ?? Data(),
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue
        )
    }

    /// Embeds one caller-supplied CMS blob into a single-architecture Mach-O signature.
    @objc(signMachOWithCMSBlobData:bundleIdentifier:cmsSignature:subjectCommonName:entitlementsXML:infoPlistData:resourceDirectoryData:codeDirectoryHashingMode:error:)
    public func signMachOWithCMSBlob(
        _ data: Data,
        bundleIdentifier: String,
        cmsSignature: Data,
        subjectCommonName: String,
        entitlementsXML: String?,
        infoPlistData: Data?,
        resourceDirectoryData: Data?,
        codeDirectoryHashingMode: CodeDirectoryHashingModeObjC
    ) throws -> Data {
        try RorkSigner.signMachOWithCMSBlob(
            data,
            bundleIdentifier: bundleIdentifier,
            cmsSignature: cmsSignature,
            subjectCommonName: subjectCommonName,
            entitlementsXML: entitlementsXML ?? "",
            infoPlist: infoPlistData ?? Data(),
            resourceDirectory: resourceDirectoryData ?? Data(),
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue
        )
    }

    /// Embeds one caller-supplied CMS blob using an explicit team identifier.
    @objc(signMachOWithCMSBlobData:bundleIdentifier:cmsSignature:subjectCommonName:teamIdentifier:entitlementsXML:infoPlistData:resourceDirectoryData:codeDirectoryHashingMode:error:)
    public func signMachOWithCMSBlob(
        _ data: Data,
        bundleIdentifier: String,
        cmsSignature: Data,
        subjectCommonName: String,
        teamIdentifier: String,
        entitlementsXML: String?,
        infoPlistData: Data?,
        resourceDirectoryData: Data?,
        codeDirectoryHashingMode: CodeDirectoryHashingModeObjC
    ) throws -> Data {
        try RorkSigner.signMachOWithCMSBlob(
            data,
            bundleIdentifier: bundleIdentifier,
            cmsSignature: cmsSignature,
            subjectCommonName: subjectCommonName,
            teamIdentifier: teamIdentifier,
            entitlementsXML: entitlementsXML ?? "",
            infoPlist: infoPlistData ?? Data(),
            resourceDirectory: resourceDirectoryData ?? Data(),
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue
        )
    }

    /// Generates a detached CMS SignedData blob over content.
    @objc(makeDetachedCMSSignatureForContent:alternateCodeDirectory:identity:error:)
    public func makeDetachedCMSSignature(
        for content: Data,
        alternateCodeDirectory: Data?,
        identity: SigningIdentityObjC
    ) throws -> Data {
        try RorkSigner.makeDetachedCMSSignature(
            for: content,
            alternateCodeDirectory: alternateCodeDirectory ?? Data(),
            identity: identity.coreValue
        )
    }

    /// Verifies a detached CMS SignedData payload against its signed content.
    @objc(verifyDetachedCMSSignature:content:error:)
    public func verifyDetachedCMSSignature(_ cmsPayload: Data, content: Data) throws -> NSDictionary {
        try ReportBridge.dictionary(
            from: RorkSigner.verifyDetachedCMSSignature(cmsPayload, content: content)
        )
    }

    /// Signs a Mach-O by generating detached CMS signatures with an identity.
    @objc(signMachOWithIdentityData:bundleIdentifier:identity:entitlementsXML:infoPlistData:resourceDirectoryData:codeDirectoryHashingMode:error:)
    public func signMachOWithIdentity(
        _ data: Data,
        bundleIdentifier: String,
        identity: SigningIdentityObjC,
        entitlementsXML: String?,
        infoPlistData: Data?,
        resourceDirectoryData: Data?,
        codeDirectoryHashingMode: CodeDirectoryHashingModeObjC
    ) throws -> Data {
        try RorkSigner.signMachOWithIdentity(
            data,
            bundleIdentifier: bundleIdentifier,
            identity: identity.coreValue,
            entitlementsXML: entitlementsXML ?? "",
            infoPlist: infoPlistData ?? Data(),
            resourceDirectory: resourceDirectoryData ?? Data(),
            codeDirectoryHashingMode: codeDirectoryHashingMode.coreValue
        )
    }

    /// Validates a provisioning profile and private-key credential.
    ///
    /// A successful result proves that `credentialData` contains a private key
    /// matching one of the profile's developer certificates, then returns the
    /// profile's Apple team identifier. The method does not evaluate Apple trust,
    /// certificate policy, OCSP, or revocation.
    @objc(validatedTeamIdentifierWithProvisioningProfileData:credentialData:password:error:)
    public func validatedTeamIdentifier(
        provisioningProfileData: Data,
        credentialData: Data,
        password: String?
    ) throws -> String {
        try RorkSigner.validatedTeamIdentifier(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password ?? ""
        )
    }

    /// Validates a decoded provisioning profile and private-key credential.
    @objc(validatedTeamIdentifierWithProvisioningProfile:credentialData:password:error:)
    public func validatedTeamIdentifier(
        provisioningProfile: ProvisioningProfileObjC,
        credentialData: Data,
        password: String?
    ) throws -> String {
        try RorkSigner.validatedTeamIdentifier(
            provisioningProfile: provisioningProfile.coreValue,
            credentialData: credentialData,
            password: password ?? ""
        )
    }

    /// Builds the `_CodeSignature/CodeResources` plist for an app-style bundle.
    @objc(buildCodeResourcesForBundleAtURL:error:)
    public func buildCodeResources(forBundleAt bundleURL: URL) throws -> Data {
        try RorkSigner.buildCodeResources(forBundleAt: bundleURL)
    }

    /// Writes `_CodeSignature/CodeResources` for an app-style bundle.
    @objc(sealBundleResourcesAtURL:error:)
    public func sealBundleResources(at bundleURL: URL) throws -> URL {
        try RorkSigner.sealBundleResources(at: bundleURL)
    }

    /// Verifies an app-style bundle against its existing CodeResources seal.
    @objc(verifyCodeResourcesForBundleAtURL:error:)
    public func verifyCodeResources(forBundleAt bundleURL: URL) throws -> NSDictionary {
        try ReportBridge.dictionary(from: RorkSigner.verifyCodeResources(forBundleAt: bundleURL))
    }

    /// Verifies every CodeResources seal found in the root bundle and nested bundles.
    @objc(verifyCodeResourcesRecursivelyForBundleAtURL:error:)
    public func verifyCodeResourcesRecursively(forBundleAt bundleURL: URL) throws -> [NSDictionary] {
        try RorkSigner.verifyCodeResourcesRecursively(forBundleAt: bundleURL)
            .map(ReportBridge.dictionary(from:))
    }

    /// Inspects a copied app bundle before app signing mutates it.
    @objc(inspectAppAtURL:replacementBundleIdentifier:error:)
    public func inspectApp(
        at bundleURL: URL,
        replacementBundleIdentifier: String
    ) throws -> AppInspectionReportObjC {
        let report = try RorkSigner.inspectApp(
            at: bundleURL,
            replacementBundleIdentifier: replacementBundleIdentifier
        )
        return AppInspectionReportObjC(report)
    }

    /// Signs an app-style bundle inside-out with ad-hoc signatures.
    @objc(signBundleAdHocAtURL:options:error:)
    public func signBundleAdHoc(
        at bundleURL: URL,
        options: BundleSigningOptionsObjC?
    ) throws -> BundleSigningReportObjC {
        let options = options ?? BundleSigningOptionsObjC()
        let report = try RorkSigner.signBundleAdHoc(
            at: bundleURL,
            options: try options.coreValue()
        )
        return BundleSigningReportObjC(report)
    }

    /// Signs an app-style bundle inside-out with identity-backed CMS signatures.
    @objc(signBundleWithIdentityAtURL:identity:options:error:)
    public func signBundleWithIdentity(
        at bundleURL: URL,
        identity: SigningIdentityObjC,
        options: BundleSigningOptionsObjC?
    ) throws -> BundleSigningReportObjC {
        let options = options ?? BundleSigningOptionsObjC()
        let report = try RorkSigner.signBundleWithIdentity(
            at: bundleURL,
            identity: identity.coreValue,
            options: try options.coreValue()
        )
        return BundleSigningReportObjC(report)
    }

    /// Signs an app-style bundle with a provisioning profile and private-key credential.
    ///
    /// This preserves the bundle identifiers already on disk. The profile is
    /// used for entitlement derivation and credential authorization. Set
    /// `options.embedProvisioningProfile` when the output should carry an
    /// `embedded.mobileprovision` file.
    @objc(signBundleWithCredentialAtURL:provisioningProfileData:credentialData:password:options:error:)
    public func signBundleWithCredential(
        at bundleURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String?,
        options: BundleSigningOptionsObjC?
    ) throws -> BundleSigningReportObjC {
        let options = options ?? BundleSigningOptionsObjC.preserveIdentifierCredentialDefaults()
        let report = try RorkSigner.signBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password ?? "",
            options: try options.coreValue(rootProvisioningProfile: provisioningProfileData)
        )
        return BundleSigningReportObjC(report)
    }

    /// Signs a hosted bundle with identity-backed CMS signatures.
    ///
    /// The signer temporarily uses the host executable and bundle identifier
    /// from `options`, signs the original guest executable under that identifier,
    /// restores the original guest `Info.plist`, and removes the copied host
    /// stub before returning.
    @objc(signHostedBundleWithIdentityAtURL:identity:options:error:)
    public func signHostedBundleWithIdentity(
        at bundleURL: URL,
        identity: SigningIdentityObjC,
        options: HostedBundleSigningOptionsObjC
    ) throws -> BundleSigningReportObjC {
        let report = try RorkSigner.signHostedBundleWithIdentity(
            at: bundleURL,
            identity: identity.coreValue,
            options: try options.coreValue()
        )
        return BundleSigningReportObjC(report)
    }

    /// Signs a hosted bundle with a provisioning profile and private-key credential.
    ///
    /// The profile creates the signing identity and, by default, supplies the
    /// temporary root provisioning profile that must authorize
    /// `options.hostBundleIdentifier`.
    @objc(signHostedBundleWithCredentialAtURL:provisioningProfileData:credentialData:password:options:error:)
    public func signHostedBundleWithCredential(
        at bundleURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String?,
        options: HostedBundleSigningOptionsObjC
    ) throws -> BundleSigningReportObjC {
        let report = try RorkSigner.signHostedBundleWithCredential(
            at: bundleURL,
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password ?? "",
            options: try options.coreValue()
        )
        return BundleSigningReportObjC(report)
    }

    /// Signs a standalone `.framework` bundle with ad-hoc signatures.
    @objc(signFrameworkAdHocAtURL:options:error:)
    public func signFrameworkAdHoc(
        at frameworkURL: URL,
        options: FrameworkSigningOptionsObjC?
    ) throws -> BundleSigningReportObjC {
        let options = options ?? FrameworkSigningOptionsObjC()
        let report = try RorkSigner.signFrameworkAdHoc(
            at: frameworkURL,
            options: options.coreValue()
        )
        return BundleSigningReportObjC(report)
    }

    /// Signs a standalone `.framework` bundle with identity-backed CMS signatures.
    @objc(signFrameworkWithIdentityAtURL:identity:options:error:)
    public func signFrameworkWithIdentity(
        at frameworkURL: URL,
        identity: SigningIdentityObjC,
        options: FrameworkSigningOptionsObjC?
    ) throws -> BundleSigningReportObjC {
        let options = options ?? FrameworkSigningOptionsObjC()
        let report = try RorkSigner.signFrameworkWithIdentity(
            at: frameworkURL,
            identity: identity.coreValue,
            options: options.coreValue()
        )
        return BundleSigningReportObjC(report)
    }

    /// Signs a standalone `.framework` bundle with a provisioning profile and credential.
    ///
    /// The profile authorizes the credential but is not embedded into the
    /// framework and does not supply framework entitlements unless explicit
    /// entitlement input is provided on `options`.
    @objc(signFrameworkWithCredentialAtURL:provisioningProfileData:credentialData:password:options:error:)
    public func signFrameworkWithCredential(
        at frameworkURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String?,
        options: FrameworkSigningOptionsObjC?
    ) throws -> BundleSigningReportObjC {
        let options = options ?? FrameworkSigningOptionsObjC()
        let report = try RorkSigner.signFrameworkWithCredential(
            at: frameworkURL,
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password ?? "",
            options: options.coreValue()
        )
        return BundleSigningReportObjC(report)
    }

    /// Rewrites and signs a copied app bundle with ad-hoc signatures.
    @objc(signAppBundleAdHocAtURL:options:error:)
    public func signAppBundleAdHoc(
        at bundleURL: URL,
        options: AppSigningOptionsObjC
    ) throws -> BundleSigningReportObjC {
        let report = try RorkSigner.signBundle(
            at: bundleURL,
            options: try options.coreValue()
        )
        return BundleSigningReportObjC(report)
    }

    /// Rewrites and signs a copied app bundle with identity-backed CMS signatures.
    @objc(signAppBundleAtURL:identity:options:error:)
    public func signAppBundle(
        at bundleURL: URL,
        identity: SigningIdentityObjC,
        options: AppSigningOptionsObjC
    ) throws -> BundleSigningReportObjC {
        let report = try RorkSigner.signBundle(
            at: bundleURL,
            identity: identity.coreValue,
            options: try options.coreValue()
        )
        return BundleSigningReportObjC(report)
    }

    /// Rewrites and signs a copied app bundle with a profile/credential pair.
    ///
    /// The root profile and credential create the signing identity. Optional
    /// per-bundle profiles on `options` cover app extensions or embedded apps,
    /// and `options.watchProvisioningProfileData` supplies a Watch fallback.
    @objc(signAppBundleAtURL:provisioningProfileData:credentialData:password:options:error:)
    public func signAppBundle(
        at bundleURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String?,
        options: AppSigningOptionsObjC
    ) throws -> BundleSigningReportObjC {
        let identity = try RorkSign.SigningIdentity(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password ?? ""
        )
        let report = try RorkSigner.signBundle(
            at: bundleURL,
            identity: identity,
            options: try options.coreValue(rootProvisioningProfile: provisioningProfileData)
        )
        return BundleSigningReportObjC(report)
    }

    /// Signs the app inside an IPA archive with ad-hoc signatures.
    @objc(signIPAAdHocAtURL:outputURL:options:compressionMode:temporaryDirectoryURL:error:)
    public func signIPAAdHoc(
        at archiveURL: URL,
        outputURL: URL,
        options: BundleSigningOptionsObjC?,
        compressionMode: ArchiveCompressionModeObjC,
        temporaryDirectoryURL: URL?
    ) throws -> IPAArchiveSigningReportObjC {
        let options = options ?? BundleSigningOptionsObjC()
        let report = try RorkSigner.signIPAAdHoc(
            at: archiveURL,
            outputURL: outputURL,
            options: try options.coreValue(),
            archiveCompressionMode: compressionMode.coreValue,
            temporaryDirectory: temporaryDirectoryURL
        )
        return IPAArchiveSigningReportObjC(report)
    }

    /// Signs the app inside an IPA archive with identity-backed CMS signatures.
    @objc(signIPAWithIdentityAtURL:outputURL:identity:options:compressionMode:temporaryDirectoryURL:error:)
    public func signIPAWithIdentity(
        at archiveURL: URL,
        outputURL: URL,
        identity: SigningIdentityObjC,
        options: BundleSigningOptionsObjC?,
        compressionMode: ArchiveCompressionModeObjC,
        temporaryDirectoryURL: URL?
    ) throws -> IPAArchiveSigningReportObjC {
        let options = options ?? BundleSigningOptionsObjC()
        let report = try RorkSigner.signIPAWithIdentity(
            at: archiveURL,
            outputURL: outputURL,
            identity: identity.coreValue,
            options: try options.coreValue(),
            archiveCompressionMode: compressionMode.coreValue,
            temporaryDirectory: temporaryDirectoryURL
        )
        return IPAArchiveSigningReportObjC(report)
    }

    /// Rewrites and signs the app inside an IPA with ad-hoc signatures.
    @objc(signAppIPAAdHocAtURL:outputURL:options:compressionMode:temporaryDirectoryURL:error:)
    public func signAppIPAAdHoc(
        at archiveURL: URL,
        outputURL: URL,
        options: AppSigningOptionsObjC,
        compressionMode: ArchiveCompressionModeObjC,
        temporaryDirectoryURL: URL?
    ) throws -> IPAArchiveSigningReportObjC {
        let report = try RorkSigner.signIPA(
            at: archiveURL,
            outputURL: outputURL,
            options: try options.coreValue(),
            archiveCompressionMode: compressionMode.coreValue,
            temporaryDirectory: temporaryDirectoryURL
        )
        return IPAArchiveSigningReportObjC(report)
    }

    /// Rewrites and signs the app inside an IPA with identity-backed CMS signatures.
    @objc(signAppIPAAtURL:outputURL:identity:options:compressionMode:temporaryDirectoryURL:error:)
    public func signAppIPA(
        at archiveURL: URL,
        outputURL: URL,
        identity: SigningIdentityObjC,
        options: AppSigningOptionsObjC,
        compressionMode: ArchiveCompressionModeObjC,
        temporaryDirectoryURL: URL?
    ) throws -> IPAArchiveSigningReportObjC {
        let report = try RorkSigner.signIPA(
            at: archiveURL,
            outputURL: outputURL,
            identity: identity.coreValue,
            options: try options.coreValue(),
            archiveCompressionMode: compressionMode.coreValue,
            temporaryDirectory: temporaryDirectoryURL
        )
        return IPAArchiveSigningReportObjC(report)
    }

    /// Rewrites and signs the app inside an IPA with a profile/credential pair.
    @objc(signAppIPAAtURL:outputURL:provisioningProfileData:credentialData:password:options:compressionMode:temporaryDirectoryURL:error:)
    public func signAppIPA(
        at archiveURL: URL,
        outputURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String?,
        options: AppSigningOptionsObjC,
        compressionMode: ArchiveCompressionModeObjC,
        temporaryDirectoryURL: URL?
    ) throws -> IPAArchiveSigningReportObjC {
        let identity = try RorkSign.SigningIdentity(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password ?? ""
        )
        let report = try RorkSigner.signIPA(
            at: archiveURL,
            outputURL: outputURL,
            identity: identity,
            options: try options.coreValue(rootProvisioningProfile: provisioningProfileData),
            archiveCompressionMode: compressionMode.coreValue,
            temporaryDirectory: temporaryDirectoryURL
        )
        return IPAArchiveSigningReportObjC(report)
    }
}

/// Errors raised by the Objective-C facade before control reaches the signer.
private enum SignerBridgeError: LocalizedError {
    case invalidOption(String)

    var errorDescription: String? {
        switch self {
        case let .invalidOption(message):
            return message
        }
    }
}

/// Bridges nullable Objective-C returns whose `nil` value can also be a valid result.
private func nullableObjCReturn<T>(
    _ errorPointer: NSErrorPointer,
    _ body: () throws -> T?
) -> T? {
    do {
        errorPointer?.pointee = nil
        return try body()
    } catch let error as NSError {
        errorPointer?.pointee = error
        return nil
    }
}

/// Validates Objective-C dictionaries before converting them to typed Swift maps.
private enum BridgeDictionaries {
    /// Converts an `NSDictionary` to `[String: String]` with precise option errors.
    static func stringByStringKey(_ dictionary: NSDictionary, label: String) throws -> [String: String] {
        var result: [String: String] = [:]
        for (key, value) in dictionary {
            guard let key = key as? String else {
                throw SignerBridgeError.invalidOption("\(label) contains a non-string key.")
            }
            guard let value = value as? String else {
                throw SignerBridgeError.invalidOption("\(label)[\(key)] is not NSString.")
            }
            result[key] = value
        }
        return result
    }

    /// Converts an `NSDictionary` to `[String: Data]` with precise option errors.
    static func dataByStringKey(_ dictionary: NSDictionary, label: String) throws -> [String: Data] {
        var result: [String: Data] = [:]
        for (key, value) in dictionary {
            guard let key = key as? String else {
                throw SignerBridgeError.invalidOption("\(label) contains a non-string key.")
            }
            guard let data = value as? Data else {
                throw SignerBridgeError.invalidOption("\(label)[\(key)] is not NSData.")
            }
            result[key] = data
        }
        return result
    }
}

/// Starts an async Swift report operation and returns through the Objective-C facade.
///
/// The isolated parameter lets the child task inherit the caller's current
/// isolation. That keeps the facade's established non-`Sendable` completion
/// type source-compatible while preventing the callback and operation from
/// being transferred to an unrelated executor.
private func completeReport<Value>(
    _ completionHandler: @escaping (NSDictionary?, NSError?) -> Void,
    isolation: isolated (any Actor)? = #isolation,
    operation: @escaping () async throws -> Value
) {
    Task {
        // An explicit use keeps the caller's isolation attached to the task.
        _ = isolation
        do {
            completionHandler(try ReportBridge.dictionary(from: try await operation()), nil)
        } catch {
            completionHandler(nil, error as NSError)
        }
    }
}

/// Converts Swift report structs into Foundation containers for Objective-C.
private enum ReportBridge {
    /// Converts a report value into an Objective-C dictionary root.
    static func dictionary(from value: Any) throws -> NSDictionary {
        guard let dictionary = bridge(value) as? NSDictionary else {
            throw SignerBridgeError.invalidOption("Report value cannot be represented as NSDictionary.")
        }
        return dictionary
    }

    /// Recursively converts Swift values into plist-like Foundation values.
    private static func bridge(_ value: Any) -> Any {
        if let value = value as? NSNull {
            return value
        }
        if let value = value as? String {
            return value
        }
        if let value = value as? Data {
            return value
        }
        if let value = value as? Date {
            return value
        }
        if let value = value as? URL {
            return value
        }
        if let value = value as? Bool {
            return value
        }
        if let value = value as? Int {
            return value
        }
        if let value = value as? Int64 {
            return value
        }
        if let value = value as? UInt32 {
            return NSNumber(value: value)
        }
        if let value = value as? UInt64 {
            return NSNumber(value: value)
        }
        if let value = value as? TimeInterval {
            return value
        }

        let mirror = Mirror(reflecting: value)
        switch mirror.displayStyle {
        case .optional:
            guard let child = mirror.children.first else {
                return NSNull()
            }
            return bridge(child.value)
        case .collection, .set:
            return mirror.children.map { bridge($0.value) }
        case .dictionary:
            var dictionary: [String: Any] = [:]
            for child in mirror.children {
                let pair = Array(Mirror(reflecting: child.value).children)
                guard pair.count == 2 else {
                    continue
                }
                dictionary[String(describing: pair[0].value)] = bridge(pair[1].value)
            }
            return dictionary
        case .struct, .class:
            var dictionary: [String: Any] = [:]
            for child in mirror.children {
                guard let label = child.label else {
                    continue
                }
                dictionary[label] = bridge(child.value)
            }
            return dictionary
        case .enum:
            return String(describing: value)
        case .tuple, .foreignReference:
            return mirror.children.map { bridge($0.value) }
        case nil:
            return String(describing: value)
        @unknown default:
            return String(describing: value)
        }
    }
}
