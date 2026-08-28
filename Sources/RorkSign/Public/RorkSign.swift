import Foundation

/// Errors surfaced by the signing pipeline.
///
/// The associated strings are intentionally user-readable because this package
/// is used both as a library and as a command-line tool. They should describe
/// the invalid artifact or unsupported feature, not an implementation detail.
public enum RorkSignError: Error, Equatable, LocalizedError {
    /// The input is not a supported Mach-O file or its load commands are unsafe.
    case invalidMachO(String)

    /// The entitlement plist cannot be represented in Apple's XML/DER slots.
    case invalidEntitlements(String)

    /// The bundle layout or Info.plist metadata is invalid for signing.
    case invalidBundle(String)

    /// The IPA/zip archive layout is invalid or cannot be unpacked/repacked.
    case invalidArchive(String)

    /// `_CodeSignature/CodeResources` could not be generated.
    case resourceSealing(String)

    /// A provisioning profile could not be decoded or lacks required fields.
    case invalidProvisioningProfile(String)

    /// A certificate/private-key signing identity could not be loaded.
    case invalidSigningIdentity(String)

    /// CMS preparation or embedding failed.
    ///
    /// This covers both caller-supplied CMS embedding and pure-Swift CMS
    /// generation for identity-backed signatures.
    case cmsSigning(String)

    /// OCSP request transport or response validation failed.
    case ocsp(String)

    /// The requested signing mode is recognized but not implemented yet.
    case unsupported(String)

    /// Returns the actionable reason carried by the error.
    ///
    /// Signing errors cross library, CLI, and browser boundaries. Preserving
    /// the associated message prevents those clients from receiving only an
    /// opaque enum case and error code.
    public var errorDescription: String? {
        switch self {
        case let .invalidMachO(message),
             let .invalidEntitlements(message),
             let .invalidBundle(message),
             let .invalidArchive(message),
             let .resourceSealing(message),
             let .invalidProvisioningProfile(message),
             let .invalidSigningIdentity(message),
             let .cmsSigning(message),
             let .ocsp(message),
             let .unsupported(message):
            return message
        }
    }
}

/// Coarse Mach-O container kind.
public enum MachOKind: Equatable {
    /// A 32-bit thin Mach-O. It can be inspected, but signing is not supported.
    case machO32

    /// A 64-bit thin Mach-O.
    case machO64

    /// A fat/universal Mach-O containing one or more architecture slices.
    case universal
}

/// High-level metadata extracted from a Mach-O file.
///
/// This intentionally stays small and stable. Deeper structures such as segment
/// and section tables remain internal so callers do not need to understand every
/// Mach-O detail just to inspect or sign an executable.
public struct MachOInfo: Equatable {
    /// Thin or universal container kind.
    public let kind: MachOKind

    /// Magic value as it appears in the file's relevant header.
    public let magic: UInt32

    /// Mach-O file type for thin files, or `0` for universal containers.
    public let fileType: UInt32

    /// Number of architecture slices represented by this file.
    public let architectureCount: UInt32

    /// Whether a thin file declares `LC_CODE_SIGNATURE`.
    public let hasCodeSignature: Bool

    /// `LC_CODE_SIGNATURE.dataoff` for thin files, or `0` when absent.
    public let codeSignatureOffset: UInt32

    /// `LC_CODE_SIGNATURE.datasize` for thin files, or `0` when absent.
    public let codeSignatureSize: UInt32
}

/// One dynamic-library load command declared by a Mach-O image.
///
/// ZSign-style dylib injection is implemented by adding `LC_LOAD_DYLIB` or
/// `LC_LOAD_WEAK_DYLIB` commands before the final code-signing pass. The path is
/// the install name stored in the load command, for example
/// `@executable_path/Hook.dylib` or `@rpath/Framework.framework/Framework`.
public struct MachODylibLoadCommand: Equatable {
    /// Dynamic-library install name referenced by dyld.
    public let path: String

    /// Whether this is an `LC_LOAD_WEAK_DYLIB` command.
    public let weak: Bool

    /// Creates a load-command description.
    public init(path: String, weak: Bool = false) {
        self.path = path
        self.weak = weak
    }
}

/// CodeDirectory bytes that must be signed for one Mach-O architecture.
///
/// Identity-backed Apple signatures are detached CMS signatures over the primary
/// CodeDirectory blob. Universal Mach-O files need one CMS signature per slice,
/// so this value carries the architecture index alongside the bytes to sign.
public struct MachOCMSCodeDirectory: Equatable {
    /// Zero-based architecture index in the thin or universal Mach-O input.
    public let architectureIndex: Int

    /// Primary CodeDirectory blob, including its `CSMAGIC_CODEDIRECTORY`
    /// header, ready to be signed as detached CMS content.
    public let codeDirectory: Data

    /// Alternate CodeDirectory blob embedded at `CSSLOT_ALTERNATE_CODEDIRECTORIES`.
    ///
    /// Apple signatures commonly use a SHA-1 primary CodeDirectory for the CMS
    /// content and a SHA-256 alternate CodeDirectory for modern cdhash
    /// validation. Empty means the signature shape has no alternate directory.
    public let alternateCodeDirectory: Data
}

/// CodeDirectory digest layout written into a Mach-O embedded signature.
///
/// Apple signatures can carry multiple CodeDirectories. The default signing
/// mode keeps the broad compatibility shape used by existing signers: a
/// SHA-1 primary CodeDirectory plus a SHA-256 alternate CodeDirectory. Some
/// independent app-signing flows intentionally use a single SHA-256 primary
/// CodeDirectory so the signed app does not depend on a legacy SHA-1 cdhash.
public enum CodeDirectoryHashingMode: Equatable {
    /// Emit a SHA-1 primary CodeDirectory and a SHA-256 alternate CodeDirectory.
    ///
    /// This matches the compatibility shape used for regular app and Mach-O
    /// re-signing. Identity-backed CMS signatures sign the primary SHA-1
    /// directory and record the SHA-256 alternate cdhash in Apple-private CMS
    /// attributes.
    case compatible

    /// Emit one SHA-256 primary CodeDirectory and no alternate CodeDirectory.
    ///
    /// This is the default for app rewriting/signing when callers
    /// want independently installable apps to avoid a legacy SHA-1 cdhash.
    /// Identity-backed CMS signatures sign the SHA-256 primary directory and
    /// record that same cdhash as the sole Apple-private cdhash.
    case sha256Only
}

/// Parsed provisioning profile fields needed by signing decisions.
///
/// A `.mobileprovision` is normally a CMS envelope containing an XML property
/// list. The signer only needs a small stable model: team id, app identifier,
/// entitlement XML, expiration, and the developer certificates authorized by the
/// profile.
public struct ProvisioningProfile: Equatable {
    /// Team identifier used for application identifiers and code-signing assets.
    public let teamIdentifier: String

    /// XML plist containing the profile's `Entitlements` dictionary.
    public let entitlementsXML: String

    /// `application-identifier` entitlement, if present.
    public let applicationIdentifier: String?

    /// Profile expiration date, if the plist provides one.
    public let expirationDate: Date?

    /// DER-encoded developer certificates embedded in the profile.
    public let developerCertificatesDER: [Data]

    /// Bundle identifier pattern authorized by the profile's App ID.
    ///
    /// The value is derived from `applicationIdentifier` by removing the
    /// `<team-id>.` prefix. Explicit profiles return a concrete bundle
    /// identifier, while wildcard profiles return patterns such as `*` or
    /// `com.example.*`.
    public var authorizedBundleIdentifier: String? {
        guard let applicationIdentifier,
              applicationIdentifier.hasPrefix(teamIdentifier + ".") else {
            return nil
        }
        return String(applicationIdentifier.dropFirst(teamIdentifier.count + 1))
    }

    /// Explicit bundle identifier authorized by the profile, when it is not a wildcard App ID.
    public var explicitAuthorizedBundleIdentifier: String? {
        guard let authorizedBundleIdentifier,
              !usesWildcardBundleIdentifier else {
            return nil
        }
        return authorizedBundleIdentifier
    }

    /// Whether the profile uses a wildcard App ID such as `*` or `com.example.*`.
    public var usesWildcardBundleIdentifier: Bool {
        guard let authorizedBundleIdentifier else {
            return false
        }
        return authorizedBundleIdentifier == "*" || authorizedBundleIdentifier.hasSuffix(".*")
    }

    /// Whether `expirationDate` is in the past at the supplied date.
    public func isExpired(at date: Date = Date()) -> Bool {
        guard let expirationDate else {
            return false
        }
        return expirationDate <= date
    }

    /// Returns whether this profile's App ID authorizes `bundleIdentifier`.
    ///
    /// The `application-identifier` entitlement has the form
    /// `<team-id>.<bundle-id-pattern>`. Explicit App IDs must match exactly.
    /// Wildcard App IDs such as `TEAMID.*` or `TEAMID.com.example.*` authorize
    /// bundle identifiers under that wildcard prefix.
    public func supportsBundleIdentifier(_ bundleIdentifier: String) -> Bool {
        let requestedIdentifier = bundleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !requestedIdentifier.isEmpty,
              let pattern = authorizedBundleIdentifier else {
            return false
        }

        if pattern == "*" || pattern == requestedIdentifier {
            return true
        }
        guard pattern.hasSuffix(".*") else {
            return false
        }
        let wildcardPrefix = String(pattern.dropLast(2))
        return requestedIdentifier.hasPrefix(wildcardPrefix + ".")
    }

    /// Returns whether the profile embeds the supplied DER-encoded developer certificate.
    public func containsDeveloperCertificateDER(_ certificateDER: Data) -> Bool {
        developerCertificatesDER.contains(certificateDER)
    }

    /// Returns whether the profile authorizes the supplied signing identity.
    public func containsDeveloperCertificate(for identity: SigningIdentity) -> Bool {
        containsDeveloperCertificateDER(identity.certificateDER)
    }
}

/// X.509 KeyUsage bits advertised by a certificate.
///
/// The values use RFC 5280 bit positions, not byte-order positions from the DER
/// BIT STRING. The signer uses this to decide whether an issuer certificate is
/// structurally allowed to sign child certificates during local chain checks.
public struct CertificateKeyUsage: OptionSet, Equatable, Sendable {
    /// Raw X.509 KeyUsage bits in RFC 5280 bit order.
    public let rawValue: UInt16

    /// Creates a key-usage set from raw RFC 5280 bits.
    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// `digitalSignature`.
    public static let digitalSignature = CertificateKeyUsage(rawValue: 1 << 0)

    /// `nonRepudiation`, also known as `contentCommitment`.
    public static let contentCommitment = CertificateKeyUsage(rawValue: 1 << 1)

    /// `keyEncipherment`.
    public static let keyEncipherment = CertificateKeyUsage(rawValue: 1 << 2)

    /// `dataEncipherment`.
    public static let dataEncipherment = CertificateKeyUsage(rawValue: 1 << 3)

    /// `keyAgreement`.
    public static let keyAgreement = CertificateKeyUsage(rawValue: 1 << 4)

    /// `keyCertSign`, required for CA certificates when KeyUsage is present.
    public static let keyCertSign = CertificateKeyUsage(rawValue: 1 << 5)

    /// `cRLSign`.
    public static let cRLSign = CertificateKeyUsage(rawValue: 1 << 6)

    /// `encipherOnly`.
    public static let encipherOnly = CertificateKeyUsage(rawValue: 1 << 7)

    /// `decipherOnly`.
    public static let decipherOnly = CertificateKeyUsage(rawValue: 1 << 8)
}

/// X.509 certificate metadata used by signing preflight checks.
///
/// This is a structural inspection result, not a trust decision. The signer
/// parses the subject common name, validity window, revocation URLs, and
/// certificate-authority metadata without validating Apple roots or applying
/// certificate policy.
public struct CertificateCheckReport: Equatable {
    /// Certificate subject common name, if the certificate declares one.
    public let subjectCommonName: String

    /// Certificate subject organization name, if the certificate declares one.
    public let subjectOrganizationName: String

    /// Certificate issuer common name, if the certificate declares one.
    public let issuerCommonName: String

    /// OCSP responder URLs advertised through the certificate's Authority
    /// Information Access extension.
    ///
    /// These URLs are structural metadata only. The signer does not contact
    /// them or make revocation/trust decisions.
    public let ocspResponderURLs: [String]

    /// CRL Distribution Point URLs advertised by the certificate.
    ///
    /// These URLs are structural metadata only. The signer does not download
    /// CRLs or make revocation/trust decisions.
    public let crlDistributionPointURLs: [String]

    /// Certificate serial number formatted as colon-separated uppercase hex.
    public let serialNumberHex: String

    /// Human-readable public-key algorithm and size, such as `RSA 2048-bit`.
    public let keyAlgorithm: String

    /// Best-effort signing certificate family derived from the subject common name.
    public let certificateKind: String

    /// Whether X.509 BasicConstraints marks this certificate as a CA.
    public let isCertificateAuthority: Bool

    /// X.509 BasicConstraints `pathLenConstraint`, when present.
    public let pathLengthConstraint: Int?

    /// Whether the certificate declares a KeyUsage extension.
    public let hasKeyUsageExtension: Bool

    /// Parsed X.509 KeyUsage bits.
    ///
    /// Empty can mean either that no KeyUsage extension exists or that the
    /// extension exists without recognized bits. Check `hasKeyUsageExtension`
    /// when that distinction matters.
    public let keyUsage: CertificateKeyUsage

    /// Certificate `notBefore` validity bound.
    public let validityStartDate: Date

    /// Certificate `notAfter` validity bound.
    public let expirationDate: Date

    /// Whether this certificate can locally issue/sign other certificates.
    ///
    /// This is a structural X.509 check only: BasicConstraints must mark the
    /// certificate as a CA, and when KeyUsage is present it must include
    /// `keyCertSign`. It is not a platform trust decision.
    public var canSignCertificates: Bool {
        isCertificateAuthority && (!hasKeyUsageExtension || keyUsage.contains(.keyCertSign))
    }

    /// Whether `validityStartDate` is in the future at the supplied date.
    public func isNotYetValid(at date: Date = Date()) -> Bool {
        validityStartDate > date
    }

    /// Whether `expirationDate` is in the past at the supplied date.
    public func isExpired(at date: Date = Date()) -> Bool {
        expirationDate <= date
    }

    /// Whether the certificate validity window contains the supplied date.
    public func isValid(at date: Date = Date()) -> Bool {
        !isNotYetValid(at: date) && !isExpired(at: date)
    }
}

/// Local validation result for one certificate-to-issuer chain link.
///
/// This proves only relationships inside the caller-supplied chain: the
/// certificate's issuer name matches the next certificate's subject name, the
/// certificate signature verifies with that issuer public key, and the leaf
/// certificate for this link is valid at the selected validation date.
public struct CertificateChainLinkValidationReport: Equatable {
    /// Index of the certificate being validated.
    public let certificateIndex: Int

    /// Index of the issuer certificate used for this link.
    public let issuerIndex: Int

    /// Certificate metadata for `certificateIndex`.
    public let certificate: CertificateCheckReport

    /// Issuer metadata for `issuerIndex`.
    public let issuer: CertificateCheckReport

    /// Whether the certificate issuer DN equals the issuer certificate subject DN.
    public let issuerSubjectMatches: Bool

    /// Whether the certificate signature verifies with the issuer public key.
    public let signatureVerified: Bool

    /// Whether the issuer certificate is structurally allowed to sign certificates.
    public let issuerCanSignCertificates: Bool

    /// Number of CA certificates below this issuer in the supplied leaf-first chain.
    public let subordinateCertificateAuthorityCount: Int

    /// Whether the issuer's BasicConstraints `pathLenConstraint` permits the chain.
    public let issuerPathLengthConstraintSatisfied: Bool

    /// Whether the certificate validity window contains the validation date.
    public let certificateValidAtValidationDate: Bool
}

/// Local validation report for a caller-supplied certificate chain.
///
/// The chain is expected to be ordered leaf first. This report intentionally
/// stops at structural validation of the provided chain: it checks validity
/// windows, issuer/subject linkage, and signatures. It does not decide whether
/// the terminal certificate is trusted by Apple or the platform, and it does
/// not perform revocation or certificate-policy checks.
public struct CertificateChainValidationReport: Equatable {
    /// Certificate reports in input order.
    public let certificates: [CertificateCheckReport]

    /// Link reports from certificate `n` to issuer `n + 1`.
    public let links: [CertificateChainLinkValidationReport]

    /// Validation date used for every certificate validity window.
    public let validationDate: Date

    /// Whether every certificate validity window contains `validationDate`.
    public let allCertificatesValidAtValidationDate: Bool

    /// Whether the terminal certificate issuer DN equals its subject DN.
    public let rootSubjectMatchesIssuer: Bool

    /// Whether the terminal certificate signature verifies with its own public key.
    public let rootSignatureVerified: Bool

    /// Whether the terminal certificate is structurally allowed to sign certificates.
    public let rootCanSignCertificates: Bool

    /// Whether every provided non-root chain link is locally valid.
    public var linksAreLocallyValid: Bool {
        links.allSatisfy {
            $0.issuerSubjectMatches
                && $0.signatureVerified
                && $0.issuerCanSignCertificates
                && $0.issuerPathLengthConstraintSatisfied
                && $0.certificateValidAtValidationDate
        }
    }

    /// Whether the chain ends in a self-signed certificate.
    public var terminatesInSelfSignedCertificate: Bool {
        rootSubjectMatchesIssuer && rootSignatureVerified
    }

    /// Whether the supplied chain is locally complete and valid.
    ///
    /// This requires a valid date window for every certificate, valid signatures
    /// for all provided links, and a self-signed terminal certificate. It is not
    /// a platform trust decision.
    public var isLocallyValid: Bool {
        !certificates.isEmpty
            && allCertificatesValidAtValidationDate
            && linksAreLocallyValid
            && terminatesInSelfSignedCertificate
            && rootCanSignCertificates
    }
}

/// Pure Swift OCSP request material for one certificate/issuer pair.
///
/// The DER payload is an unsigned RFC 6960 `OCSPRequest` with one SHA-1
/// `CertID`, matching OpenSSL/ZSign request construction without a nonce.
/// `responderURL` is selected from the leaf certificate's AIA extension when
/// present, with Apple WWDR fallbacks for known issuer common names. This is
/// request material only; it is not a revocation or trust decision.
public struct OCSPRequest: Equatable, Sendable {
    /// DER-encoded `OCSPRequest` body suitable for an
    /// `application/ocsp-request` HTTP POST.
    public let derRepresentation: Data

    /// Preferred responder endpoint, if one can be derived locally.
    public let responderURL: URL?

    /// SHA-1 hash of the DER-encoded issuer distinguished name.
    public let issuerNameHash: Data

    /// SHA-1 hash of the issuer subject public key bytes.
    public let issuerKeyHash: Data

    /// Leaf certificate serial number formatted as colon-separated uppercase hex.
    public let serialNumberHex: String
}

/// Top-level status from an OCSP responder.
///
/// A successful response means the responder could process the request; callers
/// still need to inspect the contained `OCSPSingleResponse` values to learn the
/// certificate status. Non-success statuses normally carry no BasicOCSPResponse
/// body.
public enum OCSPResponseStatus: Equatable {
    /// The responder produced a response body.
    case successful

    /// The request was malformed.
    case malformedRequest

    /// The responder hit an internal error.
    case internalError

    /// The responder asked the client to retry later.
    case tryLater

    /// The responder requires the request to be signed.
    case signatureRequired

    /// The client is not authorized to query this responder.
    case unauthorized

    /// A response code not currently named by RFC 6960.
    case unknown(Int)

    /// Numeric status code carried by the DER response.
    public var code: Int {
        switch self {
        case .successful:
            return 0
        case .malformedRequest:
            return 1
        case .internalError:
            return 2
        case .tryLater:
            return 3
        case .signatureRequired:
            return 5
        case .unauthorized:
            return 6
        case .unknown(let code):
            return code
        }
    }
}

/// Certificate status carried by one OCSP `SingleResponse`.
///
/// This is the responder's signed status assertion as parsed from DER. It is
/// not a trust decision by itself; callers still need to verify the responder
/// signature, freshness, responder authorization, and issuer policy before
/// treating the status as authoritative.
public enum OCSPCertificateStatus: Equatable {
    /// The responder reports the certificate as good.
    case good

    /// The responder reports the certificate as revoked.
    case revoked(revocationTime: Date, reason: Int?)

    /// The responder does not know the certificate status.
    case unknown
}

/// One certificate status entry from a BasicOCSPResponse.
public struct OCSPSingleResponse: Equatable {
    /// SHA-1 hash of the DER-encoded issuer distinguished name from `CertID`.
    public let issuerNameHash: Data

    /// SHA-1 hash of the issuer subject public key bytes from `CertID`.
    public let issuerKeyHash: Data

    /// Certificate serial number formatted as colon-separated uppercase hex.
    public let serialNumberHex: String

    /// The responder's certificate status assertion.
    public let certificateStatus: OCSPCertificateStatus

    /// Time at which the status is known to be correct.
    public let thisUpdate: Date

    /// Optional next update time advertised by the responder.
    public let nextUpdate: Date?
}

/// Parsed OCSP response metadata.
///
/// The parser understands the common BasicOCSPResponse shape and extracts the
/// status records needed by signing and certificate-health tooling. It does not
/// verify the response signature or validate responder authorization.
public struct OCSPResponseReport: Equatable {
    /// Top-level OCSP response status.
    public let responseStatus: OCSPResponseStatus

    /// Response type OID, normally `1.3.6.1.5.5.7.48.1.1` for BasicOCSPResponse.
    public let responseTypeOID: String?

    /// Responder production time when a BasicOCSPResponse body is present.
    public let producedAt: Date?

    /// Certificate status entries carried by the response body.
    public let singleResponses: [OCSPSingleResponse]

    /// DER-encoded `ResponseData` bytes covered by the responder signature.
    public let signedResponseData: Data?

    /// Responder signature algorithm OID, if a BasicOCSPResponse body is present.
    public let signatureAlgorithmOID: String?

    /// Raw responder signature bytes from the BasicOCSPResponse BIT STRING.
    public let signature: Data?

    /// DER certificates embedded in the BasicOCSPResponse, usually including
    /// the responder certificate. These certificates are signature material
    /// only; their trust and responder authorization are not evaluated by the
    /// parser.
    public let responderCertificatesDER: [Data]
}

/// Result of verifying an OCSP BasicOCSPResponse signature.
///
/// Verification proves only that one candidate responder certificate validates
/// the BasicOCSPResponse signature over its `ResponseData`. It does not prove
/// that the certificate is trusted, authorized by the issuer, currently valid,
/// or acceptable under Apple policy.
public struct OCSPSignatureVerificationReport: Equatable {
    /// Parsed OCSP response whose signature was verified.
    public let response: OCSPResponseReport

    /// Responder certificate that validated the signature.
    public let responderCertificate: CertificateCheckReport

    /// DER responder certificate that validated the signature.
    public let responderCertificateDER: Data

    /// Whether the verifying certificate came from the OCSP response's embedded
    /// certificate set instead of caller-supplied certificate data.
    public let usedEmbeddedResponderCertificate: Bool
}

/// How the OCSP responder certificate is authorized by the issuer certificate.
public enum OCSPResponderAuthorization: Equatable {
    /// The OCSP response was signed directly by the issuer certificate.
    case issuerCertificate

    /// The response was signed by a certificate issued by the issuer and
    /// carrying the `id-kp-OCSPSigning` extended key usage.
    case delegatedResponder
}

/// Freshness policy for a verified OCSP response.
///
/// These values are caller policy, not baked-in platform trust rules.
/// `validationDate` is compared against `thisUpdate` and `nextUpdate`;
/// `allowedClockSkew` tolerates small clock differences; `maximumAge` can cap
/// how old a response may be even when the responder omits `nextUpdate`; and
/// `requiresNextUpdate` makes that responder field mandatory.
public struct OCSPResponseValidationPolicy: Equatable, Sendable {
    /// Date at which the response should be considered.
    public let validationDate: Date

    /// Clock skew tolerance applied around `thisUpdate` and `nextUpdate`.
    public let allowedClockSkew: TimeInterval

    /// Optional maximum accepted age measured from `thisUpdate`.
    public let maximumAge: TimeInterval?

    /// Whether the response must include `nextUpdate`.
    public let requiresNextUpdate: Bool

    /// Creates an OCSP validation policy.
    public init(
        validationDate: Date = Date(),
        allowedClockSkew: TimeInterval = 300,
        maximumAge: TimeInterval? = nil,
        requiresNextUpdate: Bool = false
    ) {
        self.validationDate = validationDate
        self.allowedClockSkew = allowedClockSkew
        self.maximumAge = maximumAge
        self.requiresNextUpdate = requiresNextUpdate
    }
}

/// A verified OCSP response matched to one request.
///
/// The report proves local structural checks: response status was successful,
/// the responder signature verified with a candidate certificate, one
/// `SingleResponse` matched the request's `CertID`, and the matched status was
/// fresh under the supplied policy. When an issuer certificate is supplied to
/// validation, the report also records whether the responder was the issuer or
/// an issuer-signed delegated OCSP responder. It still does not prove Apple
/// trust roots, certificate policy, or revocation of the responder certificate
/// itself.
public struct OCSPResponseValidationReport: Equatable {
    /// Signature verification details for the BasicOCSPResponse.
    public let signatureVerification: OCSPSignatureVerificationReport

    /// `SingleResponse` whose `CertID` matched the request.
    public let matchedResponse: OCSPSingleResponse

    /// Policy used for freshness checks.
    public let policy: OCSPResponseValidationPolicy

    /// Responder authorization result when issuer certificate data was supplied.
    public let responderAuthorization: OCSPResponderAuthorization?
}

/// Provisioning-profile metadata used by signing preflight checks.
///
/// The report is derived from the profile plist payload. It does not validate
/// the CMS wrapper's signer or Apple trust chain.
public struct ProvisioningProfileCheckReport: Equatable {
    /// Team identifier used by the profile.
    public let teamIdentifier: String

    /// Profile App ID entitlement, if present.
    public let applicationIdentifier: String?

    /// Profile expiration date, if present.
    public let expirationDate: Date?

    /// Developer certificates embedded in the profile.
    public let developerCertificates: [CertificateCheckReport]

    /// Whether `expirationDate` is in the past at the supplied date.
    public func isExpired(at date: Date = Date()) -> Bool {
        guard let expirationDate else {
            return false
        }
        return expirationDate <= date
    }
}

/// Signing identity metadata used by credential preflight checks.
///
/// PKCS#12 credentials can carry intermediate certificates. The signer keeps
/// those certificates for CMS generation and reports them here for diagnostics,
/// but it does not perform trust-chain validation.
public struct SigningCredentialCheckReport: Equatable {
    /// Leaf certificate selected for signing.
    public let leafCertificate: CertificateCheckReport

    /// Additional certificates carried by the credential.
    public let additionalCertificates: [CertificateCheckReport]
}

/// Result of verifying a detached CMS SignedData payload.
///
/// Verification proves that the CMS `messageDigest` attribute matches the
/// caller-provided detached content and that the embedded signer certificate's
/// public key validates the SignedData signature. RSA PKCS#1 v1.5 and NIST EC
/// ECDSA signer certificates are supported. This is intentionally not a trust
/// decision: Apple trust roots, certificate policy, OCSP, and revocation are
/// outside this report.
public struct CMSSignatureVerificationReport: Equatable {
    /// Certificate referenced by SignerInfo and used to verify the signature.
    public let signingCertificate: CertificateCheckReport

    /// Additional certificates embedded alongside the signer certificate.
    public let additionalCertificates: [CertificateCheckReport]
}

/// Hash algorithm declared by a CodeDirectory.
///
/// Embedded signatures commonly carry a SHA-1 primary CodeDirectory and a
/// SHA-256 alternate CodeDirectory. Unsupported values are preserved so callers
/// can report the exact on-disk shape instead of losing diagnostics.
public enum CodeDirectoryHashAlgorithm: Equatable {
    /// CodeDirectory hash type `1`.
    case sha1

    /// CodeDirectory hash type `2`.
    case sha256

    /// A hash type this package does not currently validate.
    case unsupported(UInt8)
}

/// Local validation result for one embedded CodeDirectory blob.
///
/// The validator recomputes code-page hashes over the signed Mach-O prefix and
/// special-slot hashes over the embedded SuperBlob children. It proves only that
/// the CodeDirectory still matches the local bytes; CMS, trust, and revocation
/// are reported separately.
public struct CodeDirectoryValidationReport: Equatable {
    /// Raw SuperBlob slot containing this CodeDirectory, such as `0` or `0x1000`.
    public let slot: UInt32

    /// Identifier string stored in the CodeDirectory.
    public let identifier: String

    /// Raw CodeDirectory version.
    public let version: UInt32

    /// Raw CodeDirectory flags.
    public let flags: UInt32

    /// Hash algorithm used for page and special-slot hashes.
    public let hashAlgorithm: CodeDirectoryHashAlgorithm

    /// Number of signed bytes declared by the CodeDirectory.
    public let codeLimit: UInt64

    /// Number of code hash slots declared by the CodeDirectory.
    public let declaredCodeSlotCount: UInt32

    /// Number of code hash slots required by `codeLimit` and page size.
    public let expectedCodeSlotCount: UInt32

    /// Whether every declared code-page hash matches the signed Mach-O prefix.
    public let codeSlotsValid: Bool

    /// Whether every non-code special slot hash matches its SuperBlob child.
    public let specialSlotsValid: Bool

    /// Whether this CodeDirectory's locally checkable hashes are valid.
    public var isValid: Bool {
        let hashAlgorithmSupported: Bool
        switch hashAlgorithm {
        case .sha1, .sha256:
            hashAlgorithmSupported = true
        case .unsupported:
            hashAlgorithmSupported = false
        }

        return declaredCodeSlotCount == expectedCodeSlotCount
            && codeSlotsValid
            && specialSlotsValid
            && hashAlgorithmSupported
    }
}

/// Certificate metadata extracted from one embedded Mach-O code signature.
///
/// Ad-hoc signatures have no CMS slot, so `signingCertificate` is `nil` and
/// `hasCMS` is `false`. Identity-backed signatures expose the CMS signer
/// certificate plus any additional certificates embedded in SignedData. When a
/// primary CodeDirectory is available, `cmsSignatureValid` reports whether the
/// detached CMS signature cryptographically verifies against it.
/// `codeDirectories` reports whether the primary and alternate CodeDirectory
/// hashes still match the executable bytes and embedded special slots. This
/// still does not validate Apple trust or perform revocation checks.
public struct MachOCodeSignatureCheckReport: Equatable {
    /// Zero-based architecture index in the thin or universal Mach-O input.
    public let architectureIndex: Int

    /// Local validation reports for embedded CodeDirectory blobs.
    public let codeDirectories: [CodeDirectoryValidationReport]

    /// Whether every embedded CodeDirectory validates against local bytes.
    public var codeDirectoryHashesValid: Bool {
        !codeDirectories.isEmpty && codeDirectories.allSatisfy(\.isValid)
    }

    /// Whether the embedded signature contains a CMS BlobWrapper slot.
    public let hasCMS: Bool

    /// Whether the CMS signature verifies against the primary CodeDirectory.
    public let cmsSignatureValid: Bool

    /// Certificate identified by CMS SignerInfo, when present.
    public let signingCertificate: CertificateCheckReport?

    /// Additional certificates carried alongside the signing certificate.
    public let additionalCertificates: [CertificateCheckReport]
}

/// Result of validating a provisioning profile against a private-key credential.
///
/// A successful report means the credential contains a private key matching one
/// of the profile's developer certificates. It does not prove that the profile
/// or certificate are currently trusted by Apple.
public struct ProfileCredentialCheckReport: Equatable {
    /// Decoded provisioning-profile metadata.
    public let provisioningProfile: ProvisioningProfileCheckReport

    /// Signing certificate selected from the provisioning profile.
    public let signingCredential: SigningCredentialCheckReport
}

/// Certificate and private key used for identity-backed code signatures.
///
/// The public model keeps the original certificate bytes so the CMS signature
/// can embed the exact leaf certificate supplied by the caller. The private key
/// itself remains internal and currently supports RSA and NIST EC signing
/// identities.
public struct SigningIdentity: Sendable {
    /// DER-encoded leaf certificate embedded into CMS SignedData.
    public let certificateDER: Data

    /// Additional DER-encoded certificates embedded alongside the leaf in CMS.
    ///
    /// PKCS#12 files often carry intermediate certificates needed to explain the
    /// leaf certificate chain. The signer does not validate trust here, but it
    /// preserves these certificates so the generated CMS has the same chain
    /// material as the caller supplied.
    public let additionalCertificatesDER: [Data]

    /// Apple team identifier associated with the provisioning profile.
    ///
    /// Plain certificate/key identities do not imply a team id, so this value is
    /// empty unless the identity was built from a provisioning profile. Bundle
    /// signing uses it to keep non-executable code signatures tied to the same
    /// team even when those images intentionally omit entitlement payloads.
    public let teamIdentifier: String

    /// Parsed certificate fields used by CMS SignerInfo.
    let certificateInfo: CertificateInfo

    /// Private key used to sign CMS signed attributes.
    let privateKey: SigningPrivateKey

    /// Leaf certificate subject common name.
    ///
    /// Apple designated requirements bind identity-backed signatures to this
    /// field, so exposing it lets callers show or audit the exact certificate
    /// identity that will be written into the requirement blob.
    public var subjectCommonName: String {
        certificateInfo.subjectCommonName
    }

    /// Leaf certificate expiration date from the X.509 validity window.
    ///
    /// This is parsed from the certificate's `notAfter` field. It is metadata
    /// only: constructing a `SigningIdentity` does not perform trust-chain,
    /// revocation, or policy validation.
    public var certificateExpirationDate: Date {
        certificateInfo.notAfter
    }

    /// Creates a signing identity from DER-encoded certificate and private key data.
    ///
    /// `privateKeyPassword` is used when `privateKeyDER` is an encrypted PKCS#8
    /// `EncryptedPrivateKeyInfo` value. Plain RSA PKCS#1, EC SEC.1, and
    /// unencrypted PKCS#8 keys do not need a password.
    public init(certificateDER: Data, privateKeyDER: Data, privateKeyPassword: String = "") throws {
        try self.init(
            certificateDER: certificateDER,
            additionalCertificatesDER: [],
            privateKey: SigningPrivateKey.load(
                derRepresentation: privateKeyDER,
                password: privateKeyPassword
            )
        )
    }

    /// Creates a signing identity from certificate and private-key bytes.
    ///
    /// `certificateData` can be a DER certificate or a PEM certificate chain.
    /// The first certificate is treated as the signing leaf and any remaining
    /// certificates are preserved as CMS chain material.
    ///
    /// `privateKeyData` can be an RSA or NIST EC private key in PEM/DER form
    /// or a PKCS#12 credential. Password-protected PKCS#12, encrypted PKCS#8,
    /// and traditional encrypted RSA PEM keys use `privateKeyPassword`.
    public init(certificateData: Data, privateKeyData: Data, privateKeyPassword: String = "") throws {
        let certificates = try Self.certificateChainDER(from: certificateData)
        let credential = try Self.credential(from: privateKeyData, password: privateKeyPassword)
        try self.init(
            certificateDER: certificates[0],
            additionalCertificatesDER: Self.additionalCertificates(
                primaryChain: Array(certificates.dropFirst()),
                credentialChain: credential.additionalCertificatesDER,
                excluding: certificates[0]
            ),
            privateKey: credential.privateKey
        )
    }

    /// Creates a signing identity from PEM-encoded certificate and private key strings.
    ///
    /// `certificatePEM` may contain either one leaf certificate or a
    /// concatenated PEM chain. The first certificate is treated as the signing
    /// leaf and the remaining certificates are embedded into CMS alongside it.
    ///
    /// `privateKeyPassword` unlocks `-----BEGIN ENCRYPTED PRIVATE KEY-----`
    /// PKCS#8 PEM documents. Unencrypted RSA and NIST EC private-key PEM
    /// documents ignore this value.
    public init(certificatePEM: String, privateKeyPEM: String, privateKeyPassword: String = "") throws {
        let certificates = try Self.certificateChainDER(from: Data(certificatePEM.utf8))
        try self.init(
            certificateDER: certificates[0],
            additionalCertificatesDER: Array(certificates.dropFirst()),
            privateKey: SigningPrivateKey.load(
                pemRepresentation: privateKeyPEM,
                password: privateKeyPassword
            )
        )
    }

    /// Creates a signing identity from a PKCS#12 (`.p12`) container.
    ///
    /// The importer is implemented in Swift and supports both modern
    /// PBES2/PBKDF2/AES-CBC exports, legacy PKCS#12 SHA-1 PBE exports using
    /// 3DES/2-key-3DES/RC2-CBC, and PKCS#5 SHA-1/DES private-key bags. It does
    /// not call `SecPKCS12Import`, so the same code path works in library and
    /// CLI contexts.
    public init(pkcs12Data: Data, password: String) throws {
        let material = try PKCS12IdentityImporter.importIdentity(
            pkcs12Data,
            password: password
        )
        try self.init(
            certificateDER: material.certificateDER,
            additionalCertificatesDER: material.additionalCertificatesDER,
            privateKey: SigningPrivateKey.load(derRepresentation: material.privateKeyDER)
        )
    }

    /// Exports this identity as a password-protected PKCS#12 container.
    ///
    /// The resulting data includes the leaf certificate, additional
    /// certificates, and the matching private key. The private key is encrypted
    /// with PBES2 and the complete container is authenticated with a PKCS#12
    /// MAC so standard platform and OpenSSL importers can validate it.
    ///
    /// - Parameter password: Passphrase used for both key encryption and
    ///   container integrity protection.
    /// - Returns: DER-encoded PKCS#12 data.
    /// - Throws: A cryptographic error when the private key cannot be encrypted
    ///   into the container.
    public func pkcs12Representation(password: String) throws -> Data {
        try PKCS12IdentityExporter.data(for: self, password: password)
    }

    /// Creates a signing identity from a provisioning profile and private-key credential.
    ///
    /// This matches the shape of many app-signing flows: the provisioning
    /// profile already carries the allowed developer certificates, while the
    /// caller supplies only the private key material. `credentialData` may be an
    /// RSA or NIST EC private key in PEM/DER form or a PKCS#12 container. When
    /// multiple certificates are present in the profile, the initializer
    /// selects the first certificate whose public key matches the supplied
    /// private key.
    ///
    /// The password is used for PKCS#12 credentials and encrypted PKCS#8
    /// private-key credentials.
    public init(
        provisioningProfile: ProvisioningProfile,
        credentialData: Data,
        password: String = ""
    ) throws {
        try self.init(
            provisioningProfile: provisioningProfile,
            credential: Self.credential(from: credentialData, password: password)
        )
    }

    /// Creates a signing identity from provisioning-profile bytes and private-key credential bytes.
    ///
    /// `provisioningProfileData` may be either a raw plist fixture or a normal
    /// CMS-wrapped `.mobileprovision`. The credential handling is identical to
    /// `init(provisioningProfile:credentialData:password:)`.
    public init(
        provisioningProfileData: Data,
        credentialData: Data,
        password: String = ""
    ) throws {
        try self.init(
            provisioningProfile: ProvisioningProfileDecoder.decode(provisioningProfileData),
            credentialData: credentialData,
            password: password
        )
    }

    /// Creates an identity from certificate data and an internal key wrapper.
    ///
    /// Protocol-specific flows use this boundary after obtaining a certificate
    /// for a key that already exists in memory. Keeping it internal prevents
    /// concrete cryptographic key types from escaping through the public API,
    /// while preserving the same certificate/key validation as public inputs.
    init(
        certificateDER: Data,
        additionalCertificatesDER: [Data],
        privateKey: SigningPrivateKey,
        teamIdentifier: String = ""
    ) throws {
        let certificateInfo = try CertificateInfo.parse(certificateDER)
        try Self.validateMatch(certificateInfo: certificateInfo, privateKey: privateKey)
        self.certificateDER = certificateDER
        self.additionalCertificatesDER = additionalCertificatesDER
        self.teamIdentifier = teamIdentifier
        self.certificateInfo = certificateInfo
        self.privateKey = privateKey
    }

    /// Returns an equivalent identity that carries the supplied Apple team identifier.
    public func withTeamIdentifier(_ teamIdentifier: String) throws -> SigningIdentity {
        let normalizedTeamIdentifier = teamIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedTeamIdentifier.isEmpty else {
            return self
        }

        let currentTeamIdentifier = self.teamIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        if currentTeamIdentifier == normalizedTeamIdentifier {
            return self
        }
        if !currentTeamIdentifier.isEmpty {
            throw RorkSignError.invalidSigningIdentity(
                "Signing identity team identifier \(currentTeamIdentifier) does not match provisioning profile team \(normalizedTeamIdentifier)."
            )
        }

        return try SigningIdentity(
            certificateDER: certificateDER,
            additionalCertificatesDER: additionalCertificatesDER,
            privateKey: privateKey,
            teamIdentifier: normalizedTeamIdentifier
        )
    }

    /// Selects the profile certificate whose public key matches the credential.
    private init(provisioningProfile: ProvisioningProfile, credential: SigningCredentialMaterial) throws {
        for certificateDER in provisioningProfile.developerCertificatesDER {
            guard let certificateInfo = try? CertificateInfo.parse(certificateDER),
                  certificateInfo.subjectPublicKeyInfoDER == credential.privateKey.publicKeyDERRepresentation else {
                continue
            }

            self.certificateDER = certificateDER
            self.additionalCertificatesDER = credential.additionalCertificatesDER
            self.teamIdentifier = provisioningProfile.teamIdentifier
            self.certificateInfo = certificateInfo
            self.privateKey = credential.privateKey
            return
        }

        throw RorkSignError.invalidSigningIdentity(
            "No provisioning-profile certificate matches the supplied private key."
        )
    }

    /// Verifies that a certificate and private key represent the same identity.
    private static func validateMatch(
        certificateInfo: CertificateInfo,
        privateKey: SigningPrivateKey
    ) throws {
        guard certificateInfo.subjectPublicKeyInfoDER == privateKey.publicKeyDERRepresentation else {
            throw RorkSignError.invalidSigningIdentity("Certificate public key does not match private key.")
        }
    }

    /// Normalizes a certificate input that may be DER or PEM encoded.
    static func certificateChainDER(from data: Data) throws -> [Data] {
        if let pem = String(data: data, encoding: .utf8),
           pem.contains("-----BEGIN ") {
            return try PEM.decodeAll(pem, acceptedTypes: ["CERTIFICATE"])
        }
        return [data]
    }

    /// Decodes supported private-key or PKCS#12 credential input.
    private static func credential(from credentialData: Data, password: String) throws -> SigningCredentialMaterial {
        if let pem = String(data: credentialData, encoding: .utf8),
           pem.contains("-----BEGIN "),
           let privateKey = try? SigningPrivateKey.load(pemRepresentation: pem, password: password) {
            return SigningCredentialMaterial(privateKey: privateKey, additionalCertificatesDER: [])
        }

        if let privateKey = try? SigningPrivateKey.load(derRepresentation: credentialData, password: password) {
            return SigningCredentialMaterial(privateKey: privateKey, additionalCertificatesDER: [])
        }

        do {
            let material = try PKCS12IdentityImporter.importIdentity(
                credentialData,
                password: password
            )
            let privateKey = try SigningPrivateKey.load(derRepresentation: material.privateKeyDER)
            return SigningCredentialMaterial(
                privateKey: privateKey,
                additionalCertificatesDER: material.additionalCertificatesDER
            )
        } catch {
            if looksLikePKCS12PFX(credentialData) {
                throw error
            }
        }

        throw RorkSignError.invalidSigningIdentity(
            "Signing credential must contain an RSA, P-256, P-384, or P-521 private key in PEM, DER, or PKCS#12 form."
        )
    }

    /// Combines caller-supplied certificate-chain material with chain material
    /// discovered inside a credential, preserving order and removing duplicate
    /// certificates. The selected leaf is excluded so CMS emits it exactly once
    /// as the signer certificate.
    private static func additionalCertificates(
        primaryChain: [Data],
        credentialChain: [Data],
        excluding leaf: Data
    ) -> [Data] {
        var result: [Data] = []
        for certificate in primaryChain + credentialChain
            where certificate != leaf && !result.contains(certificate) {
            result.append(certificate)
        }
        return result
    }

    /// Returns whether DER input has the outer shape and version of a PKCS#12 PFX.
    private static func looksLikePKCS12PFX(_ data: Data) -> Bool {
        var reader = DERReader(data)
        guard let root = try? reader.readNode(expectedTag: 0x30),
              reader.isAtEnd else {
            return false
        }

        var pfx = DERReader(root.content)
        guard let version = try? pfx.readNode(expectedTag: 0x02) else {
            return false
        }
        return version.content == Data([0x03])
    }
}

/// Private-key credential plus optional chain material extracted from caller
/// input.
private struct SigningCredentialMaterial {
    /// Private key selected from the caller credential.
    let privateKey: SigningPrivateKey

    /// Additional certificates discovered alongside the private key.
    let additionalCertificatesDER: [Data]
}

/// Summary of filesystem artifacts touched while signing a bundle.
public struct BundleSigningReport: Equatable {
    /// Bundles whose `_CodeSignature/CodeResources` file was written, in sign order.
    public let sealedBundles: [URL]

    /// Bundles whose `embedded.mobileprovision` file was written, in sign order.
    public let embeddedProvisioningProfiles: [URL]

    /// Mach-O files rewritten with embedded signatures, in sign order.
    public let signedCode: [URL]

    /// Mach-O files whose signed bytes were restored from `SigningCacheOptions`.
    ///
    /// Cached paths are also present in `signedCode` because the signer still
    /// writes those bytes into the bundle during the signing pass.
    public let cachedCode: [URL]
}

/// A dylib file to copy into the root app and load from the main executable.
///
/// This models the common ZSign `-l` behavior. The source file is copied into
/// the root app bundle before resource sealing, then the root executable gets
/// an `LC_LOAD_DYLIB` or `LC_LOAD_WEAK_DYLIB` command. When `installName` is
/// nil, the command uses `@executable_path/<source basename>`. When
/// `installName` starts with `@executable_path/`, the copied file is placed at
/// that same safe bundle-relative path.
public struct BundleDylibInjection: Equatable {
    /// Existing dylib file to copy into the root app bundle.
    public var sourceURL: URL

    /// Install name written into the root executable load command.
    public var installName: String?

    /// Whether the command should be `LC_LOAD_WEAK_DYLIB`.
    public var weak: Bool

    /// Creates a dylib injection request.
    public init(sourceURL: URL, installName: String? = nil, weak: Bool = false) {
        self.sourceURL = sourceURL
        self.installName = installName
        self.weak = weak
    }
}

/// Result of checking a bundle against its `_CodeSignature/CodeResources` seal.
///
/// The verifier checks hashes and symlink targets for sealed resources and also
/// scans the current bundle for resources that should be sealed but are missing
/// from the CodeResources plist. It does not evaluate the executable signature
/// that hashes CodeResources into the Mach-O CodeDirectory.
public struct CodeResourcesVerificationReport: Equatable {
    /// Number of resource entries present in the CodeResources plist.
    public let sealedResourceCount: Int

    /// Number of sealed entries that were present and matched their seal.
    public let verifiedResourceCount: Int

    /// Required sealed resources that no longer exist on disk.
    public let missingResources: [String]

    /// Sealed resources whose hash or symlink target no longer matches.
    public let mismatchedResources: [String]

    /// Current bundle resources that should be sealed but are absent from the
    /// CodeResources plist.
    public let unsealedResources: [String]

    /// Whether the current bundle matches the CodeResources seal.
    public var isValid: Bool {
        missingResources.isEmpty
            && mismatchedResources.isEmpty
            && unsealedResources.isEmpty
    }
}

/// Resource-seal verification for one bundle in a recursive app check.
public struct BundleCodeResourcesVerificationReport: Equatable {
    /// Bundle whose `_CodeSignature/CodeResources` seal was verified.
    public let bundleURL: URL

    /// Root-bundle-relative path, or `.` for the root bundle.
    public let relativeBundlePath: String

    /// Verification result for this bundle's CodeResources file.
    public let codeResources: CodeResourcesVerificationReport

    /// Whether this bundle's resource seal is valid.
    public var isValid: Bool {
        codeResources.isValid
    }
}

/// Summary of one IPA archive signing operation.
///
/// Archive signing extracts an IPA into a temporary workspace, signs the
/// `Payload/*.app` bundle, and creates a new archive. The report stores paths
/// relative to the extracted archive root so callers get stable metadata even
/// after the temporary workspace is removed.
public struct IPAArchiveSigningReport: Equatable {
    /// Destination IPA written by the signer.
    public let outputArchiveURL: URL

    /// App bundle path inside the IPA, usually `Payload/AppName.app`.
    public let appBundlePath: String

    /// Bundles whose `_CodeSignature/CodeResources` file was written.
    public let sealedBundlePaths: [String]

    /// Bundles whose `embedded.mobileprovision` file was written.
    public let embeddedProvisioningProfilePaths: [String]

    /// Mach-O files rewritten with embedded signatures.
    public let signedCodePaths: [String]

    /// Mach-O files restored from the signing cache.
    public let cachedCodePaths: [String]
}

/// Role of a provisioned bundle found during app-signing inspection.
public enum AppProvisioningKind: String, Equatable {
    /// The root `.app` bundle passed to the inspector or signer.
    case rootApp

    /// An embedded app extension bundle.
    case appExtension

    /// An embedded Apple Watch app bundle.
    case watchApp

    /// Another embedded `.app` bundle that is not detected as a Watch app.
    case nestedApp
}

/// One app-style bundle that may need a provisioning profile after rewriting.
///
/// App signing can re-home an app under a new root bundle identifier.
/// This value describes the identifier that is currently on disk and the
/// identifier that app signing would write before selecting profiles and
/// entitlements.
public struct AppProvisioningRequirement: Equatable {
    /// Bundle URL on disk.
    public let url: URL

    /// Root-bundle-relative path, or `.` for the root bundle.
    public let relativePath: String

    /// Bundle identifier currently stored in `Info.plist`.
    public let originalBundleIdentifier: String

    /// Bundle identifier app signing would write before signing.
    public let rewrittenBundleIdentifier: String

    /// Provisioning role for this bundle.
    public let kind: AppProvisioningKind

    /// Whether this bundle is detected as an Apple Watch app.
    public let isWatchBundle: Bool

    /// Rewritten associated bundle identifier when the bundle declares one.
    public let associatedBundleIdentifier: String?

    /// `CFBundleExecutable` value, when present.
    public let executableName: String?

    /// Creates a provisioning requirement value.
    public init(
        url: URL,
        relativePath: String,
        originalBundleIdentifier: String,
        rewrittenBundleIdentifier: String,
        kind: AppProvisioningKind,
        isWatchBundle: Bool,
        associatedBundleIdentifier: String?,
        executableName: String?
    ) {
        self.url = url
        self.relativePath = relativePath
        self.originalBundleIdentifier = originalBundleIdentifier
        self.rewrittenBundleIdentifier = rewrittenBundleIdentifier
        self.kind = kind
        self.isWatchBundle = isWatchBundle
        self.associatedBundleIdentifier = associatedBundleIdentifier
        self.executableName = executableName
    }
}

/// Read-only app-signing inspection report.
///
/// The report does not mutate the bundle. It lets callers preview which bundle
/// identifiers will need provisioning profiles before app signing.
public struct AppInspectionReport: Equatable {
    /// Root app bundle that was inspected.
    public let rootBundleURL: URL

    /// Root bundle identifier currently stored in `Info.plist`.
    public let rootBundleIdentifier: String

    /// Replacement root bundle identifier used for the inspection.
    public let replacementBundleIdentifier: String

    /// Provisioned app-style bundles found in app-signing order.
    public let provisioningRequirements: [AppProvisioningRequirement]

    /// Rewritten bundle identifiers that need root/per-bundle profile coverage.
    public var rewrittenBundleIdentifiers: [String] {
        provisioningRequirements.map(\.rewrittenBundleIdentifier)
    }

    /// Rewritten Watch app bundle identifiers that may need a Watch profile.
    public var watchBundleIdentifiers: [String] {
        provisioningRequirements
            .filter(\.isWatchBundle)
            .map(\.rewrittenBundleIdentifier)
    }

    /// Rewritten non-Watch extension identifiers that may need per-bundle profiles.
    public var appExtensionBundleIdentifiers: [String] {
        provisioningRequirements
            .filter { $0.kind == .appExtension && !$0.isWatchBundle }
            .map(\.rewrittenBundleIdentifier)
    }

    /// Creates an app inspection report.
    public init(
        rootBundleURL: URL,
        rootBundleIdentifier: String,
        replacementBundleIdentifier: String,
        provisioningRequirements: [AppProvisioningRequirement]
    ) {
        self.rootBundleURL = rootBundleURL
        self.rootBundleIdentifier = rootBundleIdentifier
        self.replacementBundleIdentifier = replacementBundleIdentifier
        self.provisioningRequirements = provisioningRequirements
    }
}

/// ZIP compression choice used when writing IPA archives.
///
/// ZSign exposes numeric compression levels from `0` through `9`. The Swift
/// implementation intentionally keeps the public library model smaller:
/// `.stored` writes uncompressed ZIP entries and `.deflated` writes standard
/// Deflate entries. The CLI maps ZSign level `0` to `.stored` and levels
/// `1...9` to `.deflated` because the underlying Swift ZIP library does not
/// expose per-level tuning.
public enum ArchiveCompressionMode: Equatable {
    /// Store files without compression.
    case stored

    /// Compress regular files with ZIP Deflate.
    case deflated
}

public struct BundleSigningOptions: Equatable {
    /// Entitlements applied to the root executable when no identifier-specific
    /// entry exists.
    ///
    /// If this is empty and the root bundle has a decodable exact or fallback
    /// provisioning profile, the profile's entitlement dictionary is used
    /// instead.
    public var defaultEntitlementsXML: String

    /// Provisioning profile for the root bundle when no exact identifier entry
    /// exists in `provisioningProfilesByBundleIdentifier`.
    ///
    /// This matches common command-line signing flows where a single
    /// `.mobileprovision` file is supplied for the app being signed. The root
    /// fallback can be an exact or wildcard App ID profile; identity-backed
    /// signing validates that the profile authorizes the root bundle identifier
    /// before embedding or deriving entitlements from it.
    public var rootProvisioningProfile: Data?

    /// Entitlement plist XML keyed by `CFBundleIdentifier`.
    ///
    /// A dictionary entry, even an empty string, is treated as an explicit
    /// choice and takes precedence over profile-derived entitlements.
    public var entitlementsByBundleIdentifier: [String: String]

    /// Embedded provisioning profile bytes keyed by `CFBundleIdentifier`.
    ///
    /// When no explicit entitlement entry exists for a bundle, a valid profile
    /// supplies that bundle's entitlement XML fallback and identity-backed
    /// signing validates that the selected certificate is authorized by it.
    /// Exact entries apply to any bundle with that identifier and take
    /// precedence over `rootProvisioningProfile`. Profiles are written into
    /// bundles only when `embedProvisioningProfiles` is true.
    public var provisioningProfilesByBundleIdentifier: [String: Data]

    /// Whether profiles in `provisioningProfilesByBundleIdentifier` are written
    /// as `embedded.mobileprovision` before resource sealing.
    ///
    /// App signing needs this enabled because the resulting app must
    /// be independently installable. Preserve-identifier signing can leave this
    /// disabled while still using the profile for entitlements and certificate
    /// authorization. When disabled, any existing `embedded.mobileprovision`
    /// file is removed before `CodeResources` is generated so the final bundle
    /// does not seal a stale profile.
    public var embedProvisioningProfiles: Bool

    /// The identifier written to the root executable's CodeDirectory.
    ///
    /// When `nil`, the signer uses the root bundle's `CFBundleIdentifier`.
    /// The override does not rewrite `Info.plist` or nested-code identifiers.
    /// Surrounding whitespace is ignored; empty values and embedded NUL
    /// characters are rejected before signing.
    public var codeDirectoryIdentifier: String?

    /// CodeDirectory digest layout used for every Mach-O signed in this bundle.
    ///
    /// Regular bundle signing defaults to `.compatible` so ordinary re-signing
    /// keeps the broadest validation shape. App signing constructs these
    /// options with `.sha256Only` unless the caller overrides it there.
    public var codeDirectoryHashingMode: CodeDirectoryHashingMode

    /// Dylib files copied into the root app and loaded by the root executable.
    ///
    /// Each source must be a supported Mach-O file. The copied dylib is sealed
    /// in CodeResources and signed as standalone code before the root
    /// executable is signed.
    public var dylibInjections: [BundleDylibInjection]

    /// Dylib load commands removed from the root executable before signing.
    ///
    /// Entries with `/` are exact install names. Bare filenames also match
    /// `@executable_path/<name>`.
    public var dylibLoadCommandsToRemove: [String]

    /// Optional persistent cache for signed Mach-O outputs.
    ///
    /// The cache key includes the normalized Mach-O bytes plus entitlements,
    /// resource seal, Info.plist, identity, and hash-mode inputs. This keeps
    /// cache hits safe across repeated folder or IPA signing runs while letting
    /// callers disable reads for force-rebuild workflows.
    public var signingCache: SigningCacheOptions?

    /// Optional logger-backed diagnostics for bundle signing.
    ///
    /// Logging is intentionally opt-in. The signer never bootstraps SwiftLog or
    /// prints directly, so callers can wire this to stdout, files, OSLog, or a
    /// custom backend according to their environment.
    public var diagnostics: SigningDiagnostics

    /// Creates bundle-signing options using the root bundle identifier for its
    /// CodeDirectory.
    ///
    /// `defaultEntitlementsXML` is used only for the root executable when no
    /// identifier-specific entitlement entry or profile-derived fallback
    /// exists. Nested bundles intentionally default to no entitlement payload
    /// unless they have a matching entitlement or provisioning-profile entry.
    public init(
        defaultEntitlementsXML: String = "",
        rootProvisioningProfile: Data? = nil,
        entitlementsByBundleIdentifier: [String: String] = [:],
        provisioningProfilesByBundleIdentifier: [String: Data] = [:],
        embedProvisioningProfiles: Bool = true,
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible,
        dylibInjections: [BundleDylibInjection] = [],
        dylibLoadCommandsToRemove: [String] = [],
        signingCache: SigningCacheOptions? = nil,
        diagnostics: SigningDiagnostics = .disabled
    ) {
        self.defaultEntitlementsXML = defaultEntitlementsXML
        self.rootProvisioningProfile = rootProvisioningProfile
        self.entitlementsByBundleIdentifier = entitlementsByBundleIdentifier
        self.provisioningProfilesByBundleIdentifier = provisioningProfilesByBundleIdentifier
        self.embedProvisioningProfiles = embedProvisioningProfiles
        self.codeDirectoryIdentifier = nil
        self.codeDirectoryHashingMode = codeDirectoryHashingMode
        self.dylibInjections = dylibInjections
        self.dylibLoadCommandsToRemove = dylibLoadCommandsToRemove
        self.signingCache = signingCache
        self.diagnostics = diagnostics
    }

    /// Creates bundle-signing options with an explicit root CodeDirectory
    /// identifier.
    public init(
        defaultEntitlementsXML: String = "",
        rootProvisioningProfile: Data? = nil,
        entitlementsByBundleIdentifier: [String: String] = [:],
        provisioningProfilesByBundleIdentifier: [String: Data] = [:],
        embedProvisioningProfiles: Bool = true,
        codeDirectoryIdentifier: String?,
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible,
        dylibInjections: [BundleDylibInjection] = [],
        dylibLoadCommandsToRemove: [String] = [],
        signingCache: SigningCacheOptions? = nil,
        diagnostics: SigningDiagnostics = .disabled
    ) {
        self.init(
            defaultEntitlementsXML: defaultEntitlementsXML,
            rootProvisioningProfile: rootProvisioningProfile,
            entitlementsByBundleIdentifier: entitlementsByBundleIdentifier,
            provisioningProfilesByBundleIdentifier: provisioningProfilesByBundleIdentifier,
            embedProvisioningProfiles: embedProvisioningProfiles,
            codeDirectoryHashingMode: codeDirectoryHashingMode,
            dylibInjections: dylibInjections,
            dylibLoadCommandsToRemove: dylibLoadCommandsToRemove,
            signingCache: signingCache,
            diagnostics: diagnostics
        )
        self.codeDirectoryIdentifier = codeDirectoryIdentifier
    }

    /// Compares semantic signing inputs while ignoring the diagnostics sink.
    public static func == (lhs: BundleSigningOptions, rhs: BundleSigningOptions) -> Bool {
        lhs.defaultEntitlementsXML == rhs.defaultEntitlementsXML
            && lhs.rootProvisioningProfile == rhs.rootProvisioningProfile
            && lhs.entitlementsByBundleIdentifier == rhs.entitlementsByBundleIdentifier
            && lhs.provisioningProfilesByBundleIdentifier == rhs.provisioningProfilesByBundleIdentifier
            && lhs.embedProvisioningProfiles == rhs.embedProvisioningProfiles
            && lhs.codeDirectoryIdentifier == rhs.codeDirectoryIdentifier
            && lhs.codeDirectoryHashingMode == rhs.codeDirectoryHashingMode
            && lhs.dylibInjections == rhs.dylibInjections
            && lhs.dylibLoadCommandsToRemove == rhs.dylibLoadCommandsToRemove
            && lhs.signingCache == rhs.signingCache
    }
}

/// Options for signing a standalone `.framework` bundle in place.
///
/// Framework signing is narrower than app signing. A framework should be
/// resource-sealed and its executable should receive a Mach-O code signature,
/// but it normally should not embed an `embedded.mobileprovision` file or
/// inherit app-only entitlements from a provisioning profile. When signing with
/// a provisioning profile and credential, the profile is used to authorize the
/// certificate/private-key pair; entitlement input is supplied only when
/// `entitlementsXML` is set explicitly.
public struct FrameworkSigningOptions: Equatable {
    /// Entitlement plist XML supplied for the framework executable.
    ///
    /// The default empty string omits entitlement input entirely. Dynamic
    /// framework binaries are usually `MH_DYLIB`; those images omit XML and DER
    /// entitlement slots even when entitlement XML is supplied, matching the
    /// signer policy for non-main Mach-O code. App capabilities should normally
    /// remain on the embedding app or extension.
    public var entitlementsXML: String

    /// The identifier written to the framework executable's CodeDirectory.
    ///
    /// When `nil`, the signer uses the framework's `CFBundleIdentifier`.
    /// Set this when a host must load the framework under an identifier
    /// authorized by the host provisioning profile. The override changes only
    /// the root executable signature; it does not rewrite `Info.plist` or the
    /// identifiers of nested code. Surrounding whitespace is ignored; empty
    /// values and embedded NUL characters are rejected before signing.
    public var codeDirectoryIdentifier: String?

    /// CodeDirectory digest layout used for framework Mach-O signatures.
    ///
    /// The default `.compatible` mode emits SHA-1 and SHA-256 CodeDirectories,
    /// matching the broad compatibility default used by ordinary bundle
    /// signing.
    public var codeDirectoryHashingMode: CodeDirectoryHashingMode

    /// Optional persistent cache for signed Mach-O outputs.
    ///
    /// The cache key includes normalized Mach-O bytes plus the framework
    /// entitlements, resource seal, Info.plist, identity, and hash-mode inputs.
    public var signingCache: SigningCacheOptions?

    /// Optional logger-backed diagnostics for framework signing.
    ///
    /// Logging is intentionally opt-in. The signer never bootstraps SwiftLog or
    /// prints directly, so callers can route framework signing progress through
    /// the same diagnostics sink used by app bundle and IPA signing.
    public var diagnostics: SigningDiagnostics

    /// Creates framework-signing options.
    ///
    /// Leave `entitlementsXML` empty for the ordinary framework case. Supply an
    /// explicit plist only for framework artifacts that intentionally need
    /// entitlement input and whose Mach-O type can carry entitlement slots.
    ///
    /// - Parameters:
    ///   - entitlementsXML: Entitlement plist XML supplied for the framework
    ///     executable.
    ///   - codeDirectoryHashingMode: Digest layout used for signed Mach-O code.
    ///   - signingCache: Persistent cache for signed Mach-O outputs.
    ///   - diagnostics: Opt-in signing diagnostics sink.
    public init(
        entitlementsXML: String = "",
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible,
        signingCache: SigningCacheOptions? = nil,
        diagnostics: SigningDiagnostics = .disabled
    ) {
        self.entitlementsXML = entitlementsXML
        self.codeDirectoryIdentifier = nil
        self.codeDirectoryHashingMode = codeDirectoryHashingMode
        self.signingCache = signingCache
        self.diagnostics = diagnostics
    }

    /// Creates framework-signing options with an explicit CodeDirectory identifier.
    ///
    /// - Parameters:
    ///   - codeDirectoryIdentifier: Identifier written to the root framework
    ///     executable's CodeDirectory.
    ///   - entitlementsXML: Entitlement plist XML supplied for the framework
    ///     executable.
    ///   - codeDirectoryHashingMode: Digest layout used for signed Mach-O code.
    ///   - signingCache: Persistent cache for signed Mach-O outputs.
    ///   - diagnostics: Opt-in signing diagnostics sink.
    public init(
        codeDirectoryIdentifier: String,
        entitlementsXML: String = "",
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible,
        signingCache: SigningCacheOptions? = nil,
        diagnostics: SigningDiagnostics = .disabled
    ) {
        self.init(
            entitlementsXML: entitlementsXML,
            codeDirectoryHashingMode: codeDirectoryHashingMode,
            signingCache: signingCache,
            diagnostics: diagnostics
        )
        self.codeDirectoryIdentifier = codeDirectoryIdentifier
    }

    /// Compares semantic signing inputs while ignoring the diagnostics sink.
    public static func == (lhs: FrameworkSigningOptions, rhs: FrameworkSigningOptions) -> Bool {
        lhs.entitlementsXML == rhs.entitlementsXML
            && lhs.codeDirectoryIdentifier == rhs.codeDirectoryIdentifier
            && lhs.codeDirectoryHashingMode == rhs.codeDirectoryHashingMode
            && lhs.signingCache == rhs.signingCache
    }
}

/// Options for signing a bundle that will be hosted by another executable.
///
/// Hosted signing is for specialized runtimes that copy a guest bundle but load
/// its code from an already-installed host app or extension instead of
/// installing the copied bundle as an independent app. The signer temporarily
/// points `CFBundleExecutable` and `CFBundleIdentifier` at the host executable
/// and host bundle identifier for the signing pass, signs the original guest
/// executable under that host identifier, then restores the original
/// `Info.plist` and removes the copied host stub.
///
/// The final bundle is intentionally not directly installable: its restored
/// `Info.plist` no longer matches the temporary root executable signature.
/// Use `signBundle` with `AppSigningOptions` when the output must be installed and
/// launched directly by iOS.
public struct HostedBundleSigningOptions: Equatable {
    /// Executable from the host app or extension used as the temporary signing stub.
    ///
    /// The file must be a supported Mach-O. It is copied into the bundle under
    /// `stubExecutableName`, signed as the root executable, and removed after
    /// the signing pass completes.
    public var hostExecutableURL: URL

    /// Host identifier written to the hosted executable CodeDirectories.
    ///
    /// Identity-backed signing validates any selected root provisioning profile
    /// against this identifier. Both the temporary root stub and the original
    /// guest executable use it instead of the restored guest identifier.
    public var hostBundleIdentifier: String

    /// Plain filename used for the copied host executable inside the guest bundle.
    ///
    /// The value must not contain path separators, `.` or `..`. The default is
    /// deliberately generic so public callers do not inherit an application-
    /// specific file name.
    public var stubExecutableName: String

    /// Regular bundle-signing options used during the temporary signing pass.
    ///
    /// Hosted signing defaults to not embedding provisioning profiles. The
    /// credential overload fills `rootProvisioningProfile` with the supplied
    /// profile when this value leaves it empty. Hosted signing always replaces
    /// `codeDirectoryIdentifier` with `hostBundleIdentifier`.
    public var bundleSigningOptions: BundleSigningOptions

    /// Creates hosted-bundle signing options.
    ///
    /// - Parameters:
    ///   - hostExecutableURL: Host executable copied into the bundle as a
    ///     temporary signing stub.
    ///   - hostBundleIdentifier: Host identifier used for the temporary root
    ///     stub and original guest executable signatures.
    ///   - stubExecutableName: Filename for the copied host executable inside
    ///     the bundle.
    ///   - bundleSigningOptions: Full bundle-signing options for the signing
    ///     pass. The default omits embedded provisioning profiles and uses the
    ///     compatibility CodeDirectory hash layout.
    public init(
        hostExecutableURL: URL,
        hostBundleIdentifier: String,
        stubExecutableName: String = "HostedSigningStub",
        bundleSigningOptions: BundleSigningOptions = BundleSigningOptions(
            embedProvisioningProfiles: false,
            codeDirectoryHashingMode: .compatible
        )
    ) {
        self.hostExecutableURL = hostExecutableURL
        self.hostBundleIdentifier = hostBundleIdentifier
        self.stubExecutableName = stubExecutableName
        self.bundleSigningOptions = bundleSigningOptions
    }
}

public enum RorkSigner {
    /// Package version for CLI diagnostics and consumers that expose signer info.
    public static var version: String {
        "0.6.5"
    }

    /// Reads high-level Mach-O metadata needed by signing and diagnostics.
    ///
    /// This does not rewrite the input. Thin files are validated enough to catch
    /// malformed load-command tables; universal files are validated at the fat
    /// header level.
    public static func inspectMachO(_ data: Data) throws -> MachOInfo {
        try MachOSigner.inspect(data)
    }

    /// Extracts ZSign-compatible metadata from an app bundle.
    ///
    /// When `outputDirectory` is supplied, the signer writes `metadata.json`
    /// and copies the largest declared app icon into that directory. Pass
    /// `sourceArchiveURL` when the bundle came from an IPA and the report should
    /// include archive filename and size.
    public static func extractBundleMetadata(
        at bundleURL: URL,
        outputDirectory: URL? = nil,
        sourceArchiveURL: URL? = nil,
        timestamp: Date = Date()
    ) throws -> AppMetadataReport {
        try AppMetadataExtractor.extractBundleMetadata(
            bundleURL: bundleURL,
            outputDirectory: outputDirectory,
            sourceArchiveURL: sourceArchiveURL,
            timestamp: timestamp
        )
    }

    /// Extracts ZSign-compatible metadata from the app inside an IPA archive.
    ///
    /// When `outputDirectory` is supplied, the signer writes `metadata.json`
    /// and copies the largest declared app icon into that directory.
    public static func extractIPAMetadata(
        at archiveURL: URL,
        outputDirectory: URL? = nil,
        timestamp: Date = Date(),
        temporaryDirectory: URL? = nil
    ) throws -> AppMetadataReport {
        try AppMetadataExtractor.extractIPAMetadata(
            archiveURL: archiveURL,
            outputDirectory: outputDirectory,
            timestamp: timestamp,
            temporaryDirectory: temporaryDirectory
        )
    }

    /// Checks the first DER or PEM-encoded X.509 certificate.
    ///
    /// The report contains local certificate metadata only. This method does not
    /// validate certificate trust, policy, or revocation. When `data` is a PEM
    /// chain, use `checkCertificateChain(_:)` to inspect every certificate.
    public static func checkCertificate(_ data: Data) throws -> CertificateCheckReport {
        try certificateCheckReport(fromDER: certificateDER(from: data))
    }

    /// Checks the first DER or PEM-encoded X.509 certificate from disk.
    public static func checkCertificate(at url: URL) throws -> CertificateCheckReport {
        try checkCertificate(Data(contentsOf: url))
    }

    /// Checks every certificate in a DER certificate or PEM certificate chain.
    ///
    /// DER inputs return a single report. PEM inputs may contain multiple
    /// `CERTIFICATE` blocks; the reports preserve that file order, which should
    /// be leaf first for signing identities and their intermediate chain.
    public static func checkCertificateChain(_ data: Data) throws -> [CertificateCheckReport] {
        try certificateChainDER(from: data).map(certificateCheckReport(fromDER:))
    }

    /// Checks every certificate in a DER certificate or PEM certificate chain from disk.
    public static func checkCertificateChain(at url: URL) throws -> [CertificateCheckReport] {
        try checkCertificateChain(Data(contentsOf: url))
    }

    /// Locally validates a DER certificate or PEM certificate chain.
    ///
    /// The chain must be ordered leaf first. This verifies only the material
    /// supplied by the caller: validity windows, issuer/subject linkage,
    /// certificate signatures, and whether the terminal certificate is
    /// self-signed. Apple trust roots, certificate policy, OCSP, and CRLs remain
    /// explicit caller policy.
    public static func validateCertificateChain(
        _ data: Data,
        validationDate: Date = Date()
    ) throws -> CertificateChainValidationReport {
        try CertificateChainValidator.validate(
            certificatesDER: certificateChainDER(from: data),
            validationDate: validationDate
        )
    }

    /// Locally validates a certificate chain from disk.
    public static func validateCertificateChain(
        at url: URL,
        validationDate: Date = Date()
    ) throws -> CertificateChainValidationReport {
        try validateCertificateChain(Data(contentsOf: url), validationDate: validationDate)
    }

    /// Locally validates the certificate chain carried by a signing identity.
    ///
    /// The identity leaf is followed by any additional certificates preserved
    /// from a PEM chain or PKCS#12 container.
    public static func validateCertificateChain(
        identity: SigningIdentity,
        validationDate: Date = Date()
    ) throws -> CertificateChainValidationReport {
        try CertificateChainValidator.validate(
            certificatesDER: [identity.certificateDER] + identity.additionalCertificatesDER,
            validationDate: validationDate
        )
    }

    /// Builds a pure Swift OCSP request for a leaf certificate and issuer.
    ///
    /// The certificate inputs may be DER certificates or PEM certificate files.
    /// PEM chains use their first certificate. The returned request is suitable
    /// for callers that want to perform their own responder transport and
    /// policy checks without depending on OpenSSL.
    public static func makeOCSPRequest(
        certificateData: Data,
        issuerCertificateData: Data
    ) throws -> OCSPRequest {
        try OCSPRequestBuilder.makeRequest(
            certificateDER: certificateDER(from: certificateData),
            issuerCertificateDER: certificateDER(from: issuerCertificateData)
        )
    }

    /// Builds a pure Swift OCSP request for certificate files on disk.
    public static func makeOCSPRequest(
        certificateAt certificateURL: URL,
        issuerCertificateAt issuerCertificateURL: URL
    ) throws -> OCSPRequest {
        try makeOCSPRequest(
            certificateData: Data(contentsOf: certificateURL),
            issuerCertificateData: Data(contentsOf: issuerCertificateURL)
        )
    }

    /// Parses an OCSP response DER payload.
    ///
    /// This extracts the top-level response status and BasicOCSPResponse
    /// `SingleResponse` records. The parser does not verify the responder
    /// signature, perform freshness checks, or decide whether the responder is
    /// authorized for the queried issuer.
    public static func parseOCSPResponse(_ data: Data) throws -> OCSPResponseReport {
        try OCSPResponseParser.parse(data)
    }

    /// Parses an OCSP response DER payload from disk.
    public static func parseOCSPResponse(at url: URL) throws -> OCSPResponseReport {
        try parseOCSPResponse(Data(contentsOf: url))
    }

    /// Verifies an OCSP BasicOCSPResponse signature.
    ///
    /// Candidate responder certificates are taken from `responderCertificateData`
    /// when supplied and from certificates embedded in the OCSP response. The
    /// first certificate that validates the response signature is reported. This
    /// does not validate trust roots, responder authorization, certificate
    /// validity windows, revocation, or response freshness.
    public static func verifyOCSPResponseSignature(
        _ data: Data,
        responderCertificateData: Data? = nil
    ) throws -> OCSPSignatureVerificationReport {
        try OCSPSignatureVerifier.verify(
            responseDER: data,
            responderCertificateData: responderCertificateData
        )
    }

    /// Verifies an OCSP BasicOCSPResponse signature from disk.
    public static func verifyOCSPResponseSignature(
        at responseURL: URL,
        responderCertificateAt responderCertificateURL: URL? = nil
    ) throws -> OCSPSignatureVerificationReport {
        try verifyOCSPResponseSignature(
            Data(contentsOf: responseURL),
            responderCertificateData: responderCertificateURL.map { try Data(contentsOf: $0) }
        )
    }

    /// Verifies, matches, and freshness-checks an OCSP response for one request.
    ///
    /// This method performs local validation only: BasicOCSPResponse signature
    /// verification, `CertID` matching against `request`, time-window checks
    /// under `policy`, and optional responder authorization against
    /// `issuerCertificateData`. It does not contact responders, evaluate Apple
    /// trust roots, download CRLs, or make platform certificate-policy
    /// decisions.
    public static func validateOCSPResponse(
        _ data: Data,
        matching request: OCSPRequest,
        responderCertificateData: Data? = nil,
        issuerCertificateData: Data? = nil,
        policy: OCSPResponseValidationPolicy = OCSPResponseValidationPolicy()
    ) throws -> OCSPResponseValidationReport {
        try OCSPResponseValidator.validate(
            responseDER: data,
            request: request,
            responderCertificateData: responderCertificateData,
            issuerCertificateData: issuerCertificateData,
            policy: policy
        )
    }

    /// Verifies, matches, and freshness-checks an OCSP response from disk.
    public static func validateOCSPResponse(
        at responseURL: URL,
        matching request: OCSPRequest,
        responderCertificateAt responderCertificateURL: URL? = nil,
        issuerCertificateAt issuerCertificateURL: URL? = nil,
        policy: OCSPResponseValidationPolicy = OCSPResponseValidationPolicy()
    ) throws -> OCSPResponseValidationReport {
        try validateOCSPResponse(
            Data(contentsOf: responseURL),
            matching: request,
            responderCertificateData: responderCertificateURL.map { try Data(contentsOf: $0) },
            issuerCertificateData: issuerCertificateURL.map { try Data(contentsOf: $0) },
            policy: policy
        )
    }

    /// Checks a provisioning profile's plist payload and embedded certificates.
    ///
    /// Raw plist fixtures and CMS-wrapped `.mobileprovision` data are accepted.
    /// The profile's CMS signature and Apple trust chain are not validated.
    public static func checkProvisioningProfile(_ data: Data) throws -> ProvisioningProfileCheckReport {
        try checkProvisioningProfile(try decodeProvisioningProfile(data))
    }

    /// Checks a provisioning profile from disk.
    public static func checkProvisioningProfile(at url: URL) throws -> ProvisioningProfileCheckReport {
        try checkProvisioningProfile(Data(contentsOf: url))
    }

    /// Checks an already-decoded provisioning profile.
    public static func checkProvisioningProfile(_ profile: ProvisioningProfile) throws -> ProvisioningProfileCheckReport {
        try provisioningProfileCheckReport(from: profile)
    }

    /// Checks a PKCS#12 signing identity.
    ///
    /// This verifies that the container has a private key matching its selected
    /// leaf certificate and returns certificate metadata for diagnostics. It
    /// does not validate Apple trust, policy, or revocation.
    public static func checkPKCS12Identity(
        _ data: Data,
        password: String = ""
    ) throws -> SigningCredentialCheckReport {
        try signingCredentialCheckReport(from: SigningIdentity(pkcs12Data: data, password: password))
    }

    /// Checks a PKCS#12 signing identity from disk.
    public static func checkPKCS12Identity(
        at url: URL,
        password: String = ""
    ) throws -> SigningCredentialCheckReport {
        try checkPKCS12Identity(Data(contentsOf: url), password: password)
    }

    /// Checks a certificate/private-key pair.
    ///
    /// The certificate may be PEM or DER. The private key may be PEM or DER.
    /// This proves only that the public key in the certificate matches the
    /// supplied private key.
    public static func checkSigningIdentity(
        certificateData: Data,
        privateKeyData: Data,
        password: String = ""
    ) throws -> SigningCredentialCheckReport {
        let identity = try SigningIdentity(
            certificateData: certificateData,
            privateKeyData: privateKeyData,
            privateKeyPassword: password
        )
        return try signingCredentialCheckReport(from: identity)
    }

    /// Checks a provisioning profile against a private-key credential.
    ///
    /// `credentialData` may be a PEM/DER RSA or NIST EC private key, or a
    /// PKCS#12 container. A successful report means the private key matches one
    /// of the profile's developer certificates.
    public static func checkProfileCredential(
        provisioningProfileData: Data,
        credentialData: Data,
        password: String = ""
    ) throws -> ProfileCredentialCheckReport {
        let profile = try decodeProvisioningProfile(provisioningProfileData)
        return try checkProfileCredential(
            provisioningProfile: profile,
            credentialData: credentialData,
            password: password
        )
    }

    /// Checks a decoded provisioning profile against a private-key credential.
    public static func checkProfileCredential(
        provisioningProfile: ProvisioningProfile,
        credentialData: Data,
        password: String = ""
    ) throws -> ProfileCredentialCheckReport {
        let identity = try SigningIdentity(
            provisioningProfile: provisioningProfile,
            credentialData: credentialData,
            password: password
        )
        return ProfileCredentialCheckReport(
            provisioningProfile: try provisioningProfileCheckReport(from: provisioningProfile),
            signingCredential: try signingCredentialCheckReport(from: identity)
        )
    }

    /// Checks embedded Mach-O code signatures for local signing-certificate metadata.
    ///
    /// The method follows `LC_CODE_SIGNATURE` in thin and universal Mach-O
    /// files. Ad-hoc signatures return a report without a signing certificate.
    /// Identity-backed signatures parse the CMS certificate set and return the
    /// signer certificate first. CMS signatures are verified against the
    /// primary CodeDirectory when both slots are present. Apple trust
    /// evaluation and revocation checks are intentionally out of scope.
    public static func checkMachOCodeSignatures(_ data: Data) throws -> [MachOCodeSignatureCheckReport] {
        try CodeSignatureInspector.readEmbeddedSignatureContexts(in: data).map { context in
            let signature = context.signature
            let codeDirectories = try CodeSignatureInspector.validateCodeDirectories(in: context)
            guard let cmsSlot = signature.firstSlot(0x10000) else {
                return MachOCodeSignatureCheckReport(
                    architectureIndex: signature.architectureIndex,
                    codeDirectories: codeDirectories,
                    hasCMS: false,
                    cmsSignatureValid: false,
                    signingCertificate: nil,
                    additionalCertificates: []
                )
            }

            let cmsPayload = try cmsPayload(fromBlobWrapper: cmsSlot.data)
            let certificates = try CMSCertificateInspector.signingCertificates(in: cmsPayload)
            let cmsSignatureValid = signature.firstSlot(0).map { codeDirectorySlot in
                (try? CMSVerifier.verifyDetached(
                    cmsPayload: cmsPayload,
                    content: codeDirectorySlot.data
                )) != nil
            } ?? false
            return MachOCodeSignatureCheckReport(
                architectureIndex: signature.architectureIndex,
                codeDirectories: codeDirectories,
                hasCMS: true,
                cmsSignatureValid: cmsSignatureValid,
                signingCertificate: try certificates.first.map(certificateCheckReport(fromDER:)),
                additionalCertificates: try certificates.dropFirst().map(certificateCheckReport(fromDER:))
            )
        }
    }

    /// Checks embedded Mach-O code signatures from disk.
    public static func checkMachOCodeSignatures(at url: URL) throws -> [MachOCodeSignatureCheckReport] {
        try checkMachOCodeSignatures(Data(contentsOf: url))
    }

    /// Reads dynamic-library load commands from a thin or universal Mach-O.
    ///
    /// Universal binaries return commands from every architecture slice in file
    /// order. Duplicate paths are preserved because slices can legitimately
    /// differ while a caller is inspecting or repairing a binary.
    public static func dylibLoadCommands(in data: Data) throws -> [MachODylibLoadCommand] {
        try MachOSigner.dylibLoadCommands(data)
    }

    /// Adds a dynamic-library load command to a thin or universal Mach-O.
    ///
    /// This mutates only the load-command table. The resulting binary must be
    /// signed afterwards because the CodeDirectory covers load commands. The
    /// input must have enough load-command padding before the first file
    /// content to hold the new command.
    public static func injectDylibLoadCommand(
        into data: Data,
        path: String,
        weak: Bool = false
    ) throws -> Data {
        try MachOSigner.injectDylibLoadCommand(data, path: path, weak: weak)
    }

    /// Removes matching dynamic-library load commands from a thin or universal Mach-O.
    ///
    /// A removal entry containing a slash is matched exactly. A bare filename
    /// also matches `@executable_path/<filename>`, which is the common bundle
    /// injection shape. The resulting binary must be signed afterwards.
    public static func removeDylibLoadCommands(
        from data: Data,
        matching paths: [String]
    ) throws -> Data {
        try MachOSigner.removeDylibLoadCommands(data, matching: paths)
    }

    /// Rewrites a supported Mach-O with an ad-hoc embedded signature.
    ///
    /// `bundleIdentifier` is stored in the CodeDirectory identifier field and in
    /// the generated designated requirement. `entitlementsXML` is embedded as
    /// XML and DER when provided. `resourceDirectory` should be the serialized
    /// CodeResources plist for a bundle main executable; it is hashed into the
    /// resource-directory special slot. `codeDirectoryHashingMode` controls
    /// whether the signature carries the compatibility SHA-1/SHA-256 pair or a
    /// single SHA-256 primary CodeDirectory.
    public static func signMachOAdHoc(
        _ data: Data,
        bundleIdentifier: String,
        entitlementsXML: String = "",
        infoPlist: Data = Data(),
        resourceDirectory: Data = Data(),
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible
    ) throws -> Data {
        let entitlementsDER = try entitlementsXML.isEmpty
            ? Data()
            : DEREntitlementsEncoder.encodeXML(entitlementsXML)
        return try MachOSigner.signAdHoc(
            data,
            bundleIdentifier: bundleIdentifier,
            entitlementsXML: entitlementsXML,
            entitlementsDER: entitlementsDER,
            infoPlist: infoPlist,
            resourceDirectory: resourceDirectory,
            codeDirectoryHashingMode: codeDirectoryHashingMode
        )
    }

    /// Prepares CodeDirectory blobs for caller-provided CMS signing.
    ///
    /// CMS signatures are size-sensitive because the eventual CMS blob length
    /// changes `LC_CODE_SIGNATURE.datasize`, and that load command is itself
    /// covered by the CodeDirectory page hashes. Pass the previous CMS sizes in
    /// `cmsSignatureLengthHints`, sign the returned CodeDirectories, then repeat
    /// if the produced CMS sizes differ from the hints. `subjectCommonName`
    /// must match the certificate used by the caller's detached CMS signer when
    /// the final signature should carry an identity-backed designated
    /// requirement. `teamIdentifier` optionally writes an explicit CodeDirectory
    /// team id; when empty, it is inferred from entitlements. `signMachOWithCMSBlobs`
    /// embeds the final CMS blobs.
    public static func prepareMachOCMSCodeDirectories(
        _ data: Data,
        bundleIdentifier: String,
        subjectCommonName: String = "",
        teamIdentifier: String = "",
        entitlementsXML: String = "",
        infoPlist: Data = Data(),
        resourceDirectory: Data = Data(),
        cmsSignatureLengthHints: [Int] = [],
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible
    ) throws -> [MachOCMSCodeDirectory] {
        let entitlementsDER = try entitlementsXML.isEmpty
            ? Data()
            : DEREntitlementsEncoder.encodeXML(entitlementsXML)
        return try MachOSigner.prepareCMSCodeDirectories(
            data,
            bundleIdentifier: bundleIdentifier,
            subjectCommonName: subjectCommonName,
            teamIdentifier: teamIdentifier,
            entitlementsXML: entitlementsXML,
            entitlementsDER: entitlementsDER,
            infoPlist: infoPlist,
            resourceDirectory: resourceDirectory,
            cmsSignatureLengthHints: cmsSignatureLengthHints,
            codeDirectoryHashingMode: codeDirectoryHashingMode
        )
    }

    /// Embeds caller-provided detached CMS blobs into a Mach-O signature.
    ///
    /// Thin Mach-O files require exactly one CMS blob. Universal Mach-O files
    /// require one blob per architecture in fat-header order. Use the same
    /// `subjectCommonName` and `teamIdentifier` values passed during preparation
    /// so the final CodeDirectory matches the CMS-signed bytes.
    public static func signMachOWithCMSBlobs(
        _ data: Data,
        bundleIdentifier: String,
        cmsSignatures: [Data],
        subjectCommonName: String = "",
        teamIdentifier: String = "",
        entitlementsXML: String = "",
        infoPlist: Data = Data(),
        resourceDirectory: Data = Data(),
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible
    ) throws -> Data {
        let entitlementsDER = try entitlementsXML.isEmpty
            ? Data()
            : DEREntitlementsEncoder.encodeXML(entitlementsXML)
        return try MachOSigner.signWithCMSBlobs(
            data,
            bundleIdentifier: bundleIdentifier,
            subjectCommonName: subjectCommonName,
            teamIdentifier: teamIdentifier,
            entitlementsXML: entitlementsXML,
            entitlementsDER: entitlementsDER,
            infoPlist: infoPlist,
            resourceDirectory: resourceDirectory,
            cmsSignatures: cmsSignatures,
            codeDirectoryHashingMode: codeDirectoryHashingMode
        )
    }

    /// Convenience overload for thin Mach-O files with one detached CMS blob.
    public static func signMachOWithCMSBlob(
        _ data: Data,
        bundleIdentifier: String,
        cmsSignature: Data,
        subjectCommonName: String = "",
        teamIdentifier: String = "",
        entitlementsXML: String = "",
        infoPlist: Data = Data(),
        resourceDirectory: Data = Data(),
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible
    ) throws -> Data {
        try signMachOWithCMSBlobs(
            data,
            bundleIdentifier: bundleIdentifier,
            cmsSignatures: [cmsSignature],
            subjectCommonName: subjectCommonName,
            teamIdentifier: teamIdentifier,
            entitlementsXML: entitlementsXML,
            infoPlist: infoPlist,
            resourceDirectory: resourceDirectory,
            codeDirectoryHashingMode: codeDirectoryHashingMode
        )
    }

    /// Generates a detached CMS SignedData blob over `content`.
    ///
    /// Code signatures pass the primary CodeDirectory blob as `content`. The
    /// optional `alternateCodeDirectory` is not signed directly; it is recorded in
    /// Apple-private cdhash attributes so verifiers can see the SHA-256 alternate
    /// cdhash that will be embedded beside the primary directory.
    /// The returned data is the payload stored inside the code-signature CMS
    /// BlobWrapper slot.
    public static func makeDetachedCMSSignature(
        for content: Data,
        alternateCodeDirectory: Data = Data(),
        identity: SigningIdentity
    ) throws -> Data {
        try CMSGenerator.signDetached(
            content: content,
            alternateCodeDirectory: alternateCodeDirectory,
            identity: identity
        )
    }

    /// Verifies a detached CMS SignedData payload against its signed content.
    ///
    /// This checks the CMS `messageDigest` signed attribute and the RSA or NIST
    /// EC signature over the signed-attributes set using the embedded signer
    /// certificate. It intentionally does not evaluate Apple trust anchors,
    /// certificate policy, OCSP, or revocation.
    public static func verifyDetachedCMSSignature(
        _ cmsPayload: Data,
        content: Data
    ) throws -> CMSSignatureVerificationReport {
        let certificates = try CMSVerifier.verifyDetached(
            cmsPayload: cmsPayload,
            content: content
        )
        guard let signingCertificate = certificates.first else {
            throw RorkSignError.cmsSigning("Detached CMS signer certificate is missing.")
        }
        return CMSSignatureVerificationReport(
            signingCertificate: try certificateCheckReport(fromDER: signingCertificate),
            additionalCertificates: try certificates.dropFirst().map(certificateCheckReport(fromDER:))
        )
    }

    /// Signs a Mach-O by generating detached CMS signatures with `identity`.
    ///
    /// The method performs the required size-stabilization loop: CodeDirectory
    /// bytes are prepared with CMS length hints, signed, and retried until the
    /// generated CMS lengths stop changing.
    /// `codeDirectoryHashingMode` is forwarded through the stabilization pass,
    /// so SHA-256-only signatures sign the SHA-256 primary CodeDirectory and do
    /// not embed an alternate directory.
    public static func signMachOWithIdentity(
        _ data: Data,
        bundleIdentifier: String,
        identity: SigningIdentity,
        entitlementsXML: String = "",
        infoPlist: Data = Data(),
        resourceDirectory: Data = Data(),
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .compatible
    ) throws -> Data {
        let architectureCount = Int(try inspectMachO(data).architectureCount)
        guard architectureCount > 0 else {
            throw RorkSignError.invalidMachO("Mach-O has no architectures.")
        }

        if identity.privateKey.cmsSignatureAlgorithm.usesVariableLengthSignature {
            return try signMachOWithVariableLengthCMS(
                data,
                bundleIdentifier: bundleIdentifier,
                identity: identity,
                entitlementsXML: entitlementsXML,
                infoPlist: infoPlist,
                resourceDirectory: resourceDirectory,
                codeDirectoryHashingMode: codeDirectoryHashingMode,
                architectureCount: architectureCount
            )
        }

        var cmsLengthHints = Array(repeating: 0, count: architectureCount)
        for _ in 0..<8 {
            let prepared = try prepareMachOCMSCodeDirectories(
                data,
                bundleIdentifier: bundleIdentifier,
                subjectCommonName: identity.certificateInfo.subjectCommonName,
                teamIdentifier: identity.teamIdentifier,
                entitlementsXML: entitlementsXML,
                infoPlist: infoPlist,
                resourceDirectory: resourceDirectory,
                cmsSignatureLengthHints: cmsLengthHints,
                codeDirectoryHashingMode: codeDirectoryHashingMode
            )
            let cmsSignatures = try prepared.map { preparedCodeDirectory in
                try makeDetachedCMSSignature(
                    for: preparedCodeDirectory.codeDirectory,
                    alternateCodeDirectory: preparedCodeDirectory.alternateCodeDirectory,
                    identity: identity
                )
            }
            let nextHints = cmsSignatures.map(\.count)
            if nextHints == cmsLengthHints {
                return try signMachOWithCMSBlobs(
                    data,
                    bundleIdentifier: bundleIdentifier,
                    cmsSignatures: cmsSignatures,
                    subjectCommonName: identity.certificateInfo.subjectCommonName,
                    teamIdentifier: identity.teamIdentifier,
                    entitlementsXML: entitlementsXML,
                    infoPlist: infoPlist,
                    resourceDirectory: resourceDirectory,
                    codeDirectoryHashingMode: codeDirectoryHashingMode
                )
            }
            cmsLengthHints = nextHints
        }

        throw RorkSignError.cmsSigning("CMS signature length did not stabilize.")
    }

    /// Signs Mach-O files with CMS algorithms whose DER signature length can vary.
    ///
    /// ECDSA signatures encode two ASN.1 INTEGER values, so the CMS payload can
    /// legitimately be a few bytes shorter or longer on each signing attempt.
    /// Instead of requiring an exact repeat, reserve a CMS payload size, sign the
    /// CodeDirectory generated for that reservation, and let the Mach-O writer
    /// pad outside the SuperBlob so `LC_CODE_SIGNATURE.datasize` stays equal to
    /// the value covered by the CodeDirectory.
    private static func signMachOWithVariableLengthCMS(
        _ data: Data,
        bundleIdentifier: String,
        identity: SigningIdentity,
        entitlementsXML: String,
        infoPlist: Data,
        resourceDirectory: Data,
        codeDirectoryHashingMode: CodeDirectoryHashingMode,
        architectureCount: Int
    ) throws -> Data {
        var cmsLengthHints = Array(repeating: 0, count: architectureCount)
        for _ in 0..<8 {
            let prepared = try prepareMachOCMSCodeDirectories(
                data,
                bundleIdentifier: bundleIdentifier,
                subjectCommonName: identity.certificateInfo.subjectCommonName,
                teamIdentifier: identity.teamIdentifier,
                entitlementsXML: entitlementsXML,
                infoPlist: infoPlist,
                resourceDirectory: resourceDirectory,
                cmsSignatureLengthHints: cmsLengthHints,
                codeDirectoryHashingMode: codeDirectoryHashingMode
            )
            let cmsSignatures = try prepared.map { preparedCodeDirectory in
                try makeDetachedCMSSignature(
                    for: preparedCodeDirectory.codeDirectory,
                    alternateCodeDirectory: preparedCodeDirectory.alternateCodeDirectory,
                    identity: identity
                )
            }

            if zip(cmsSignatures, cmsLengthHints).allSatisfy({ signature, hint in
                hint > 0 && signature.count <= hint
            }) {
                let entitlementsDER = try entitlementsXML.isEmpty
                    ? Data()
                    : DEREntitlementsEncoder.encodeXML(entitlementsXML)
                return try MachOSigner.signWithCMSBlobs(
                    data,
                    bundleIdentifier: bundleIdentifier,
                    subjectCommonName: identity.certificateInfo.subjectCommonName,
                    teamIdentifier: identity.teamIdentifier,
                    entitlementsXML: entitlementsXML,
                    entitlementsDER: entitlementsDER,
                    infoPlist: infoPlist,
                    resourceDirectory: resourceDirectory,
                    cmsSignatures: cmsSignatures,
                    cmsSignatureLengthHints: cmsLengthHints,
                    codeDirectoryHashingMode: codeDirectoryHashingMode
                )
            }

            cmsLengthHints = cmsSignatures.map { signature in
                signature.count + 64
            }
        }

        throw RorkSignError.cmsSigning("CMS signature length did not fit reserved space.")
    }

    /// Decodes a provisioning profile from raw data.
    ///
    /// Both raw plist data and CMS-wrapped `.mobileprovision` data are accepted.
    /// CMS signatures are not validated here; this parser extracts the plist
    /// payload needed by signing and leaves trust decisions to higher layers.
    public static func decodeProvisioningProfile(_ data: Data) throws -> ProvisioningProfile {
        try ProvisioningProfileDecoder.decode(data)
    }

    /// Decodes a provisioning profile from disk.
    public static func decodeProvisioningProfile(at url: URL) throws -> ProvisioningProfile {
        try decodeProvisioningProfile(Data(contentsOf: url))
    }

    /// Returns the Apple team identifier from a provisioning profile payload.
    ///
    /// This is a parsing convenience only. It accepts raw plist or CMS-wrapped
    /// `.mobileprovision` data and returns the decoded team id without checking
    /// any signing credential, certificate trust, expiration, or revocation.
    public static func teamIdentifier(provisioningProfileData: Data) throws -> String {
        try decodeProvisioningProfile(provisioningProfileData).teamIdentifier
    }

    /// Returns the Apple team identifier from a provisioning profile file.
    public static func teamIdentifier(provisioningProfileAt url: URL) throws -> String {
        try teamIdentifier(provisioningProfileData: Data(contentsOf: url))
    }

    /// Returns the Apple team identifier from an already-decoded profile.
    public static func teamIdentifier(provisioningProfile: ProvisioningProfile) -> String {
        provisioningProfile.teamIdentifier
    }

    /// Returns the bundle identifier pattern authorized by a provisioning profile payload.
    public static func authorizedBundleIdentifier(provisioningProfileData: Data) throws -> String? {
        try decodeProvisioningProfile(provisioningProfileData).authorizedBundleIdentifier
    }

    /// Returns the bundle identifier pattern authorized by a provisioning profile file.
    public static func authorizedBundleIdentifier(provisioningProfileAt url: URL) throws -> String? {
        try authorizedBundleIdentifier(provisioningProfileData: Data(contentsOf: url))
    }

    /// Returns the bundle identifier pattern authorized by an already-decoded profile.
    public static func authorizedBundleIdentifier(provisioningProfile: ProvisioningProfile) -> String? {
        provisioningProfile.authorizedBundleIdentifier
    }

    /// Returns the explicit authorized bundle identifier, or `nil` for wildcard profiles.
    public static func explicitAuthorizedBundleIdentifier(provisioningProfileData: Data) throws -> String? {
        try decodeProvisioningProfile(provisioningProfileData).explicitAuthorizedBundleIdentifier
    }

    /// Returns the explicit authorized bundle identifier from a profile file.
    public static func explicitAuthorizedBundleIdentifier(provisioningProfileAt url: URL) throws -> String? {
        try explicitAuthorizedBundleIdentifier(provisioningProfileData: Data(contentsOf: url))
    }

    /// Returns the explicit authorized bundle identifier from an already-decoded profile.
    public static func explicitAuthorizedBundleIdentifier(provisioningProfile: ProvisioningProfile) -> String? {
        provisioningProfile.explicitAuthorizedBundleIdentifier
    }

    /// Inspects a copied app bundle before app signing mutates it.
    ///
    /// The report previews the root and nested bundle identifiers that
    /// app signing would write for `replacementBundleIdentifier`. It does
    /// not validate provisioning profiles and does not change files on disk.
    public static func inspectApp(
        at bundleURL: URL,
        replacementBundleIdentifier: String
    ) throws -> AppInspectionReport {
        try AppBundleInspector.inspect(
            rootBundleURL: bundleURL,
            replacementBundleIdentifier: replacementBundleIdentifier
        )
    }

    /// Returns the Apple team identifier after validating a profile/credential pair.
    ///
    /// The method decodes `provisioningProfileData`, loads `credentialData` as a
    /// PEM/DER private key or PKCS#12 container, and verifies that the private key
    /// matches one of the profile's developer certificates before returning the
    /// profile's team id. This is the cheap credential preflight used before
    /// signing work begins, so callers can reject mismatched profile/key uploads
    /// without mutating any bundle.
    ///
    /// The check proves possession of a private key authorized by the profile.
    /// It does not validate Apple trust roots, certificate policy, revocation,
    /// or profile expiration; callers that surface certificate health should
    /// inspect `SigningIdentity.certificateExpirationDate` and run their own
    /// policy checks.
    public static func validatedTeamIdentifier(
        provisioningProfileData: Data,
        credentialData: Data,
        password: String = ""
    ) throws -> String {
        let profile = try decodeProvisioningProfile(provisioningProfileData)
        _ = try SigningIdentity(
            provisioningProfile: profile,
            credentialData: credentialData,
            password: password
        )
        return profile.teamIdentifier
    }

    /// Returns the Apple team identifier after validating a decoded profile.
    ///
    /// Use this overload when the caller already decoded the profile for other
    /// signing decisions. Validation is identical to
    /// `validatedTeamIdentifier(provisioningProfileData:credentialData:password:)`:
    /// the supplied credential must contain a private key matching one of the
    /// profile's developer certificates.
    public static func validatedTeamIdentifier(
        provisioningProfile: ProvisioningProfile,
        credentialData: Data,
        password: String = ""
    ) throws -> String {
        _ = try SigningIdentity(
            provisioningProfile: provisioningProfile,
            credentialData: credentialData,
            password: password
        )
        return provisioningProfile.teamIdentifier
    }

    /// Builds the `_CodeSignature/CodeResources` plist for an app-style bundle.
    ///
    /// The returned bytes are deterministic for a fixed filesystem tree and can
    /// be passed to `signMachOAdHoc` as `resourceDirectory`.
    public static func buildCodeResources(forBundleAt bundleURL: URL) throws -> Data {
        try CodeResourcesBuilder.build(bundleURL: bundleURL)
    }

    /// Writes `_CodeSignature/CodeResources` for an app-style bundle.
    ///
    /// Existing CodeResources output is replaced atomically.
    @discardableResult
    public static func sealBundleResources(at bundleURL: URL) throws -> URL {
        try CodeResourcesBuilder.write(bundleURL: bundleURL)
    }

    /// Verifies an app-style bundle against its existing CodeResources seal.
    ///
    /// The report checks resource hashes, symlink targets, required missing
    /// resources, and current resources that should be sealed but are not listed
    /// in `_CodeSignature/CodeResources`.
    public static func verifyCodeResources(forBundleAt bundleURL: URL) throws -> CodeResourcesVerificationReport {
        try CodeResourcesBuilder.verify(bundleURL: bundleURL)
    }

    /// Verifies every CodeResources seal found in the root bundle and nested bundles.
    ///
    /// Bundles without `_CodeSignature/CodeResources` are skipped so loose
    /// inspection flows can still fall back to executable/profile checks. Use
    /// `verifyCodeResources(forBundleAt:)` when a missing root seal should be an
    /// error.
    public static func verifyCodeResourcesRecursively(
        forBundleAt bundleURL: URL
    ) throws -> [BundleCodeResourcesVerificationReport] {
        try CodeResourcesBuilder.verifyRecursively(bundleURL: bundleURL)
    }

    /// Signs an app-style bundle inside-out with ad-hoc Mach-O signatures.
    ///
    /// This convenience overload applies `entitlementsXML` only to the root
    /// bundle executable.
    @discardableResult
    public static func signBundleAdHoc(
        at bundleURL: URL,
        entitlementsXML: String = ""
    ) throws -> BundleSigningReport {
        try signBundleAdHoc(
            at: bundleURL,
            options: BundleSigningOptions(defaultEntitlementsXML: entitlementsXML)
        )
    }

    /// Signs an app-style bundle inside-out with explicit signing assets.
    ///
    /// Nested bundles are signed before their parents. Provisioning profiles are
    /// embedded before resource sealing so the profile is protected by
    /// CodeResources.
    @discardableResult
    public static func signBundleAdHoc(
        at bundleURL: URL,
        options: BundleSigningOptions
    ) throws -> BundleSigningReport {
        try BundleSigner.signAdHoc(bundleURL: bundleURL, options: options)
    }

    /// Signs an app-style bundle inside-out with identity-backed CMS signatures.
    @discardableResult
    public static func signBundleWithIdentity(
        at bundleURL: URL,
        identity: SigningIdentity,
        options: BundleSigningOptions = BundleSigningOptions()
    ) throws -> BundleSigningReport {
        try BundleSigner.signWithIdentity(
            bundleURL: bundleURL,
            identity: identity,
            options: options
        )
    }

    /// Signs a bundle with a provisioning profile and private-key credential.
    ///
    /// This is the library-level preserve-identifier signing path. The profile
    /// is decoded, the supplied credential is matched against one of the
    /// profile's developer certificates, and the resulting identity signs the
    /// bundle inside-out.
    ///
    /// By default the profile is used for entitlements and certificate
    /// authorization but is not embedded into the bundle, matching the existing
    /// preserve-identifier signer behavior. Profile entitlements are expanded to the
    /// bundle identifiers on disk so wildcard or host-profile App IDs do not
    /// leak into the signed executable. Set `embedProvisioningProfile` when the
    /// output bundle should carry `embedded.mobileprovision`; embedded profiles
    /// must authorize the bundle identifier they are written into.
    @discardableResult
    public static func signBundleWithCredential(
        at bundleURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String = "",
        embedProvisioningProfile: Bool = false,
        codeDirectoryHashingMode: CodeDirectoryHashingMode = .sha256Only,
        dylibInjections: [BundleDylibInjection] = [],
        dylibLoadCommandsToRemove: [String] = []
    ) throws -> BundleSigningReport {
        let identity = try SigningIdentity(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password
        )
        return try BundleSigner.signWithCredential(
            bundleURL: bundleURL,
            identity: identity,
            options: BundleSigningOptions(
                rootProvisioningProfile: provisioningProfileData,
                embedProvisioningProfiles: embedProvisioningProfile,
                codeDirectoryHashingMode: codeDirectoryHashingMode,
                dylibInjections: dylibInjections,
                dylibLoadCommandsToRemove: dylibLoadCommandsToRemove
            )
        )
    }

    /// Signs a bundle with a provisioning profile, private-key credential, and explicit options.
    ///
    /// This overload preserves the same profile semantics as
    /// ``signBundleWithCredential(at:provisioningProfileData:credentialData:password:embedProvisioningProfile:codeDirectoryHashingMode:dylibInjections:dylibLoadCommandsToRemove:)``
    /// while letting callers supply the full bundle-signing option surface.
    /// In particular, non-embedded profile signing skips bundle-identifier
    /// authorization so hosts can sign guest bundles that intentionally preserve
    /// their original identifiers.
    @discardableResult
    public static func signBundleWithCredential(
        at bundleURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String = "",
        options: BundleSigningOptions
    ) throws -> BundleSigningReport {
        let identity = try SigningIdentity(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password
        )
        var resolvedOptions = options
        if resolvedOptions.rootProvisioningProfile == nil {
            resolvedOptions.rootProvisioningProfile = provisioningProfileData
        }
        return try BundleSigner.signWithCredential(
            bundleURL: bundleURL,
            identity: identity,
            options: resolvedOptions
        )
    }

    /// Signs a hosted bundle with identity-backed CMS signatures.
    ///
    /// The signing pass temporarily uses `options.hostExecutableURL` and
    /// `options.hostBundleIdentifier` as the root executable identity, signs
    /// the original bundle executable as loose code under the same identifier,
    /// seals resources, signs the temporary stub, and then restores the original
    /// `Info.plist` while removing the stub. Any root provisioning profile
    /// supplied through `options.bundleSigningOptions` must authorize the host
    /// bundle identifier.
    @discardableResult
    public static func signHostedBundleWithIdentity(
        at bundleURL: URL,
        identity: SigningIdentity,
        options: HostedBundleSigningOptions
    ) throws -> BundleSigningReport {
        try BundleSigner.signHostedWithIdentity(
            bundleURL: bundleURL,
            identity: identity,
            options: options
        )
    }

    /// Signs a hosted bundle with a provisioning profile and private-key credential.
    ///
    /// The supplied profile creates and authorizes the signing identity. When
    /// `options.bundleSigningOptions.rootProvisioningProfile` is empty, the
    /// profile is also used as the root provisioning profile for entitlement
    /// derivation and host-bundle-identifier authorization during the temporary
    /// signing pass.
    @discardableResult
    public static func signHostedBundleWithCredential(
        at bundleURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String = "",
        options: HostedBundleSigningOptions
    ) throws -> BundleSigningReport {
        let identity = try SigningIdentity(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password
        )
        var resolvedOptions = options
        if resolvedOptions.bundleSigningOptions.rootProvisioningProfile == nil {
            resolvedOptions.bundleSigningOptions.rootProvisioningProfile = provisioningProfileData
        }
        return try BundleSigner.signHostedWithIdentity(
            bundleURL: bundleURL,
            identity: identity,
            options: resolvedOptions
        )
    }

    /// Signs a standalone `.framework` bundle with an ad-hoc Mach-O signature.
    ///
    /// The framework is sealed and signed in place. Unlike app bundle signing,
    /// framework signing never embeds provisioning profiles and does not derive
    /// entitlements from a profile fallback.
    @discardableResult
    public static func signFrameworkAdHoc(
        at frameworkURL: URL,
        options: FrameworkSigningOptions = FrameworkSigningOptions()
    ) throws -> BundleSigningReport {
        try BundleSigner.signFrameworkAdHoc(
            frameworkURL: frameworkURL,
            options: options
        )
    }

    /// Signs a standalone `.framework` bundle with identity-backed CMS signatures.
    ///
    /// The identity supplies the certificate chain and private key used for the
    /// framework executable. Entitlement input is supplied only when provided
    /// through `options.entitlementsXML`.
    @discardableResult
    public static func signFrameworkWithIdentity(
        at frameworkURL: URL,
        identity: SigningIdentity,
        options: FrameworkSigningOptions = FrameworkSigningOptions()
    ) throws -> BundleSigningReport {
        try BundleSigner.signFrameworkWithIdentity(
            frameworkURL: frameworkURL,
            identity: identity,
            options: options
        )
    }

    /// Signs a standalone `.framework` bundle with a provisioning profile and credential.
    ///
    /// The profile is decoded only to select and authorize the developer
    /// certificate that matches the supplied credential. It is not embedded into
    /// the framework and its app entitlements are not copied onto the framework
    /// executable. Entitlement input is supplied only when the caller provides
    /// explicit framework entitlements in `options`.
    @discardableResult
    public static func signFrameworkWithCredential(
        at frameworkURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String = "",
        options: FrameworkSigningOptions = FrameworkSigningOptions()
    ) throws -> BundleSigningReport {
        let identity = try SigningIdentity(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password
        )
        return try BundleSigner.signFrameworkWithIdentity(
            frameworkURL: frameworkURL,
            identity: identity,
            options: options
        )
    }

    /// Rewrites and signs an app bundle with ad-hoc signatures.
    ///
    /// This is the app-level flow used when a copied app must become its own
    /// installable app under a new root bundle identifier. The method rewrites
    /// app and extension `Info.plist` identifiers, derives entitlements
    /// from the supplied provisioning profiles, embeds those profiles before
    /// sealing resources, applies the optional Watch provisioning-profile
    /// fallback for embedded Watch apps, and then performs the regular
    /// inside-out signing pass.
    @discardableResult
    public static func signBundle(
        at bundleURL: URL,
        options: AppSigningOptions
    ) throws -> BundleSigningReport {
        try AppBundleSigner.signAdHoc(
            bundleURL: bundleURL,
            options: options
        )
    }

    /// Rewrites and signs an app bundle with CMS signatures.
    ///
    /// The supplied `identity` must be authorized by every provisioning profile
    /// in `options`, including the optional Watch fallback profile. The returned
    /// report describes the final sealing and Mach-O rewrite pass; identifier
    /// rewrites happen before that pass and are visible on disk immediately when
    /// the method succeeds.
    @discardableResult
    public static func signBundle(
        at bundleURL: URL,
        identity: SigningIdentity,
        options: AppSigningOptions
    ) throws -> BundleSigningReport {
        try AppBundleSigner.signWithIdentity(
            bundleURL: bundleURL,
            identity: identity,
            options: options
        )
    }

    /// Rewrites and signs an app bundle with a profile/credential pair.
    ///
    /// The root profile and credential create the signing identity, optional
    /// per-bundle profiles cover app extensions or embedded apps, and
    /// `watchProvisioningProfileData` supplies a Watch fallback profile used for
    /// embedded Watch apps. Metadata and cleanup options come from
    /// `options`. The app-signing pass always embeds the selected profiles
    /// before sealing resources. When `options.rootEntitlementsXML` is non-empty, it
    /// is embedded into the rewritten root executable instead of the root
    /// profile's entitlement dictionary.
    @discardableResult
    public static func signBundle(
        at bundleURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String = "",
        options: AppSigningOptions
    ) throws -> BundleSigningReport {
        let identity = try SigningIdentity(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password
        )
        var resolvedOptions = options
        if resolvedOptions.rootProvisioningProfile == nil {
            resolvedOptions.rootProvisioningProfile = provisioningProfileData
        }
        return try signBundle(
            at: bundleURL,
            identity: identity,
            options: resolvedOptions
        )
    }

    /// Signs the app inside an IPA archive with ad-hoc signatures.
    ///
    /// The input archive must contain exactly one signable `Payload/*.app`
    /// bundle. The output archive is replaced if it already exists.
    @discardableResult
    public static func signIPAAdHoc(
        at archiveURL: URL,
        outputURL: URL,
        options: BundleSigningOptions = BundleSigningOptions(),
        archiveCompressionMode: ArchiveCompressionMode = .stored,
        temporaryDirectory: URL? = nil
    ) throws -> IPAArchiveSigningReport {
        try IPAArchiveSigner.signAdHoc(
            archiveURL: archiveURL,
            outputURL: outputURL,
            options: options,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        )
    }

    /// Signs the app inside an IPA archive with identity-backed CMS signatures.
    @discardableResult
    public static func signIPAWithIdentity(
        at archiveURL: URL,
        outputURL: URL,
        identity: SigningIdentity,
        options: BundleSigningOptions = BundleSigningOptions(),
        archiveCompressionMode: ArchiveCompressionMode = .stored,
        temporaryDirectory: URL? = nil
    ) throws -> IPAArchiveSigningReport {
        try IPAArchiveSigner.signWithIdentity(
            archiveURL: archiveURL,
            outputURL: outputURL,
            identity: identity,
            options: options,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        )
    }

    /// Rewrites and signs the app inside an IPA with ad-hoc signatures.
    @discardableResult
    public static func signIPA(
        at archiveURL: URL,
        outputURL: URL,
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode = .stored,
        temporaryDirectory: URL? = nil
    ) throws -> IPAArchiveSigningReport {
        try IPAArchiveSigner.signAppAdHoc(
            archiveURL: archiveURL,
            outputURL: outputURL,
            options: options,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        )
    }

    /// Rewrites and signs the app inside an IPA with CMS signatures.
    @discardableResult
    public static func signIPA(
        at archiveURL: URL,
        outputURL: URL,
        identity: SigningIdentity,
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode = .stored,
        temporaryDirectory: URL? = nil
    ) throws -> IPAArchiveSigningReport {
        try IPAArchiveSigner.signAppWithIdentity(
            archiveURL: archiveURL,
            outputURL: outputURL,
            identity: identity,
            options: options,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        )
    }

    /// Packages a root-level app-bundle ZIP and signs it as an IPA.
    ///
    /// This package-only entry point supports the browser facade without
    /// expanding the filesystem-based public API. Native callers should keep
    /// using the existing IPA signing overloads.
    @discardableResult
    package static func signAppArchive(
        at archiveURL: URL,
        outputURL: URL,
        identity: SigningIdentity,
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode = .stored,
        temporaryDirectory: URL? = nil
    ) throws -> IPAArchiveSigningReport {
        try IPAArchiveSigner.signAppArchiveWithIdentity(
            archiveURL: archiveURL,
            outputURL: outputURL,
            identity: identity,
            options: options,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        )
    }

    /// Rewrites and signs the app inside an IPA with a profile/credential pair.
    ///
    /// This is the archive equivalent of
    /// `signBundle(at:provisioningProfileData:credentialData:password:options:)`:
    /// the archive is unpacked, the payload app is rewritten using `options`,
    /// selected profiles are embedded and sealed, and the app is repacked into
    /// `outputURL`.
    @discardableResult
    public static func signIPA(
        at archiveURL: URL,
        outputURL: URL,
        provisioningProfileData: Data,
        credentialData: Data,
        password: String = "",
        options: AppSigningOptions,
        archiveCompressionMode: ArchiveCompressionMode = .stored,
        temporaryDirectory: URL? = nil
    ) throws -> IPAArchiveSigningReport {
        let identity = try SigningIdentity(
            provisioningProfileData: provisioningProfileData,
            credentialData: credentialData,
            password: password
        )
        var resolvedOptions = options
        if resolvedOptions.rootProvisioningProfile == nil {
            resolvedOptions.rootProvisioningProfile = provisioningProfileData
        }
        return try signIPA(
            at: archiveURL,
            outputURL: outputURL,
            identity: identity,
            options: resolvedOptions,
            archiveCompressionMode: archiveCompressionMode,
            temporaryDirectory: temporaryDirectory
        )
    }

    /// Normalizes a certificate input that may be DER or PEM encoded.
    private static func certificateDER(from data: Data) throws -> Data {
        try certificateChainDER(from: data)[0]
    }

    /// Normalizes a certificate or certificate-chain input.
    ///
    /// PEM files can contain a leaf followed by intermediate certificates. The
    /// first certificate is the signing leaf by convention; any remaining
    /// certificates are chain material that should be preserved in CMS output.
    private static func certificateChainDER(from data: Data) throws -> [Data] {
        try SigningIdentity.certificateChainDER(from: data)
    }

    /// Builds a public check report from DER certificate bytes.
    static func certificateCheckReport(fromDER certificateDER: Data) throws -> CertificateCheckReport {
        let info = try CertificateInfo.parse(certificateDER)
        return CertificateCheckReport(
            subjectCommonName: info.subjectCommonName,
            subjectOrganizationName: info.subjectOrganizationName,
            issuerCommonName: info.issuerCommonName,
            ocspResponderURLs: info.ocspResponderURLs,
            crlDistributionPointURLs: info.crlDistributionPointURLs,
            serialNumberHex: info.serialNumberHex,
            keyAlgorithm: info.keyAlgorithm,
            certificateKind: certificateKind(fromCommonName: info.subjectCommonName),
            isCertificateAuthority: info.isCertificateAuthority,
            pathLengthConstraint: info.pathLengthConstraint,
            hasKeyUsageExtension: info.hasKeyUsageExtension,
            keyUsage: info.keyUsage,
            validityStartDate: info.notBefore,
            expirationDate: info.notAfter
        )
    }

    /// Builds a public check report from a decoded provisioning profile.
    private static func provisioningProfileCheckReport(
        from profile: ProvisioningProfile
    ) throws -> ProvisioningProfileCheckReport {
        let certificates = try profile.developerCertificatesDER.map(certificateCheckReport(fromDER:))
        return ProvisioningProfileCheckReport(
            teamIdentifier: profile.teamIdentifier,
            applicationIdentifier: profile.applicationIdentifier,
            expirationDate: profile.expirationDate,
            developerCertificates: certificates
        )
    }

    /// Builds a public check report from a loaded signing identity.
    private static func signingCredentialCheckReport(
        from identity: SigningIdentity
    ) throws -> SigningCredentialCheckReport {
        try SigningCredentialCheckReport(
            leafCertificate: certificateCheckReport(fromDER: identity.certificateDER),
            additionalCertificates: identity.additionalCertificatesDER.map(certificateCheckReport(fromDER:))
        )
    }

    /// Returns the CMS SignedData payload stored in a BlobWrapper slot.
    private static func cmsPayload(fromBlobWrapper wrapper: Data) throws -> Data {
        guard let magic = wrapper.readUInt32BE(at: 0),
              magic == 0xfade0b01,
              let length = wrapper.readUInt32BE(at: 4),
              length >= 8,
              Int(length) <= wrapper.count else {
            throw RorkSignError.cmsSigning("Embedded CMS BlobWrapper is malformed.")
        }
        return wrapper.subdata(in: 8..<Int(length))
    }

    /// Mirrors common Apple signing certificate names in local diagnostics.
    private static func certificateKind(fromCommonName commonName: String) -> String {
        if commonName.contains("Apple Distribution") {
            return "Apple Distribution"
        }
        if commonName.contains("iPhone Distribution") {
            return "iPhone Distribution"
        }
        if commonName.contains("Apple Development") {
            return "Apple Development"
        }
        if commonName.contains("iPhone Developer") {
            return "iPhone Developer"
        }
        if commonName.contains("Mac Developer") {
            return "Mac Developer"
        }
        if commonName.contains("Developer ID Application") {
            return "Developer ID Application"
        }
        if commonName.contains("Developer ID Installer") {
            return "Developer ID Installer"
        }
        return "Certificate"
    }
}

/// Reads a bundle identifier without instantiating `Bundle`.
///
/// Signing operates on filesystem artifacts that may not be loadable by the
/// current process, so this helper reads `Info.plist` directly.
private func bundleIdentifier(at bundleURL: URL) throws -> String {
    let infoURL = bundleURL.appendingPathComponent("Info.plist")
    let data = try Data(contentsOf: infoURL)
    let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    guard let dictionary = plist as? [String: Any],
          let identifier = dictionary["CFBundleIdentifier"] as? String else {
        throw RorkSignError.invalidBundle("Bundle Info.plist has no CFBundleIdentifier: \(infoURL.path)")
    }
    let trimmed = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
        throw RorkSignError.invalidBundle("Bundle Info.plist has an empty CFBundleIdentifier: \(infoURL.path)")
    }
    return trimmed
}
