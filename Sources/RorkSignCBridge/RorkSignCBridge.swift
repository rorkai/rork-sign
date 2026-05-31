import Foundation
import RorkSign

/// Swift implementation behind the public C ABI.
///
/// The C boundary intentionally deals only in binary property lists and
/// allocated byte buffers. All parsing, signing, resource sealing, CMS work,
/// and Mach-O rewriting remains inside the Swift `RorkSign` module.
enum RorkSignCBridge {
    typealias Request = [String: Any]

    enum Operation: Int32 {
        case version = 0
        case inspectMachO = 1
        case extractBundleMetadata = 2
        case extractIPAMetadata = 3
        case checkCertificate = 4
        case checkCertificateChain = 5
        case validateCertificateChain = 6
        case makeOCSPRequest = 7
        case parseOCSPResponse = 8
        case verifyOCSPResponseSignature = 9
        case validateOCSPResponse = 10
        case checkProvisioningProfile = 11
        case checkPKCS12Identity = 12
        case checkSigningIdentity = 13
        case checkProfileCredential = 14
        case checkMachOCodeSignatures = 15
        case readEmbeddedCodeSignatures = 16
        case dylibLoadCommands = 17
        case injectDylibLoadCommand = 18
        case removeDylibLoadCommands = 19
        case signMachOAdHoc = 20
        case prepareMachOCMSCodeDirectories = 21
        case signMachOWithCMSBlobs = 22
        case makeDetachedCMSSignature = 23
        case verifyDetachedCMSSignature = 24
        case signMachOWithIdentity = 25
        case decodeProvisioningProfile = 26
        case validatedTeamIdentifier = 27
        case buildCodeResources = 28
        case sealBundleResources = 29
        case verifyCodeResources = 30
        case verifyCodeResourcesRecursively = 31
        case signBundleAdHoc = 32
        case signBundleWithIdentity = 33
        case signBundleWithCredential = 34
        case signStandaloneBundleAdHoc = 35
        case signStandaloneBundleWithIdentity = 36
        case signStandaloneBundleWithCredential = 37
        case signIPAAdHoc = 38
        case signIPAWithIdentity = 39
        case signStandaloneIPAAdHoc = 40
        case signStandaloneIPAWithIdentity = 41
        case signStandaloneIPAWithCredential = 42
    }

    static func execute(operation rawOperation: Int32, requestBytes: UnsafeRawPointer?, requestLength: Int) throws -> Data {
        guard let operation = Operation(rawValue: rawOperation) else {
            throw inputError("Unknown RorkSign operation: \(rawOperation).")
        }
        let request = try decodeRequest(bytes: requestBytes, length: requestLength)
        let response: Any

        switch operation {
        case .version:
            response = ["version": RorkSigner.version]

        case .inspectMachO:
            response = ["report": propertyListValue(try RorkSigner.inspectMachO(data(from: request)))]

        case .extractBundleMetadata:
            response = ["report": propertyListValue(try RorkSigner.extractBundleMetadata(
                at: url(from: request, key: "bundlePath"),
                outputDirectory: optionalURL(from: request, key: "outputDirectoryPath"),
                sourceArchiveURL: optionalURL(from: request, key: "sourceArchivePath"),
                timestamp: date(from: request, key: "timestamp") ?? Date()
            ))]

        case .extractIPAMetadata:
            response = ["report": propertyListValue(try RorkSigner.extractIPAMetadata(
                at: url(from: request, key: "archivePath"),
                outputDirectory: optionalURL(from: request, key: "outputDirectoryPath"),
                timestamp: date(from: request, key: "timestamp") ?? Date(),
                temporaryDirectory: optionalURL(from: request, key: "temporaryDirectoryPath")
            ))]

        case .checkCertificate:
            response = ["report": propertyListValue(try RorkSigner.checkCertificate(data(from: request)))]

        case .checkCertificateChain:
            response = ["reports": propertyListValue(try RorkSigner.checkCertificateChain(data(from: request)))]

        case .validateCertificateChain:
            if hasIdentityInput(request) {
                response = ["report": propertyListValue(try RorkSigner.validateCertificateChain(
                    identity: identity(from: request),
                    validationDate: date(from: request, key: "validationDate") ?? Date()
                ))]
            } else {
                response = ["report": propertyListValue(try RorkSigner.validateCertificateChain(
                    data(from: request),
                    validationDate: date(from: request, key: "validationDate") ?? Date()
                ))]
            }

        case .makeOCSPRequest:
            response = ["report": propertyListValue(try RorkSigner.makeOCSPRequest(
                certificateData: data(from: request, key: "certificateData"),
                issuerCertificateData: data(from: request, key: "issuerCertificateData")
            ))]

        case .parseOCSPResponse:
            response = ["report": propertyListValue(try RorkSigner.parseOCSPResponse(data(from: request)))]

        case .verifyOCSPResponseSignature:
            response = ["report": propertyListValue(try RorkSigner.verifyOCSPResponseSignature(
                data(from: request, key: "responseData", fallbackKey: "data"),
                responderCertificateData: optionalData(from: request, key: "responderCertificateData")
            ))]

        case .validateOCSPResponse:
            let ocspRequest = try RorkSigner.makeOCSPRequest(
                certificateData: data(from: request, key: "certificateData"),
                issuerCertificateData: data(from: request, key: "issuerCertificateData")
            )
            response = ["report": propertyListValue(try RorkSigner.validateOCSPResponse(
                data(from: request, key: "responseData", fallbackKey: "data"),
                matching: ocspRequest,
                responderCertificateData: optionalData(from: request, key: "responderCertificateData"),
                issuerCertificateData: optionalData(from: request, key: "issuerCertificateData"),
                policy: ocspPolicy(from: request)
            ))]

        case .checkProvisioningProfile:
            response = ["report": propertyListValue(try RorkSigner.checkProvisioningProfile(data(from: request)))]

        case .checkPKCS12Identity:
            response = ["report": propertyListValue(try RorkSigner.checkPKCS12Identity(
                data(from: request, key: "credentialData", fallbackKey: "data"),
                password: string(from: request, key: "password", default: "")
            ))]

        case .checkSigningIdentity:
            response = ["report": propertyListValue(try RorkSigner.checkSigningIdentity(
                certificateData: data(from: request, key: "certificateData"),
                privateKeyData: data(from: request, key: "privateKeyData", fallbackKey: "credentialData"),
                password: string(from: request, key: "password", default: "")
            ))]

        case .checkProfileCredential:
            response = ["report": propertyListValue(try RorkSigner.checkProfileCredential(
                provisioningProfileData: data(from: request, key: "provisioningProfileData"),
                credentialData: data(from: request, key: "credentialData"),
                password: string(from: request, key: "password", default: "")
            ))]

        case .checkMachOCodeSignatures:
            response = ["reports": propertyListValue(try RorkSigner.checkMachOCodeSignatures(data(from: request)))]

        case .readEmbeddedCodeSignatures:
            response = ["reports": propertyListValue(try RorkSigner.readEmbeddedCodeSignatures(in: data(from: request)))]

        case .dylibLoadCommands:
            response = ["commands": propertyListValue(try RorkSigner.dylibLoadCommands(in: data(from: request)))]

        case .injectDylibLoadCommand:
            response = ["data": try RorkSigner.injectDylibLoadCommand(
                into: data(from: request),
                path: string(from: request, key: "path"),
                weak: bool(from: request, key: "weak", default: false)
            )]

        case .removeDylibLoadCommands:
            response = ["data": try RorkSigner.removeDylibLoadCommands(
                from: data(from: request),
                matching: stringArray(from: request, key: "paths")
            )]

        case .signMachOAdHoc:
            response = ["data": try RorkSigner.signMachOAdHoc(
                data(from: request),
                bundleIdentifier: string(from: request, key: "bundleIdentifier"),
                entitlementsXML: string(from: request, key: "entitlementsXML", default: ""),
                infoPlist: optionalData(from: request, key: "infoPlistData") ?? Data(),
                resourceDirectory: optionalData(from: request, key: "resourceDirectoryData") ?? Data(),
                codeDirectoryHashingMode: hashingMode(from: request, default: .compatible)
            )]

        case .prepareMachOCMSCodeDirectories:
            response = ["reports": propertyListValue(try RorkSigner.prepareMachOCMSCodeDirectories(
                data(from: request),
                bundleIdentifier: string(from: request, key: "bundleIdentifier"),
                subjectCommonName: string(from: request, key: "subjectCommonName", default: ""),
                entitlementsXML: string(from: request, key: "entitlementsXML", default: ""),
                infoPlist: optionalData(from: request, key: "infoPlistData") ?? Data(),
                resourceDirectory: optionalData(from: request, key: "resourceDirectoryData") ?? Data(),
                cmsSignatureLengthHints: intArray(from: request, key: "cmsSignatureLengthHints"),
                codeDirectoryHashingMode: hashingMode(from: request, default: .compatible)
            ))]

        case .signMachOWithCMSBlobs:
            response = ["data": try RorkSigner.signMachOWithCMSBlobs(
                data(from: request),
                bundleIdentifier: string(from: request, key: "bundleIdentifier"),
                cmsSignatures: dataArray(from: request, key: "cmsSignatures", singleKey: "cmsSignatureData"),
                subjectCommonName: string(from: request, key: "subjectCommonName", default: ""),
                entitlementsXML: string(from: request, key: "entitlementsXML", default: ""),
                infoPlist: optionalData(from: request, key: "infoPlistData") ?? Data(),
                resourceDirectory: optionalData(from: request, key: "resourceDirectoryData") ?? Data(),
                codeDirectoryHashingMode: hashingMode(from: request, default: .compatible)
            )]

        case .makeDetachedCMSSignature:
            response = ["data": try RorkSigner.makeDetachedCMSSignature(
                for: data(from: request, key: "contentData", fallbackKey: "data"),
                alternateCodeDirectory: optionalData(from: request, key: "alternateCodeDirectoryData") ?? Data(),
                identity: identity(from: request)
            )]

        case .verifyDetachedCMSSignature:
            response = ["report": propertyListValue(try RorkSigner.verifyDetachedCMSSignature(
                data(from: request, key: "cmsData", fallbackKey: "data"),
                content: data(from: request, key: "contentData")
            ))]

        case .signMachOWithIdentity:
            response = ["data": try RorkSigner.signMachOWithIdentity(
                data(from: request),
                bundleIdentifier: string(from: request, key: "bundleIdentifier"),
                identity: identity(from: request),
                entitlementsXML: string(from: request, key: "entitlementsXML", default: ""),
                infoPlist: optionalData(from: request, key: "infoPlistData") ?? Data(),
                resourceDirectory: optionalData(from: request, key: "resourceDirectoryData") ?? Data(),
                codeDirectoryHashingMode: hashingMode(from: request, default: .compatible)
            )]

        case .decodeProvisioningProfile:
            response = ["report": propertyListValue(try RorkSigner.decodeProvisioningProfile(data(from: request)))]

        case .validatedTeamIdentifier:
            let teamIdentifier = try RorkSigner.validatedTeamIdentifier(
                provisioningProfileData: data(from: request, key: "provisioningProfileData"),
                credentialData: data(from: request, key: "credentialData"),
                password: string(from: request, key: "password", default: "")
            )
            response = ["teamIdentifier": teamIdentifier, "value": teamIdentifier]

        case .buildCodeResources:
            response = ["data": try RorkSigner.buildCodeResources(forBundleAt: url(from: request, key: "bundlePath"))]

        case .sealBundleResources:
            let outputURL = try RorkSigner.sealBundleResources(at: url(from: request, key: "bundlePath"))
            response = ["urlPath": outputURL.path]

        case .verifyCodeResources:
            response = ["report": propertyListValue(try RorkSigner.verifyCodeResources(
                forBundleAt: url(from: request, key: "bundlePath")
            ))]

        case .verifyCodeResourcesRecursively:
            response = ["reports": propertyListValue(try RorkSigner.verifyCodeResourcesRecursively(
                forBundleAt: url(from: request, key: "bundlePath")
            ))]

        case .signBundleAdHoc:
            response = ["report": propertyListValue(try RorkSigner.signBundleAdHoc(
                at: url(from: request, key: "bundlePath"),
                options: bundleOptions(from: request, defaultHashingMode: .compatible)
            ))]

        case .signBundleWithIdentity:
            response = ["report": propertyListValue(try RorkSigner.signBundleWithIdentity(
                at: url(from: request, key: "bundlePath"),
                identity: identity(from: request),
                options: bundleOptions(from: request, defaultHashingMode: .compatible)
            ))]

        case .signBundleWithCredential:
            response = ["report": propertyListValue(try RorkSigner.signBundleWithCredential(
                at: url(from: request, key: "bundlePath"),
                provisioningProfileData: data(from: request, key: "provisioningProfileData"),
                credentialData: data(from: request, key: "credentialData"),
                password: string(from: request, key: "password", default: ""),
                embedProvisioningProfile: bool(from: request, key: "embedProvisioningProfile", default: false),
                codeDirectoryHashingMode: hashingMode(from: request, default: .compatible),
                dylibInjections: dylibInjections(from: request),
                dylibLoadCommandsToRemove: stringArray(from: request, key: "dylibLoadCommandsToRemove")
            ))]

        case .signStandaloneBundleAdHoc:
            response = ["report": propertyListValue(try RorkSigner.signStandaloneBundleAdHoc(
                at: url(from: request, key: "bundlePath"),
                options: standaloneOptions(from: request)
            ))]

        case .signStandaloneBundleWithIdentity:
            response = ["report": propertyListValue(try RorkSigner.signStandaloneBundleWithIdentity(
                at: url(from: request, key: "bundlePath"),
                identity: identity(from: request),
                options: standaloneOptions(from: request)
            ))]

        case .signStandaloneBundleWithCredential:
            response = ["report": propertyListValue(try RorkSigner.signStandaloneBundleWithCredential(
                at: url(from: request, key: "bundlePath"),
                provisioningProfileData: data(from: request, key: "provisioningProfileData"),
                credentialData: data(from: request, key: "credentialData"),
                password: string(from: request, key: "password", default: ""),
                bundleIdentifier: string(from: request, key: "bundleIdentifier"),
                provisioningProfilesByBundleIdentifier: dataDictionary(from: request, key: "provisioningProfilesByBundleIdentifier"),
                watchProvisioningProfileData: optionalData(from: request, key: "watchProvisioningProfileData"),
                appGroupIdentifiers: stringArray(from: request, key: "appGroupIdentifiers"),
                rootEntitlementsXML: string(from: request, key: "rootEntitlementsXML", default: ""),
                displayName: optionalString(from: request, key: "displayName"),
                bundleVersion: optionalString(from: request, key: "bundleVersion"),
                minimumOSVersion: optionalString(from: request, key: "minimumOSVersion"),
                enableDocuments: bool(from: request, key: "enableDocuments", default: false),
                removeExtensions: bool(from: request, key: "removeExtensions", default: false),
                removeWatchApps: bool(from: request, key: "removeWatchApps", default: false),
                removeUISupportedDevices: bool(from: request, key: "removeUISupportedDevices", default: false),
                embedProvisioningProfiles: bool(from: request, key: "embedProvisioningProfiles", default: true),
                dylibInjections: dylibInjections(from: request),
                dylibLoadCommandsToRemove: stringArray(from: request, key: "dylibLoadCommandsToRemove"),
                codeDirectoryHashingMode: hashingMode(from: request, default: .sha256Only)
            ))]

        case .signIPAAdHoc:
            response = ["report": propertyListValue(try RorkSigner.signIPAAdHoc(
                at: url(from: request, key: "archivePath"),
                outputURL: url(from: request, key: "outputArchivePath"),
                options: bundleOptions(from: request, defaultHashingMode: .compatible),
                archiveCompressionMode: archiveCompressionMode(from: request),
                temporaryDirectory: optionalURL(from: request, key: "temporaryDirectoryPath")
            ))]

        case .signIPAWithIdentity:
            response = ["report": propertyListValue(try RorkSigner.signIPAWithIdentity(
                at: url(from: request, key: "archivePath"),
                outputURL: url(from: request, key: "outputArchivePath"),
                identity: identity(from: request),
                options: bundleOptions(from: request, defaultHashingMode: .compatible),
                archiveCompressionMode: archiveCompressionMode(from: request),
                temporaryDirectory: optionalURL(from: request, key: "temporaryDirectoryPath")
            ))]

        case .signStandaloneIPAAdHoc:
            response = ["report": propertyListValue(try RorkSigner.signStandaloneIPAAdHoc(
                at: url(from: request, key: "archivePath"),
                outputURL: url(from: request, key: "outputArchivePath"),
                options: standaloneOptions(from: request),
                archiveCompressionMode: archiveCompressionMode(from: request),
                temporaryDirectory: optionalURL(from: request, key: "temporaryDirectoryPath")
            ))]

        case .signStandaloneIPAWithIdentity:
            response = ["report": propertyListValue(try RorkSigner.signStandaloneIPAWithIdentity(
                at: url(from: request, key: "archivePath"),
                outputURL: url(from: request, key: "outputArchivePath"),
                identity: identity(from: request),
                options: standaloneOptions(from: request),
                archiveCompressionMode: archiveCompressionMode(from: request),
                temporaryDirectory: optionalURL(from: request, key: "temporaryDirectoryPath")
            ))]

        case .signStandaloneIPAWithCredential:
            response = ["report": propertyListValue(try RorkSigner.signStandaloneIPAWithCredential(
                at: url(from: request, key: "archivePath"),
                outputURL: url(from: request, key: "outputArchivePath"),
                provisioningProfileData: data(from: request, key: "provisioningProfileData"),
                credentialData: data(from: request, key: "credentialData"),
                password: string(from: request, key: "password", default: ""),
                bundleIdentifier: string(from: request, key: "bundleIdentifier"),
                provisioningProfilesByBundleIdentifier: dataDictionary(from: request, key: "provisioningProfilesByBundleIdentifier"),
                watchProvisioningProfileData: optionalData(from: request, key: "watchProvisioningProfileData"),
                appGroupIdentifiers: stringArray(from: request, key: "appGroupIdentifiers"),
                rootEntitlementsXML: string(from: request, key: "rootEntitlementsXML", default: ""),
                displayName: optionalString(from: request, key: "displayName"),
                bundleVersion: optionalString(from: request, key: "bundleVersion"),
                minimumOSVersion: optionalString(from: request, key: "minimumOSVersion"),
                enableDocuments: bool(from: request, key: "enableDocuments", default: false),
                removeExtensions: bool(from: request, key: "removeExtensions", default: false),
                removeWatchApps: bool(from: request, key: "removeWatchApps", default: false),
                removeUISupportedDevices: bool(from: request, key: "removeUISupportedDevices", default: false),
                embedProvisioningProfiles: bool(from: request, key: "embedProvisioningProfiles", default: true),
                dylibInjections: dylibInjections(from: request),
                dylibLoadCommandsToRemove: stringArray(from: request, key: "dylibLoadCommandsToRemove"),
                codeDirectoryHashingMode: hashingMode(from: request, default: .sha256Only),
                archiveCompressionMode: archiveCompressionMode(from: request),
                temporaryDirectory: optionalURL(from: request, key: "temporaryDirectoryPath")
            ))]
        }

        return try encodeResponse(response)
    }
}

private extension RorkSignCBridge {
    static func decodeRequest(bytes: UnsafeRawPointer?, length: Int) throws -> Request {
        guard length > 0 else {
            return [:]
        }
        guard let bytes else {
            throw inputError("Request length is non-zero but request bytes are missing.")
        }
        let data = Data(bytes: bytes, count: length)
        let propertyList = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let request = propertyList as? Request else {
            throw inputError("RorkSign C request must be a property-list dictionary.")
        }
        return request
    }

    static func encodeResponse(_ response: Any) throws -> Data {
        try PropertyListSerialization.data(
            fromPropertyList: response,
            format: .binary,
            options: 0
        )
    }

    static func data(from request: Request, key: String = "data", fallbackKey: String? = nil) throws -> Data {
        if let value = request[key] as? Data {
            return value
        }
        if let fallbackKey, let value = request[fallbackKey] as? Data {
            return value
        }
        throw inputError("Missing data field '\(key)'.")
    }

    static func optionalData(from request: Request, key: String) -> Data? {
        request[key] as? Data
    }

    static func string(from request: Request, key: String) throws -> String {
        guard let value = request[key] as? String, !value.isEmpty else {
            throw inputError("Missing string field '\(key)'.")
        }
        return value
    }

    static func string(from request: Request, key: String, default defaultValue: String) -> String {
        request[key] as? String ?? defaultValue
    }

    static func optionalString(from request: Request, key: String) -> String? {
        request[key] as? String
    }

    static func bool(from request: Request, key: String, default defaultValue: Bool) -> Bool {
        request[key] as? Bool ?? defaultValue
    }

    static func double(from request: Request, key: String) -> Double? {
        if let value = request[key] as? Double {
            return value
        }
        if let value = request[key] as? NSNumber {
            return value.doubleValue
        }
        return nil
    }

    static func date(from request: Request, key: String) -> Date? {
        if let value = request[key] as? Date {
            return value
        }
        if let timestamp = double(from: request, key: key) {
            return Date(timeIntervalSince1970: timestamp)
        }
        return nil
    }

    static func url(from request: Request, key: String) throws -> URL {
        URL(fileURLWithPath: try string(from: request, key: key))
    }

    static func optionalURL(from request: Request, key: String) -> URL? {
        guard let path = request[key] as? String, !path.isEmpty else {
            return nil
        }
        return URL(fileURLWithPath: path)
    }

    static func stringArray(from request: Request, key: String) -> [String] {
        request[key] as? [String] ?? []
    }

    static func intArray(from request: Request, key: String) -> [Int] {
        if let values = request[key] as? [Int] {
            return values
        }
        if let values = request[key] as? [NSNumber] {
            return values.map(\.intValue)
        }
        return []
    }

    static func dataArray(from request: Request, key: String, singleKey: String? = nil) throws -> [Data] {
        if let values = request[key] as? [Data] {
            return values
        }
        if let singleKey, let value = request[singleKey] as? Data {
            return [value]
        }
        throw inputError("Missing data-array field '\(key)'.")
    }

    static func dataDictionary(from request: Request, key: String) -> [String: Data] {
        request[key] as? [String: Data] ?? [:]
    }

    static func hashingMode(from request: Request, default defaultValue: CodeDirectoryHashingMode) -> CodeDirectoryHashingMode {
        switch (request["codeDirectoryHashingMode"] as? String)?.lowercased() {
        case "sha256only", "sha256-only", "sha256_only":
            return .sha256Only
        case "compatible":
            return .compatible
        default:
            return defaultValue
        }
    }

    static func archiveCompressionMode(from request: Request) -> ArchiveCompressionMode {
        switch (request["archiveCompressionMode"] as? String)?.lowercased() {
        case "deflated", "deflate":
            return .deflated
        default:
            return .stored
        }
    }

    static func ocspPolicy(from request: Request) -> OCSPResponseValidationPolicy {
        OCSPResponseValidationPolicy(
            validationDate: date(from: request, key: "validationDate") ?? Date(),
            allowedClockSkew: double(from: request, key: "allowedClockSkew") ?? 300,
            maximumAge: double(from: request, key: "maximumAge"),
            requiresNextUpdate: bool(from: request, key: "requiresNextUpdate", default: false)
        )
    }

    static func bundleOptions(from request: Request, defaultHashingMode: CodeDirectoryHashingMode) -> BundleSigningOptions {
        BundleSigningOptions(
            defaultEntitlementsXML: string(from: request, key: "defaultEntitlementsXML", default: ""),
            rootProvisioningProfile: optionalData(from: request, key: "rootProvisioningProfileData")
                ?? optionalData(from: request, key: "provisioningProfileData"),
            entitlementsByBundleIdentifier: request["entitlementsByBundleIdentifier"] as? [String: String] ?? [:],
            provisioningProfilesByBundleIdentifier: dataDictionary(from: request, key: "provisioningProfilesByBundleIdentifier"),
            embedProvisioningProfiles: bool(from: request, key: "embedProvisioningProfiles", default: true),
            codeDirectoryHashingMode: hashingMode(from: request, default: defaultHashingMode),
            dylibInjections: dylibInjections(from: request),
            dylibLoadCommandsToRemove: stringArray(from: request, key: "dylibLoadCommandsToRemove"),
            signingCache: signingCache(from: request)
        )
    }

    static func standaloneOptions(from request: Request) throws -> StandaloneBundleSigningOptions {
        StandaloneBundleSigningOptions(
            bundleIdentifier: try string(from: request, key: "bundleIdentifier"),
            rootProvisioningProfile: optionalData(from: request, key: "rootProvisioningProfileData")
                ?? optionalData(from: request, key: "provisioningProfileData"),
            watchProvisioningProfile: optionalData(from: request, key: "watchProvisioningProfileData"),
            provisioningProfilesByBundleIdentifier: dataDictionary(from: request, key: "provisioningProfilesByBundleIdentifier"),
            appGroupIdentifiers: stringArray(from: request, key: "appGroupIdentifiers"),
            rootEntitlementsXML: string(from: request, key: "rootEntitlementsXML", default: ""),
            displayName: optionalString(from: request, key: "displayName"),
            bundleVersion: optionalString(from: request, key: "bundleVersion"),
            minimumOSVersion: optionalString(from: request, key: "minimumOSVersion"),
            enableDocuments: bool(from: request, key: "enableDocuments", default: false),
            removeExtensions: bool(from: request, key: "removeExtensions", default: false),
            removeWatchApps: bool(from: request, key: "removeWatchApps", default: false),
            removeUISupportedDevices: bool(from: request, key: "removeUISupportedDevices", default: false),
            embedProvisioningProfiles: bool(from: request, key: "embedProvisioningProfiles", default: true),
            dylibInjections: dylibInjections(from: request),
            dylibLoadCommandsToRemove: stringArray(from: request, key: "dylibLoadCommandsToRemove"),
            codeDirectoryHashingMode: hashingMode(from: request, default: .sha256Only),
            signingCache: signingCache(from: request)
        )
    }

    static func dylibInjections(from request: Request) -> [BundleDylibInjection] {
        guard let values = request["dylibInjections"] as? [[String: Any]] else {
            return []
        }
        return values.compactMap { value in
            guard let sourcePath = value["sourcePath"] as? String, !sourcePath.isEmpty else {
                return nil
            }
            return BundleDylibInjection(
                sourceURL: URL(fileURLWithPath: sourcePath),
                installName: value["installName"] as? String,
                weak: value["weak"] as? Bool ?? false
            )
        }
    }

    static func signingCache(from request: Request) -> SigningCacheOptions? {
        guard let path = request["signingCacheDirectoryPath"] as? String, !path.isEmpty else {
            return nil
        }
        return SigningCacheOptions(
            directoryURL: URL(fileURLWithPath: path),
            readExistingEntries: bool(from: request, key: "signingCacheReadExistingEntries", default: true)
        )
    }

    static func hasIdentityInput(_ request: Request) -> Bool {
        request["certificateData"] is Data
            || request["privateKeyData"] is Data
            || request["credentialData"] is Data
            || request["pkcs12Data"] is Data
    }

    static func identity(from request: Request) throws -> SigningIdentity {
        let password = string(from: request, key: "password", default: "")
        if let profileData = request["provisioningProfileData"] as? Data,
           let credentialData = request["credentialData"] as? Data {
            return try SigningIdentity(
                provisioningProfileData: profileData,
                credentialData: credentialData,
                password: password
            )
        }
        if let certificateData = request["certificateData"] as? Data,
           let privateKeyData = request["privateKeyData"] as? Data ?? request["credentialData"] as? Data {
            return try SigningIdentity(
                certificateData: certificateData,
                privateKeyData: privateKeyData,
                privateKeyPassword: password
            )
        }
        if let pkcs12Data = request["pkcs12Data"] as? Data ?? request["credentialData"] as? Data {
            return try SigningIdentity(pkcs12Data: pkcs12Data, password: password)
        }
        throw inputError("Missing signing identity fields.")
    }

    static func inputError(_ message: String) -> NSError {
        NSError(
            domain: "RorkSignC",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }

    static func errorMessage(for error: Error) -> String {
        switch error {
        case let RorkSignError.invalidMachO(message):
            return "Invalid Mach-O: \(message)"
        case let RorkSignError.invalidEntitlements(message):
            return "Invalid entitlements: \(message)"
        case let RorkSignError.invalidBundle(message):
            return "Invalid bundle: \(message)"
        case let RorkSignError.invalidArchive(message):
            return "Invalid archive: \(message)"
        case let RorkSignError.resourceSealing(message):
            return "Resource sealing failed: \(message)"
        case let RorkSignError.invalidProvisioningProfile(message):
            return "Invalid provisioning profile: \(message)"
        case let RorkSignError.invalidSigningIdentity(message):
            return "Invalid signing identity: \(message)"
        case let RorkSignError.cmsSigning(message):
            return "CMS signing failed: \(message)"
        case let RorkSignError.ocsp(message):
            return "OCSP failed: \(message)"
        case let RorkSignError.unsupported(message):
            return "Unsupported operation: \(message)"
        default:
            let localizedDescription = (error as NSError).localizedDescription
            return localizedDescription.isEmpty ? String(describing: error) : localizedDescription
        }
    }
}

private func propertyListValue(_ value: Any) -> Any {
    if let value = unwrapOptional(value) {
        return propertyListValue(value)
    }

    switch value {
    case let value as Data:
        return value
    case let value as Date:
        return value
    case let value as URL:
        return value.path
    case let value as String:
        return value
    case let value as Bool:
        return value
    case let value as Int:
        return value
    case let value as Int32:
        return Int(value)
    case let value as UInt32:
        return NSNumber(value: value)
    case let value as Int64:
        return NSNumber(value: value)
    case let value as UInt64:
        return NSNumber(value: value)
    case let value as Double:
        return value
    case let value as Float:
        return Double(value)
    case let value as [Any]:
        return value.map(propertyListValue)
    case let value as [String: Any]:
        return value.mapValues(propertyListValue)
    default:
        break
    }

    let mirror = Mirror(reflecting: value)
    switch mirror.displayStyle {
    case .collection, .set:
        return mirror.children.map { propertyListValue($0.value) }
    case .dictionary:
        var dictionary: [String: Any] = [:]
        for child in mirror.children {
            let pair = Mirror(reflecting: child.value)
            guard pair.children.count == 2 else {
                continue
            }
            let children = Array(pair.children)
            guard let key = children[0].value as? String else {
                continue
            }
            dictionary[key] = propertyListValue(children[1].value)
        }
        return dictionary
    case .enum:
        if mirror.children.isEmpty {
            return String(describing: value)
        }
        let child = mirror.children.first
        return [
            "case": child?.label ?? String(describing: value),
            "value": propertyListValue(child?.value as Any),
        ]
    case .struct, .class:
        var dictionary: [String: Any] = [:]
        for child in mirror.children {
            guard let label = child.label else {
                continue
            }
            if Mirror(reflecting: child.value).displayStyle == .optional {
                guard let unwrapped = unwrapOptional(child.value) else {
                    continue
                }
                dictionary[label] = propertyListValue(unwrapped)
            } else {
                dictionary[label] = propertyListValue(child.value)
            }
        }
        return dictionary
    default:
        return String(describing: value)
    }
}

private func unwrapOptional(_ value: Any) -> Any? {
    let mirror = Mirror(reflecting: value)
    guard mirror.displayStyle == .optional else {
        return nil
    }
    return mirror.children.first?.value
}

@_cdecl("RorkSignCExecute")
public func RorkSignCExecute(
    operation: Int32,
    requestBytes: UnsafeRawPointer?,
    requestLength: Int,
    valueBytes: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    valueLength: UnsafeMutablePointer<Int>?,
    errorBytes: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    errorLength: UnsafeMutablePointer<Int>?
) -> Bool {
    valueBytes?.pointee = nil
    valueLength?.pointee = 0
    errorBytes?.pointee = nil
    errorLength?.pointee = 0

    do {
        let response = try RorkSignCBridge.execute(
            operation: operation,
            requestBytes: requestBytes,
            requestLength: requestLength
        )
        valueBytes?.pointee = copyBytes(response)
        valueLength?.pointee = response.count
        return true
    } catch {
        let message = RorkSignCBridge.errorMessage(for: error)
        let data = Data(message.utf8)
        errorBytes?.pointee = copyCString(message)
        errorLength?.pointee = data.count
        return false
    }
}

@_cdecl("RorkSignCFree")
public func RorkSignCFree(_ bytes: UnsafeMutableRawPointer?) {
    bytes?.deallocate()
}

private func copyBytes(_ data: Data) -> UnsafeMutableRawPointer? {
    let count = max(data.count, 1)
    let result = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: 1)
    data.withUnsafeBytes { buffer in
        if let baseAddress = buffer.baseAddress, data.count > 0 {
            result.copyMemory(from: baseAddress, byteCount: data.count)
        }
    }
    return result
}

private func copyCString(_ string: String) -> UnsafeMutablePointer<CChar>? {
    let bytes = Array(string.utf8CString)
    let result = UnsafeMutablePointer<CChar>.allocate(capacity: bytes.count)
    result.initialize(from: bytes, count: bytes.count)
    return result
}
