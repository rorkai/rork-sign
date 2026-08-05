import ArgumentParser
import Foundation
import RorkSign

/// Root `rorksign` command.
///
/// The library remains the primary product. The CLI exists for fixtures,
/// debugging, and CI scripts that need a signing subprocess.
@main
@available(macOS 10.15, macCatalyst 13, iOS 13, tvOS 13, watchOS 6, *)
struct RorkSignCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rorksign",
        abstract: "Sign Mach-O files, app bundles, and IPA archives with a Swift ZSign-compatible signer.",
        subcommands: [
            ZSign.self,
            Inspect.self,
            Dylibs.self,
            Metadata.self,
            InjectDylib.self,
            RemoveDylib.self,
            Sign.self,
            AdhocSign.self,
            AdhocSignBundle.self,
            AdhocSignIPA.self,
            IdentitySign.self,
            IdentitySignP12.self,
            IdentitySignProfileKey.self,
            IdentitySignBundle.self,
            IdentitySignBundleP12.self,
            IdentitySignBundleProfileKey.self,
            IdentitySignIPA.self,
            IdentitySignIPAP12.self,
            IdentitySignIPAProfileKey.self,
            SealResources.self,
            VerifyResources.self,
            TeamID.self,
            ExportPKCS12.self,
        ],
        defaultSubcommand: ZSign.self
    )
}

/// ZSign-compatible signing command.
///
/// This is configured as the root command's default subcommand, so users can run
/// `rorksign -k key.p12 -m profile.mobileprovision -o out.ipa in.ipa` without
/// typing a subcommand, while development subcommands such as `inspect` keep
/// their normal `rorksign inspect <path>` shape.
@available(macOS 10.15, macCatalyst 13, iOS 13, tvOS 13, watchOS 6, *)
struct ZSign: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "zsign",
        abstract: "Run the ZSign-compatible signing flow."
    )

    @OptionGroup var compatibilityOptions: ZSignOptions

    mutating func run() async throws {
        try await compatibilityOptions.run()
    }
}

/// Options accepted by the ZSign-compatible command surface.
///
/// The root command routes to `ZSign` as its default subcommand, while callers
/// can still invoke `rorksign zsign` explicitly. Keeping the compatibility flags
/// in one `ArgumentParser` option group prevents those two entry points from
/// drifting as the command grows.
struct ZSignOptions: ParsableArguments {
    @Flag(name: [.customShort("a"), .customLong("adhoc")], help: "Perform ad-hoc signing only.")
    var adHoc = false

    @Option(name: [.customShort("c"), .customLong("cert")], help: "Path to a PEM or DER certificate.")
    var certificatePath: String?

    @Option(name: [.customShort("k"), .customLong("pkey")], help: "Path to a private key or PKCS#12 credential.")
    var credentialPath: String?

    @Option(name: [.customShort("m"), .customLong("prov")], help: "Path to a provisioning profile. Repeat for nested bundles.")
    var provisioningProfilePaths: [String] = []

    @Option(name: [.customShort("p"), .customLong("password")], help: "Password for the private key or PKCS#12 credential.")
    var password = ""

    @Option(name: [.customShort("b"), .customLong("bundle_id")], help: "Replacement root bundle identifier.")
    var bundleIdentifier: String?

    @Option(name: [.customShort("n"), .customLong("bundle_name")], help: "Replacement root display name.")
    var displayName: String?

    @Option(name: [.customShort("r"), .customLong("bundle_version")], help: "Replacement root bundle version.")
    var bundleVersion: String?

    @Option(name: [.customShort("e"), .customLong("entitlements")], help: "Path to an entitlements plist.")
    var entitlementsPath: String?

    @Option(name: [.customLong("entitlements-resource")], help: "Bundle-local entitlements plist filename for unsigned app artifacts.")
    var entitlementsResourceName: String?

    @Option(name: [.customShort("o"), .customLong("output")], help: "Path to the output IPA or Mach-O.")
    var outputPath: String?

    @Option(name: [.customShort("z"), .customLong("zip_level")], help: "ZIP compression level. Level 0 stores files; levels 1-9 use Deflate.")
    var zipLevel: Int?

    @Option(name: [.customShort("l"), .customLong("dylib")], help: "Path to a dylib to copy and load. Repeat to inject multiple dylibs.")
    var dylibPaths: [String] = []

    @Option(name: [.customShort("D"), .customLong("rm_dylib")], help: "Dylib install name or basename to remove. Repeat to remove multiple dylibs.")
    var dylibLoadCommandsToRemove: [String] = []

    @Flag(name: [.customShort("w"), .customLong("weak")], help: "Inject dylibs with LC_LOAD_WEAK_DYLIB.")
    var weakDylibInjection = false

    @Flag(name: [.customShort("2"), .customLong("sha256_only")], help: "Emit SHA-256-only CodeDirectory signatures.")
    var sha256Only = false

    @Option(name: [.customShort("x"), .customLong("metadata")], help: "Write ZSign-compatible metadata.json and icon output.")
    var metadataDirectoryPath: String?

    @Flag(name: [.customShort("R"), .customLong("rm_provision")], help: "Use provisioning profiles for signing without embedding them.")
    var removeProvisioningProfiles = false

    @Flag(name: [.customShort("S"), .customLong("enable_docs")], help: "Enable document-browser Info.plist keys.")
    var enableDocuments = false

    @Option(name: [.customShort("M"), .customLong("min_version")], help: "Replacement MinimumOSVersion.")
    var minimumOSVersion: String?

    @Flag(name: [.customShort("E"), .customLong("rm_extensions")], help: "Remove app extensions before signing.")
    var removeExtensions = false

    @Flag(name: [.customShort("W"), .customLong("rm_watch")], help: "Remove embedded Watch apps before signing.")
    var removeWatchApps = false

    @Flag(name: [.customShort("U"), .customLong("rm_uisd")], help: "Remove UISupportedDevices from the root Info.plist.")
    var removeUISupportedDevices = false

    @Option(name: [.customShort("t"), .customLong("temp_folder")], help: "Directory used for IPA extraction and metadata workspaces.")
    var temporaryFolderPath: String?

    @Flag(name: [.customShort("f"), .customLong("force")], help: "Rebuild signatures and resource seals while refreshing cache.")
    var force = false

    @Flag(name: [.customShort("d"), .customLong("debug")], help: "Write generated signature slots to .zsign_debug.")
    var debug = false

    @Flag(name: [.customShort("V"), .customLong("verbose")], help: "Print detailed signing paths and outputs.")
    var verbose = false

    @Flag(name: [.customShort("q"), .customLong("quiet")], help: "Reduce compatibility command output.")
    var quiet = false

    @Flag(name: [.customShort("i"), .customLong("install")], help: "Install the signed IPA with ideviceinstaller.")
    var install = false

    @Flag(name: [.customShort("C"), .customLong("check")], help: "Inspect certificate, profile, credential, and Mach-O signature metadata.")
    var checkCertificate = false

    @Flag(name: [.customLong("online-ocsp")], help: "Fetch and validate OCSP status during -C checks when issuer material is available.")
    var onlineOCSP = false

    @Flag(name: [.customShort("v"), .customLong("version")], help: "Print the version.")
    var shortVersion = false

    @Argument(help: "Input Mach-O file, app bundle, extracted archive folder, or IPA.")
    var inputPath: String?

    var hasBundledEntitlementsResource: Bool {
        guard let resourceName = entitlementsResourceName else {
            return false
        }
        return !resourceName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func run() async throws {
        if shortVersion {
            print("version: \(RorkSigner.version)")
            return
        }
        guard let inputPath else {
            throw ValidationError("Missing input file or folder. Run `rorksign --help` for usage.")
        }
        RorkSignCLILogging.bootstrapIfNeeded()
        try await ZSignCompatibleRunner(command: self).run(inputPath: inputPath)
    }
}

// MARK: - Inspection

struct Inspect: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "inspect",
        abstract: "Print high-level Mach-O metadata."
    )

    @Argument(transform: fileURL) var machO: URL

    func run() throws {
        let info = try RorkSigner.inspectMachO(Data(contentsOf: machO))
        print("kind=\(info.kind) fileType=\(info.fileType) architectures=\(info.architectureCount) codeSignature=\(info.hasCodeSignature)")
    }
}

struct Dylibs: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "dylibs",
        abstract: "Print Mach-O dynamic-library load commands."
    )

    @Argument(transform: fileURL) var machO: URL

    func run() throws {
        for command in try RorkSigner.dylibLoadCommands(in: Data(contentsOf: machO)) {
            print("\(command.weak ? "weak " : "load ")\(command.path)")
        }
    }
}

struct Metadata: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "metadata",
        abstract: "Extract ZSign-compatible app metadata and icon output."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var outputDirectory: URL

    func run() throws {
        let report: AppMetadataReport
        let archiveExtensions: Set<String> = ["ipa", "zip"]
        if archiveExtensions.contains(input.pathExtension.lowercased()) {
            report = try RorkSigner.extractIPAMetadata(
                at: input,
                outputDirectory: outputDirectory
            )
        } else {
            report = try RorkSigner.extractBundleMetadata(
                at: input,
                outputDirectory: outputDirectory
            )
        }
        print("metadata=\(outputDirectory.appendingPathComponent("metadata.json").path) app=\(report.appName) bundle=\(report.appBundleIdentifier)")
    }
}

struct InjectDylib: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "inject-dylib",
        abstract: "Add an LC_LOAD_DYLIB or LC_LOAD_WEAK_DYLIB command to a Mach-O file."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var installName: String
    @Flag(name: .shortAndLong, help: "Inject as LC_LOAD_WEAK_DYLIB.")
    var weak = false

    func run() throws {
        let rewritten = try RorkSigner.injectDylibLoadCommand(
            into: Data(contentsOf: input),
            path: installName,
            weak: weak
        )
        try rewritten.write(to: output)
    }
}

struct RemoveDylib: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "remove-dylib",
        abstract: "Remove matching LC_LOAD_DYLIB and LC_LOAD_WEAK_DYLIB commands."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var installNames: [String]

    func run() throws {
        let rewritten = try RorkSigner.removeDylibLoadCommands(
            from: Data(contentsOf: input),
            matching: installNames
        )
        try rewritten.write(to: output)
    }
}

// MARK: - Modern signing

struct Sign: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sign",
        abstract: "Sign apps, bundles, and IPA archives.",
        subcommands: [
            SignIPA.self,
        ]
    )
}

struct SignIPA: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ipa",
        abstract: "Sign and optionally rebase an IPA archive."
    )

    @Option(
        name: .long,
        help: "Input IPA archive, app bundle, or extracted archive directory."
    )
    var input: String

    @Option(name: .long, help: "Output IPA archive.")
    var output: String

    @Option(name: [.customLong("bundle-id")], help: "Replacement root bundle identifier.")
    var bundleIdentifier: String

    @Option(name: [.customLong("profile-map")], help: "JSON map from final bundle identifier to provisioning profile path.")
    var profileMapPath: String

    @Option(name: [.customLong("certificate")], help: "Path to a PEM or DER certificate.")
    var certificatePath: String

    @Option(name: [.customLong("key")], help: "Path to a private key or PKCS#12 credential.")
    var credentialPath: String

    @Option(name: [.customShort("p"), .customLong("password")], help: "Password for the private key or PKCS#12 credential.")
    var password = ""

    @Option(name: [.customLong("password-file")], help: "Path to a file containing the private-key password.")
    var passwordFile: String?

    @Option(name: [.customLong("app-groups")], help: "Comma-separated app-group identifiers.")
    var appGroups: String?

    @Option(name: [.customLong("bundle-name")], help: "Replacement root display name.")
    var bundleName: String?

    @Option(name: [.customLong("entitlements-resource")], help: "Bundle-local entitlements plist filename for unsigned app artifacts.")
    var entitlementsResourceName: String?

    func run() throws {
        let rootBundleIdentifier = bundleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !rootBundleIdentifier.isEmpty else {
            throw ValidationError("Bundle identifier must not be empty.")
        }

        let profiles = try CLISupport.readProvisioningProfileMap(path: profileMapPath)
        guard let rootProfile = profiles[rootBundleIdentifier] else {
            throw ValidationError(
                "Provisioning profile map must include a profile for root bundle identifier \(rootBundleIdentifier)."
            )
        }

        let resolvedPassword = try CLISupport.readPassword(
            value: password,
            filePath: passwordFile,
            optionName: "Signing identity"
        )
        let identity = try CLISupport.readIdentity(
            certificatePath: certificatePath,
            credentialPath: credentialPath,
            password: resolvedPassword
        )
        let preparedInput = try CLISupport.prepareIPAInput(
            at: fileURL(input)
        )
        defer {
            preparedInput.removeWorkspace()
        }
        let report = try RorkSigner.signIPA(
            at: preparedInput.archiveURL,
            outputURL: fileURL(output),
            identity: identity,
            options: AppSigningOptions(
                bundleIdentifier: rootBundleIdentifier,
                rootProvisioningProfile: rootProfile,
                provisioningProfilesByBundleIdentifier: profiles,
                appGroupIdentifiers: CLISupport.appGroupIdentifiers(appGroups),
                entitlementsResourceName: entitlementsResourceName,
                displayName: bundleName
            )
        )
        print("app=\(report.appBundlePath) sealed=\(report.sealedBundlePaths.count) signed=\(report.signedCodePaths.count)")
    }
}

// MARK: - Ad-hoc signing

struct AdhocSign: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "adhoc-sign",
        abstract: "Ad-hoc sign a single Mach-O file."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var bundleIdentifier: String
    @Argument var entitlementsXMLPath: String?

    func run() throws {
        let signed = try RorkSigner.signMachOAdHoc(
            Data(contentsOf: input),
            bundleIdentifier: bundleIdentifier,
            entitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
        )
        try signed.write(to: output)
    }
}

struct AdhocSignBundle: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "adhoc-sign-bundle",
        abstract: "Ad-hoc sign an app-style bundle in place."
    )

    @Argument(transform: fileURL) var bundle: URL
    @Argument var entitlementsXMLPath: String?

    func run() throws {
        let report = try RorkSigner.signBundleAdHoc(
            at: bundle,
            entitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
        )
        print("sealed=\(report.sealedBundles.count) signed=\(report.signedCode.count)")
    }
}

struct AdhocSignIPA: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "adhoc-sign-ipa",
        abstract: "Ad-hoc sign an IPA archive."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var entitlementsXMLPath: String?

    func run() throws {
        let report = try RorkSigner.signIPAAdHoc(
            at: input,
            outputURL: output,
            options: BundleSigningOptions(
                defaultEntitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
            )
        )
        print("app=\(report.appBundlePath) sealed=\(report.sealedBundlePaths.count) signed=\(report.signedCodePaths.count)")
    }
}

// MARK: - Identity signing (Mach-O)

struct IdentitySign: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity-sign",
        abstract: "Sign a Mach-O file with a PEM certificate and private key."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var bundleIdentifier: String
    @Argument var certificatePath: String
    @Argument var privateKeyPath: String
    @Argument var entitlementsXMLPath: String?
    @Option(name: [.customShort("p"), .customLong("password")], help: "Password for an encrypted PKCS#8 private key.")
    var password = ""

    func run() throws {
        let identity = try CLISupport.readIdentity(
            certificatePath: certificatePath,
            privateKeyPath: privateKeyPath,
            password: password
        )
        let signed = try RorkSigner.signMachOWithIdentity(
            Data(contentsOf: input),
            bundleIdentifier: bundleIdentifier,
            identity: identity,
            entitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
        )
        try signed.write(to: output)
    }
}

struct IdentitySignP12: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity-sign-p12",
        abstract: "Sign a Mach-O file with a PKCS#12 identity."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var bundleIdentifier: String
    @Argument var pkcs12Path: String
    @Argument var password: String
    @Argument var entitlementsXMLPath: String?

    func run() throws {
        let identity = try CLISupport.readPKCS12Identity(pkcs12Path: pkcs12Path, password: password)
        let signed = try RorkSigner.signMachOWithIdentity(
            Data(contentsOf: input),
            bundleIdentifier: bundleIdentifier,
            identity: identity,
            entitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
        )
        try signed.write(to: output)
    }
}

struct IdentitySignProfileKey: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity-sign-profile-key",
        abstract: "Sign a Mach-O file with a provisioning profile and credential key."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var bundleIdentifier: String
    @Argument var profilePath: String
    @Argument var credentialPath: String
    @Argument var password: String
    @Argument var entitlementsXMLPath: String?

    func run() throws {
        let identity = try CLISupport.readProfileIdentity(
            profilePath: profilePath,
            credentialPath: credentialPath,
            password: password
        )
        let signed = try RorkSigner.signMachOWithIdentity(
            Data(contentsOf: input),
            bundleIdentifier: bundleIdentifier,
            identity: identity,
            entitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
        )
        try signed.write(to: output)
    }
}

// MARK: - Identity signing (bundle)

struct IdentitySignBundle: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity-sign-bundle",
        abstract: "Sign an app bundle with a PEM certificate and private key."
    )

    @Argument(transform: fileURL) var bundle: URL
    @Argument var certificatePath: String
    @Argument var privateKeyPath: String
    @Argument var entitlementsXMLPath: String?
    @Option(name: [.customShort("p"), .customLong("password")], help: "Password for an encrypted PKCS#8 private key.")
    var password = ""

    func run() throws {
        let identity = try CLISupport.readIdentity(
            certificatePath: certificatePath,
            privateKeyPath: privateKeyPath,
            password: password
        )
        let report = try RorkSigner.signBundleWithIdentity(
            at: bundle,
            identity: identity,
            options: BundleSigningOptions(
                defaultEntitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
            )
        )
        print("sealed=\(report.sealedBundles.count) signed=\(report.signedCode.count)")
    }
}

struct IdentitySignBundleP12: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity-sign-bundle-p12",
        abstract: "Sign an app bundle with a PKCS#12 identity."
    )

    @Argument(transform: fileURL) var bundle: URL
    @Argument var pkcs12Path: String
    @Argument var password: String
    @Argument var entitlementsXMLPath: String?

    func run() throws {
        let identity = try CLISupport.readPKCS12Identity(pkcs12Path: pkcs12Path, password: password)
        let report = try RorkSigner.signBundleWithIdentity(
            at: bundle,
            identity: identity,
            options: BundleSigningOptions(
                defaultEntitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
            )
        )
        print("sealed=\(report.sealedBundles.count) signed=\(report.signedCode.count)")
    }
}

struct IdentitySignBundleProfileKey: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity-sign-bundle-profile-key",
        abstract: "Sign an app bundle with a provisioning profile and credential key."
    )

    @Argument(transform: fileURL) var bundle: URL
    @Argument var profilePath: String
    @Argument var credentialPath: String
    @Argument var password: String
    @Argument var entitlementsXMLPath: String?

    func run() throws {
        let profile = try Data(contentsOf: fileURL(profilePath))
        let identity = try CLISupport.readProfileIdentity(
            profileData: profile,
            credentialPath: credentialPath,
            password: password
        )
        let bundleIdentifier = try CLISupport.readBundleIdentifier(at: bundle)
        let report = try RorkSigner.signBundleWithIdentity(
            at: bundle,
            identity: identity,
            options: BundleSigningOptions(
                defaultEntitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath),
                provisioningProfilesByBundleIdentifier: [
                    bundleIdentifier: profile,
                ]
            )
        )
        print("sealed=\(report.sealedBundles.count) signed=\(report.signedCode.count)")
    }
}

// MARK: - Identity signing (IPA)

struct IdentitySignIPA: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity-sign-ipa",
        abstract: "Sign an IPA archive with a PEM certificate and private key."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var certificatePath: String
    @Argument var privateKeyPath: String
    @Argument var entitlementsXMLPath: String?
    @Option(name: [.customShort("p"), .customLong("password")], help: "Password for an encrypted PKCS#8 private key.")
    var password = ""

    func run() throws {
        let identity = try CLISupport.readIdentity(
            certificatePath: certificatePath,
            privateKeyPath: privateKeyPath,
            password: password
        )
        let report = try RorkSigner.signIPAWithIdentity(
            at: input,
            outputURL: output,
            identity: identity,
            options: BundleSigningOptions(
                defaultEntitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
            )
        )
        print("app=\(report.appBundlePath) sealed=\(report.sealedBundlePaths.count) signed=\(report.signedCodePaths.count)")
    }
}

struct IdentitySignIPAP12: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity-sign-ipa-p12",
        abstract: "Sign an IPA archive with a PKCS#12 identity."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var pkcs12Path: String
    @Argument var password: String
    @Argument var entitlementsXMLPath: String?

    func run() throws {
        let identity = try CLISupport.readPKCS12Identity(pkcs12Path: pkcs12Path, password: password)
        let report = try RorkSigner.signIPAWithIdentity(
            at: input,
            outputURL: output,
            identity: identity,
            options: BundleSigningOptions(
                defaultEntitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath)
            )
        )
        print("app=\(report.appBundlePath) sealed=\(report.sealedBundlePaths.count) signed=\(report.signedCodePaths.count)")
    }
}

struct IdentitySignIPAProfileKey: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity-sign-ipa-profile-key",
        abstract: "Sign an IPA archive with a provisioning profile and credential key."
    )

    @Argument(transform: fileURL) var input: URL
    @Argument(transform: fileURL) var output: URL
    @Argument var profilePath: String
    @Argument var credentialPath: String
    @Argument var password: String
    @Argument var entitlementsXMLPath: String?

    func run() throws {
        let profile = try Data(contentsOf: fileURL(profilePath))
        let identity = try CLISupport.readProfileIdentity(
            profileData: profile,
            credentialPath: credentialPath,
            password: password
        )
        let bundleIdentifier = try CLISupport.bundleIdentifier(fromProvisioningProfileData: profile)
        let report = try RorkSigner.signIPAWithIdentity(
            at: input,
            outputURL: output,
            identity: identity,
            options: BundleSigningOptions(
                defaultEntitlementsXML: CLISupport.readEntitlements(path: entitlementsXMLPath),
                provisioningProfilesByBundleIdentifier: [
                    bundleIdentifier: profile,
                ]
            )
        )
        print("app=\(report.appBundlePath) sealed=\(report.sealedBundlePaths.count) signed=\(report.signedCodePaths.count)")
    }
}

// MARK: - Utilities

struct SealResources: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "seal-resources",
        abstract: "Write _CodeSignature/CodeResources for a bundle."
    )

    @Argument(transform: fileURL) var bundle: URL

    func run() throws {
        let outputURL = try RorkSigner.sealBundleResources(at: bundle)
        print(outputURL.path)
    }
}

struct VerifyResources: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "verify-resources",
        abstract: "Verify a bundle against _CodeSignature/CodeResources."
    )

    @Argument(transform: fileURL) var bundle: URL

    func run() throws {
        let report = try RorkSigner.verifyCodeResources(forBundleAt: bundle)
        print(CLISupport.codeResourcesFields(report))
        if !report.isValid {
            throw ValidationError("CodeResources verification failed.")
        }
    }
}

struct TeamID: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "team-id",
        abstract: "Print the validated team identifier for a profile/credential pair."
    )

    @Argument var profilePath: String
    @Argument var credentialPath: String
    @Argument var password: String

    func run() throws {
        let teamIdentifier = try RorkSigner.validatedTeamIdentifier(
            provisioningProfileData: Data(contentsOf: fileURL(profilePath)),
            credentialData: Data(contentsOf: fileURL(credentialPath)),
            password: password
        )
        print(teamIdentifier)
    }
}

struct ExportPKCS12: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "export-pkcs12",
        abstract: "Export a certificate and private-key credential as PKCS#12."
    )

    @Option(
        name: [.customLong("certificate")],
        help: "Path to a PEM or DER certificate."
    )
    var certificatePath: String

    @Option(
        name: [.customLong("key")],
        help: "Path to a private key or PKCS#12 credential."
    )
    var keyPath: String

    @Option(
        name: [.customLong("input-password")],
        help: "Password for the input credential."
    )
    var inputPassword = ""

    @Option(
        name: [.customLong("input-password-file")],
        help: "Path to a file containing the input credential password."
    )
    var inputPasswordFile: String?

    @Option(
        name: [.customLong("output")],
        help: "Path to the output PKCS#12 file."
    )
    var outputPath: String

    @Option(
        name: [.customLong("output-password")],
        help: "Password for the output PKCS#12 file."
    )
    var outputPassword = ""

    @Option(
        name: [.customLong("output-password-file")],
        help: "Path to a file containing the output password."
    )
    var outputPasswordFile: String?

    func run() throws {
        let resolvedInputPassword = try CLISupport.readPassword(
            value: inputPassword,
            filePath: inputPasswordFile,
            optionName: "Input credential"
        )
        let resolvedOutputPassword = try CLISupport.readPassword(
            value: outputPassword,
            filePath: outputPasswordFile,
            optionName: "Output identity"
        )
        guard !resolvedOutputPassword.isEmpty else {
            throw ValidationError("Output password must not be empty.")
        }
        let identity = try CLISupport.readIdentity(
            certificatePath: certificatePath,
            credentialPath: keyPath,
            password: resolvedInputPassword
        )
        let output = try identity.pkcs12Representation(
            password: resolvedOutputPassword
        )
        let outputURL = fileURL(outputPath)
        try CLISupport.writeAtomically(output, to: outputURL)
        print("output=\(outputURL.path)")
    }
}
