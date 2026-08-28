# rork-sign

[![Swift](https://img.shields.io/badge/Swift-6.0-orange.svg)](Package.swift)
[![SwiftPM](https://img.shields.io/badge/SwiftPM-supported-brightgreen.svg)](Package.swift)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Pure Swift, ZSign-compatible iOS code signing for Mach-O files, app bundles,
and IPA archives.

**rork-sign** is a SwiftPM-native code-signing toolkit with a ZSign-compatible
command-line interface. It signs Mach-O files, app bundles, and IPA archives;
rewrites bundle metadata; injects or removes dylib load commands; and exposes
the same signing engine as a library API.

The implementation is written in Swift and does not shell out to Apple's
`codesign` or OpenSSL for production signing. Tests use OpenSSL as an external
oracle for certificate and CMS interoperability.

## Contents

- [Features](#features)
- [Supported Targets](#supported-targets)
- [Build](#build)
- [Usage](#usage)
- [Examples](#examples)
- [Certificate Checks](#certificate-checks)
- [Swift API](#swift-api)
- [Browser API](#browser-api)
- [Objective-C API](#objective-c-api)
- [ZSign Compatibility](#zsign-compatibility)
- [Fast Re-signing](#fast-re-signing)
- [Logging](#logging)
- [Limitations](#limitations)
- [Development](#development)
- [License](#license)

## Features

- **ZSign-compatible CLI** - supports the public ZSign-style signing flags for
  IPA, bundle, and Mach-O workflows.
- **Swift-first library** - the `RorkSign` module exposes signing, inspection,
  resource sealing, and credential APIs directly to Swift applications.
- **Browser signing** - the optional `RorkSignWeb` module accepts IPA,
  certificate, private-key, and provisioning-profile bytes without exposing
  native filesystem URLs to browser clients.
- **Objective-C facade** - the `RorkSignObjC` module exposes the public signer
  surface to Objective-C and Objective-C++ with Foundation types.
- **Mach-O signing** - ad-hoc and identity-backed signatures for thin and
  universal 64-bit Mach-O files.
- **CMS signatures** - pure Swift detached CMS SignedData generation and
  verification for RSA and NIST EC signing identities.
- **Provisioning profiles** - decode `.mobileprovision` files, derive
  entitlements, validate profile/private-key matches, and embed profiles when
  requested.
- **PKCS#12 and private keys** - import `.p12`/`.pfx`, PEM, DER, encrypted
  PKCS#8, and traditional encrypted RSA PEM credentials.
- **Bundle signing** - sign nested bundles inside-out, generate
  `_CodeSignature/CodeResources`, and hash resource seals into the executable
  CodeDirectory.
- **IPA signing** - extract, sign, and repack `Payload/*.app` archives with
  stored or deflated output.
- **Dylib editing** - inspect, inject, and remove `LC_LOAD_DYLIB` and
  `LC_LOAD_WEAK_DYLIB` commands.
- **Metadata rewriting** - update bundle identifier, display name, version,
  minimum OS version, Files app keys, extensions, Watch apps, and
  `UISupportedDevices`.
- **Inspection workflows** - check certificates, provisioning profiles,
  PKCS#12 identities, bundle resource seals, embedded Mach-O CodeDirectories,
  CMS signatures, OCSP responder URLs, and CRL distribution points.
- **OCSP utilities** - build OCSP requests, fetch responder DER, parse
  BasicOCSPResponse payloads, verify signatures, and apply explicit freshness
  policy.
- **Signature cache** - reuse unchanged Mach-O signatures across repeated
  bundle or IPA signing runs through `.zsign_cache`.

## Supported Targets

The native package supports macOS 13 or newer and iOS 15 or newer. The CLI also
builds for Windows x64 with a Swift toolchain. Native library products require
Swift 6.0 or newer, and the Objective-C product is available only where
Objective-C interoperability exists.

The opt-in `RorkSignWeb` product supports WASI browser environments. It requires
Swift 6.3 or newer because the browser product is declared in the versioned
Swift 6.3 package manifest.

## Build

Building requires a Swift 6.0 or newer toolchain. Client targets may continue
using Swift 5 language mode.

```bash
git clone https://github.com/rorkai/rork-sign.git
cd rork-sign
swift build -c release --product rorksign
.build/release/rorksign --help
```

On Windows, the executable is named `rorksign.exe`. Use
`swift build -c release --show-bin-path` when a script needs the toolchain's
exact release output directory.

The Windows archive, `rorksign-windows-x64.zip`, contains one
`rorksign.exe` and the accompanying legal notices. The executable statically
incorporates its Swift libraries but continues to use the x64 Microsoft Visual
C++ runtime. Install the current Microsoft Visual C++ Redistributable if
`MSVCP140.dll` or `VCRUNTIME140.dll` is unavailable. The pinned Windows SDK
does not provide `/MT` runtime variants, so these dependencies cannot be
folded into the executable. Each release publishes `checksums.txt` beside its
ZIP archives so downloads can be verified before extraction.

```sh
shasum -a 256 -c checksums.txt
```

During development, run the executable through SwiftPM:

```bash
swift run rorksign --help
swift run rorksign zsign --help
```

## Usage

`rorksign` uses Swift ArgumentParser. The root command defaults to the
ZSign-compatible signing flow, so these two forms are equivalent:

```bash
rorksign -a -o output.ipa input.ipa
rorksign zsign -a -o output.ipa input.ipa
```

```text
USAGE: rorksign zsign [<options>] [<input-path>]

ARGUMENTS:
  <input-path>            Input Mach-O file, app bundle, extracted archive
                          folder, or IPA.

OPTIONS:
  -a, --adhoc             Perform ad-hoc signing only.
  -c, --cert <cert>       Path to a PEM or DER certificate.
  -k, --pkey <pkey>       Path to a private key or PKCS#12 credential.
  -m, --prov <prov>       Path to a provisioning profile. Repeat for nested
                          bundles.
  -p, --password <password>
                          Password for the private key or PKCS#12 credential.
  -b, --bundle_id <bundle_id>
                          Replacement root bundle identifier.
  -n, --bundle_name <bundle_name>
                          Replacement root display name.
  -r, --bundle_version <bundle_version>
                          Replacement root bundle version.
  -e, --entitlements <entitlements>
                          Path to an entitlements plist.
  --entitlements-resource <entitlements-resource>
                          Bundle-local entitlements plist filename for unsigned
                          app artifacts.
  -o, --output <output>   Path to the output IPA or Mach-O.
  -z, --zip_level <zip_level>
                          ZIP compression level. Level 0 stores files; levels
                          1-9 use Deflate.
  -l, --dylib <dylib>     Path to a dylib to copy and load. Repeat to inject
                          multiple dylibs.
  -D, --rm_dylib <rm_dylib>
                          Dylib install name or basename to remove. Repeat to
                          remove multiple dylibs.
  -w, --weak              Inject dylibs with LC_LOAD_WEAK_DYLIB.
  -2, --sha256_only       Emit SHA-256-only CodeDirectory signatures.
  -x, --metadata <metadata>
                          Write ZSign-compatible metadata.json and icon output.
  -R, --rm_provision      Use provisioning profiles for signing without
                          embedding them.
  -S, --enable_docs       Enable document-browser Info.plist keys.
  -M, --min_version <min_version>
                          Replacement MinimumOSVersion.
  -E, --rm_extensions     Remove app extensions before signing.
  -W, --rm_watch          Remove embedded Watch apps before signing.
  -U, --rm_uisd           Remove UISupportedDevices from the root Info.plist.
  -t, --temp_folder <temp_folder>
                          Directory used for IPA extraction and metadata
                          workspaces.
  -f, --force             Rebuild signatures and resource seals while
                          refreshing cache.
  -d, --debug             Write generated signature slots to .zsign_debug.
  -V, --verbose           Print detailed signing paths and outputs.
  -q, --quiet             Reduce compatibility command output.
  -i, --install           Install the signed IPA with ideviceinstaller.
  -C, --check             Inspect certificate, profile, credential, and Mach-O
                          signature metadata.
  --online-ocsp           Fetch and validate OCSP status during -C checks when
                          issuer material is available.
  -v, --version           Print the version.
  -h, --help              Show help information.
```

## Examples

**Inspect a Mach-O file**

```bash
rorksign Demo.app/Demo
```

**Ad-hoc sign an IPA**

```bash
rorksign -a -o output.ipa Demo.ipa
```

**Sign an IPA with a PKCS#12 identity**

```bash
rorksign -k dev.p12 -p password -m app.mobileprovision -o output.ipa Demo.ipa
```

**Read bundle-local entitlements for unsigned app artifacts**

```bash
rorksign -k dev.p12 -p password -m app.mobileprovision \
  --entitlements-resource Entitlements.plist -o output.ipa Demo.ipa
```

`--entitlements-resource` names a plist file inside each bundle. It is used as
the executable's entitlement request when the executable has no embedded
entitlements, and the selected provisioning profile still constrains the final
signed values.

**Sign an app bundle with a private key and certificate**

```bash
rorksign -c cert.pem -k private-key.pem -m app.mobileprovision -o output.ipa Demo.app
```

**Change bundle identifier and display name**

```bash
rorksign -k dev.p12 -p password -m app.mobileprovision \
  -b com.example.newapp -n "New Name" -o output.ipa Demo.ipa
```

**Inject a dylib and re-sign**

```bash
rorksign -k dev.p12 -p password -m app.mobileprovision \
  -l Hook.dylib -o output.ipa Demo.ipa
```

**Inject weak dylibs into a Mach-O**

```bash
rorksign -a -w \
  -l "@executable_path/HookA.dylib" \
  -l "@executable_path/HookB.dylib" \
  Demo.app/Demo
```

**Remove a dylib load command**

```bash
rorksign -a -D Hook.dylib Demo.app/Demo
```

**Extract metadata and icon**

```bash
rorksign -x ./metadata Demo.ipa
# writes ./metadata/metadata.json and the selected icon file
```

**Enable Files app integration**

```bash
rorksign -k dev.p12 -p password -m app.mobileprovision -S -o output.ipa Demo.ipa
```

**Set minimum OS version**

```bash
rorksign -k dev.p12 -p password -m app.mobileprovision -M 14.0 -o output.ipa Demo.ipa
```

**Remove extensions, Watch apps, or UISupportedDevices**

```bash
rorksign -k dev.p12 -p password -m app.mobileprovision -E -o output.ipa Demo.ipa
rorksign -k dev.p12 -p password -m app.mobileprovision -W -o output.ipa Demo.ipa
rorksign -k dev.p12 -p password -m app.mobileprovision -U -o output.ipa Demo.ipa
```

**Use SHA-256-only CodeDirectories**

```bash
rorksign -a -2 -o output.ipa Demo.ipa
```

**Install after signing**

```bash
rorksign -k dev.p12 -p password -m app.mobileprovision -i Demo.ipa
```

`-i/--install` invokes `ideviceinstaller install <signed-ipa>`. When no
`-o/--output` path is supplied, the CLI creates a temporary IPA and removes it
after the install attempt.

## Certificate Checks

`-C/--check` inspects supported signing assets without mutating them.

Supported inputs:

- `.ipa` archives
- `.app` and `.appex` bundles
- Mach-O binaries
- `.mobileprovision` provisioning profiles
- `.p12` / `.pfx` identities
- PEM or DER certificates

```bash
# Check an IPA or app bundle
rorksign -C Demo.ipa
rorksign -C Demo.app

# Check a provisioning profile
rorksign -C app.mobileprovision

# Check a PKCS#12 identity
rorksign -C -p password dev.p12

# Check a certificate chain and fetch OCSP status when issuer material exists
rorksign -C --online-ocsp cert-chain.pem

# Sign and then report the embedded executable signature
rorksign -C -k dev.p12 -p password -m app.mobileprovision -o output.ipa Demo.ipa
```

Example output uses stable `key=value` fields for scripts:

```text
certificateCN=Apple Distribution: Example Corp certificateType=Apple Distribution certificateOrg=Example Corp certificateIssuer=Apple Worldwide Developer Relations Certification Authority certificateOCSP=https://ocsp.apple.com/ocsp03-wwdr... certificateCRL= certificateSerial=12:34:56 certificateAlgorithm=RSA 2048-bit certificateCA=false certificateCanSign=false certificateKeyUsage=digitalSignature certificateExpiration=2027-01-01T00:00:00Z certificateExpired=false
```

Local checks include:

- certificate validity windows
- issuer/subject chain links
- certificate signatures
- BasicConstraints, KeyUsage, and path-length constraints
- profile/private-key authorization
- CodeResources verification
- embedded CodeDirectory hash verification
- embedded CMS signature verification against the primary CodeDirectory

Trust roots, Apple certificate policy, CRL download, and platform trust
evaluation are intentionally left to caller policy.

## Swift API

Add the package to your SwiftPM project:

```swift
dependencies: [
    .package(url: "https://github.com/rorkai/rork-sign.git", from: "0.6.5"),
]
```

Then depend on the library product:

```swift
.product(name: "RorkSign", package: "rork-sign")
```

Ad-hoc sign an IPA:

```swift
import Foundation
import RorkSign

let report = try RorkSigner.signIPAAdHoc(
    at: URL(fileURLWithPath: "Demo.ipa"),
    outputURL: URL(fileURLWithPath: "output.ipa")
)

print(report.signedCodePaths)
```

Sign with a PKCS#12 identity:

```swift
import Foundation
import RorkSign

let identity = try SigningIdentity(
    pkcs12Data: Data(contentsOf: URL(fileURLWithPath: "dev.p12")),
    password: "password"
)

try RorkSigner.signIPAWithIdentity(
    at: URL(fileURLWithPath: "Demo.ipa"),
    outputURL: URL(fileURLWithPath: "output.ipa"),
    identity: identity
)
```

When a framework is loaded under the host app's local provisioning profile,
sign its main executable with the host bundle identifier:

```swift
let frameworkURL = URL(fileURLWithPath: "Demo.framework")
let profile = try Data(contentsOf: URL(fileURLWithPath: "app.mobileprovision"))
let credential = try Data(contentsOf: URL(fileURLWithPath: "dev.p12"))
var frameworkOptions = FrameworkSigningOptions()
frameworkOptions.codeDirectoryIdentifier = Bundle.main.bundleIdentifier

try RorkSigner.signFrameworkWithCredential(
    at: frameworkURL,
    provisioningProfileData: profile,
    credentialData: credential,
    password: "password",
    options: frameworkOptions
)
```

Framework signing seals resources and signs the framework executable in place.
It does not embed provisioning profiles or copy app entitlements from the
profile by default. Omit `codeDirectoryIdentifier` to preserve the framework's
`CFBundleIdentifier`.

Sign a hosted bundle for a runtime that loads guest code from an installed host:

```swift
try RorkSigner.signHostedBundleWithCredential(
    at: URL(fileURLWithPath: "Guest.app"),
    provisioningProfileData: profile,
    credentialData: credential,
    password: "password",
    options: HostedBundleSigningOptions(
        hostExecutableURL: URL(fileURLWithPath: "HostExecutable"),
        hostBundleIdentifier: "com.example.host"
    )
)
```

Hosted signing temporarily signs a copied host executable as the root
executable, signs the original executable as loose code under the same host
identifier, then restores the guest `Info.plist` and removes the temporary
stub. Use app signing instead when the output must be installed and launched
directly.

Read a team id from a provisioning profile:

```swift
let profileData = try Data(contentsOf: URL(fileURLWithPath: "app.mobileprovision"))
let profile = try RorkSigner.decodeProvisioningProfile(profileData)

print(profile.teamIdentifier)
print(profile.authorizedBundleIdentifier ?? "unknown")
print(profile.usesWildcardBundleIdentifier)
```

Preview the provisioning profiles needed for app signing:

```swift
let inspection = try RorkSigner.inspectApp(
    at: URL(fileURLWithPath: "Demo.app"),
    replacementBundleIdentifier: "com.example.demo"
)

for requirement in inspection.provisioningRequirements {
    print("\(requirement.relativePath): \(requirement.rewrittenBundleIdentifier)")
}
```

Sign an IPA and read bundle-local entitlements when unsigned
executables have no embedded entitlement slot:

```swift
let profileData = try Data(contentsOf: URL(fileURLWithPath: "app.mobileprovision"))
let identity = try SigningIdentity(
    pkcs12Data: Data(contentsOf: URL(fileURLWithPath: "dev.p12")),
    password: "password"
)

try RorkSigner.signIPA(
    at: URL(fileURLWithPath: "Demo.ipa"),
    outputURL: URL(fileURLWithPath: "output.ipa"),
    identity: identity,
    options: AppSigningOptions(
        bundleIdentifier: "com.example.demo",
        rootProvisioningProfile: profileData,
        entitlementsResourceName: "Entitlements.plist"
    )
)
```

Validate a profile/private-key pair before signing:

```swift
let teamID = try RorkSigner.validatedTeamIdentifier(
    provisioningProfileData: Data(contentsOf: URL(fileURLWithPath: "app.mobileprovision")),
    credentialData: Data(contentsOf: URL(fileURLWithPath: "dev.p12")),
    password: "password"
)
```

## Browser API

Swift 6.3 clients can add the package normally:

```swift
.package(
    url: "https://github.com/rorkai/rork-sign.git",
    from: "0.6.5"
)
```

Then add the `RorkSignWeb` product to the browser target:

```swift
.product(name: "RorkSignWeb", package: "rork-sign")
```

The browser application supplies credential and archive bytes. The signer
returns the completed IPA as `Data`, so private-key material and signed output
can remain inside the local WASM process:

```swift
import Foundation
import RorkSign
import RorkSignWeb

let identity = try SigningIdentity(
    certificateData: certificateData,
    privateKeyData: privateKeyData,
    privateKeyPassword: password
)
let signedIPA = try RorkSigner.signIPA(
    unsignedIPAData,
    using: identity,
    options: AppSigningOptions(
        bundleIdentifier: "com.example.demo",
        rootProvisioningProfile: provisioningProfileData
    )
)

print(signedIPA.appBundlePath)
```

The embedding runtime must expose a writable WASI temporary directory because
bundle signing operates on an isolated filesystem workspace before returning
the final archive bytes. Network-backed OCSP fetching is unavailable on WASI;
local certificate, profile, CMS, and signing operations remain available.

## Objective-C API

Add the `RorkSignObjC` product when integrating from Objective-C or
Objective-C++:

```swift
.product(name: "RorkSignObjC", package: "rork-sign")
```

Then import the module from Objective-C/Objective-C++:

```objc
@import RorkSignObjC;
```

The facade uses `RK*` Objective-C names, typed option objects, Foundation
inputs, `NSError **` failures, and typed reusable wrappers for signing
identities, provisioning profiles, OCSP requests, Mach-O CMS preparation, and
bundle/IPA signing reports.

```objc
NSError *error = nil;
RKSigner *signer = [[RKSigner alloc] init];

NSData *profile = [NSData dataWithContentsOfURL:profileURL];
NSData *credential = [NSData dataWithContentsOfURL:credentialURL];
if (!profile || !credential) {
    return;
}

NSString *teamID = [signer teamIdentifierForProvisioningProfileData:profile
                                                              error:&error];
RKProvisioningProfile *decoded = [signer decodeProvisioningProfileData:profile
                                                                  error:&error];
NSString *authorizedBundleID = decoded.authorizedBundleIdentifier;
```

Sign a bundle with a provisioning profile and credential:

```objc
RKBundleSigningOptions *options = [[RKBundleSigningOptions alloc] init];
options.embedProvisioningProfile = YES;
options.codeDirectoryHashingMode = RKCodeDirectoryHashingModeSha256Only;

RKBundleSigningReport *report =
    [signer signBundleWithCredentialAtURL:bundleURL
                  provisioningProfileData:profile
                           credentialData:credential
                                 password:@"password"
                                  options:options
                                    error:&error];
```

Sign a framework with the host app's CodeDirectory identifier:

```objc
RKFrameworkSigningOptions *frameworkOptions = [[RKFrameworkSigningOptions alloc] init];
frameworkOptions.codeDirectoryIdentifier = NSBundle.mainBundle.bundleIdentifier;
frameworkOptions.codeDirectoryHashingMode = RKCodeDirectoryHashingModeCompatible;

RKBundleSigningReport *frameworkReport =
    [signer signFrameworkWithCredentialAtURL:frameworkURL
                     provisioningProfileData:profile
                              credentialData:credential
                                    password:@"password"
                                     options:frameworkOptions
                                       error:&error];
```

Inspect an app before signing:

```objc
RKAppInspectionReport *inspection =
    [signer inspectAppAtURL:bundleURL
replacementBundleIdentifier:@"com.example.demo"
                      error:&error];

for (RKAppProvisioningRequirement *requirement
        in inspection.provisioningRequirements) {
    NSLog(@"%@: %@", requirement.relativePath, requirement.rewrittenBundleIdentifier);
}
```

Sign a hosted bundle:

```objc
RKHostedBundleSigningOptions *hostedOptions =
    [[RKHostedBundleSigningOptions alloc] initWithHostExecutableURL:hostExecutableURL
                                               hostBundleIdentifier:@"com.example.host"];

RKBundleSigningReport *hostedReport =
    [signer signHostedBundleWithCredentialAtURL:guestBundleURL
                        provisioningProfileData:profile
                                 credentialData:credential
                                       password:@"password"
                                        options:hostedOptions
                                          error:&error];
```

For APIs whose Swift reports contain non-Objective-C value types, `RKSigner`
returns `NSDictionary` / `NSArray<NSDictionary *>` reports with Foundation
values. Mutating/signing APIs return typed report objects when the report is
part of the primary workflow.

## ZSign Compatibility

The compatibility command implements the ZSign public CLI flag set:

| Area | Flags |
| --- | --- |
| Signing identity | `-k/--pkey`, `-c/--cert`, `-p/--password`, `-m/--prov` |
| Signing mode | `-a/--adhoc`, `-2/--sha256_only` |
| Output | `-o/--output`, `-z/--zip_level`, `-t/--temp_folder`, `-i/--install` |
| Bundle edits | `-b/--bundle_id`, `-n/--bundle_name`, `-r/--bundle_version`, `-M/--min_version`, `-S/--enable_docs` |
| Entitlements/profile handling | `-e/--entitlements`, `--entitlements-resource`, `-R/--rm_provision` |
| Dylib edits | `-l/--dylib`, `-D/--rm_dylib`, `-w/--weak` |
| Cleanup | `-E/--rm_extensions`, `-W/--rm_watch`, `-U/--rm_uisd` |
| Inspection/debugging | `-C/--check`, `-x/--metadata`, `-d/--debug`, `-f/--force`, `-V/--verbose`, `-q/--quiet`, `-v/--version`, `-h/--help` |

The CLI also includes `--online-ocsp` for explicit OCSP network checks during
`-C` workflows. This is an additive Swift implementation feature rather than a
ZSign flag.

The package is ZSign-compatible, not a file-by-file port. It keeps the familiar
command surface while exposing a Swift-native API and testable internal
components.

## Fast Re-signing

Bundle and IPA signing can reuse signatures from `.zsign_cache`. Cache keys
include normalized Mach-O bytes plus entitlements, resource seal, Info.plist,
identity, and CodeDirectory hash mode, so changed signing inputs miss the cache.

```bash
# First run creates cache entries.
rorksign -k dev.p12 -p password -m app.mobileprovision -o output.ipa ExtractedArchive/

# Reuses unchanged Mach-O signatures.
rorksign -k dev.p12 -p password -m app.mobileprovision -o output.ipa ExtractedArchive/

# Rebuilds signatures and refreshes cache entries.
rorksign -f -k dev.p12 -p password -m app.mobileprovision -o output.ipa ExtractedArchive/
```

Use `-V/--verbose` to print a signing preflight header plus signed, cached,
sealed, and archived paths.

## Logging

The library is silent by default. Swift callers can pass `SigningDiagnostics`
with a SwiftLog `Logger` through `BundleSigningOptions` or
`AppSigningOptions`:

```swift
import Foundation
import Logging
import RorkSign

LoggingSystem.bootstrap(StreamLogHandler.standardOutput)

var logger = Logger(label: "signing")
logger.logLevel = .info
let cacheURL = URL(fileURLWithPath: ".zsign_cache", isDirectory: true)

let options = BundleSigningOptions(
    signingCache: SigningCacheOptions(directoryURL: cacheURL),
    diagnostics: SigningDiagnostics(logger: logger)
)
```

Objective-C callers configure logging through the facade options:

```objc
RKBundleSigningOptions *options = [[RKBundleSigningOptions alloc] init];
options.logLevel = RKSigningLogLevelInfo;
options.logHandler = ^(RKSigningDiagnosticLevel level, NSString *message) {
    NSLog(@"[RorkSign] %@", message);
};
```

For object-oriented integrations, assign `options.logger` to an object that
conforms to `RKSigningLogger`. Use `RKSigningLogLevelDebug` to include detailed
path-level events such as sealed bundles and signed Mach-O files.

The CLI wires `-V/--verbose` to the same diagnostics path and keeps `-q/--quiet`
silent.

## Focused Subcommands

The default command is ZSign-compatible. Additional subcommands expose smaller
building blocks for tests, debugging, and integrations:

```bash
rorksign inspect <mach-o-path>
rorksign dylibs <mach-o-path>
rorksign metadata <app-or-ipa-path> <output-directory>
rorksign inject-dylib <input-mach-o> <output-mach-o> <install-name> [--weak]
rorksign remove-dylib <input-mach-o> <output-mach-o> <install-name-or-name> [...]
rorksign adhoc-sign <input-mach-o> <output-mach-o> <bundle-id>
rorksign adhoc-sign-bundle <bundle-path>
rorksign adhoc-sign-ipa <input-ipa> <output-ipa>
rorksign identity-sign <input-mach-o> <output-mach-o> <bundle-id> <cert-pem> <private-key-pem> [--password <password>]
rorksign identity-sign-p12 <input-mach-o> <output-mach-o> <bundle-id> <p12-path> <password>
rorksign identity-sign-profile-key <input-mach-o> <output-mach-o> <bundle-id> <profile-path> <credential-path> <password>
rorksign identity-sign-bundle <bundle-path> <cert-pem> <private-key-pem> [--password <password>]
rorksign identity-sign-bundle-p12 <bundle-path> <p12-path> <password>
rorksign identity-sign-bundle-profile-key <bundle-path> <profile-path> <credential-path> <password>
rorksign identity-sign-ipa <input-ipa> <output-ipa> <cert-pem> <private-key-pem> [--password <password>]
rorksign identity-sign-ipa-p12 <input-ipa> <output-ipa> <p12-path> <password>
rorksign identity-sign-ipa-profile-key <input-ipa> <output-ipa> <profile-path> <credential-path> <password>
rorksign sign ipa --input <ipa-app-or-extracted-path> --output <output-ipa> --bundle-id <bundle-id> --profile-map <profile-map-json> --certificate <cert-path> --key <credential-path> [--password <password> | --password-file <path>] [--app-groups <group,...>] [--bundle-name <name>] [--entitlements-resource <name>]
rorksign export-pkcs12 --certificate <cert-path> --key <credential-path> [--input-password <password> | --input-password-file <path>] --output <output-p12> [--output-password <password> | --output-password-file <path>]
rorksign seal-resources <bundle-path>
rorksign verify-resources <bundle-path>
rorksign team-id <profile-path> <credential-path> <password>
```

For `*-profile-key` commands, `credential-path` can point to a PEM/DER private
key or a PKCS#12 container. The password unlocks PKCS#12, encrypted PKCS#8, and
traditional encrypted RSA PEM credentials. Pass an empty password for
unencrypted PEM/DER credentials.

`sign ipa --profile-map` reads a JSON object keyed by the final bundle
identifiers. The root bundle id must be present. Relative profile paths are
resolved from the JSON file directory, while absolute paths remain unchanged.
The input can be an IPA, a direct `.app` bundle, or an extracted archive
directory containing `Payload`. The explicit `--certificate` and `--key` inputs
define the signing identity, and every selected provisioning profile must
authorize that certificate:

```json
{
  "com.example.app": "profiles/App.mobileprovision",
  "com.example.app.LiveProcess": "profiles/LiveProcess.mobileprovision"
}
```

`export-pkcs12` protects the exported identity with an output password. Direct
password values remain available for interactive use. Automation can read each
password from a file so the value does not appear in process arguments. Password
files are read verbatim. The command commits the output atomically after the
complete container has been encoded.

## Limitations

- Signing currently supports 64-bit Mach-O slices. 32-bit Mach-O files can be
  inspected, but not signed.
- The PKCS#12 importer focuses on common signing identities: one RSA, P-256,
  P-384, or P-521 private key plus a matching X.509 leaf certificate.
- Additional certificates are preserved in generated CMS output, but the signer
  does not perform platform trust-store evaluation.
- The CLI does not download CRLs or make Apple certificate-policy decisions.
- `--zip_level` preserves the ZSign flag shape, but the ZIP backend exposes
  stored vs deflated output rather than exact numeric compression tuning.

## Development

```bash
swift test
swift build -c release --product rorksign
```

The test suite uses synthetic Mach-O fixtures and temporary app/IPA bundles. It
asserts load-command mutations, SuperBlob indexes, CodeDirectory hash families,
entitlement slots, resource-directory hashes, CMS embedding, universal slice
rewrites, bundle signing order, app signing, CodeResources
verification, PKCS#12 import, OCSP parsing, and CLI behavior.

Some identity and CMS tests call OpenSSL as an external compatibility oracle
when it is available on the development machine. OpenSSL is not part of the
production signing path.

## License

rork-sign is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
Legal notices for bundled third-party components are available in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
