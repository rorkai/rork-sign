# rork-sign

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](Package.swift)
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
- [Objective-C API](#objective-c-api)
- [ZSign Compatibility](#zsign-compatibility)
- [Fast Re-signing](#fast-re-signing)
- [Limitations](#limitations)
- [Development](#development)
- [License](#license)

## Features

- **ZSign-compatible CLI** - supports the public ZSign-style signing flags for
  IPA, bundle, and Mach-O workflows.
- **Swift-first library** - the `RorkSign` module exposes signing, inspection,
  resource sealing, and credential APIs directly to Swift applications.
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

The package currently declares:

- macOS 13+
- iOS 15+

The CLI is intended for macOS development and CI environments with a Swift
toolchain. The library code is pure Swift and SwiftPM-based; additional platform
support should be added with CI coverage before it is advertised as supported.

## Build

```bash
git clone https://github.com/rorkai/rork-sign.git
cd rork-sign
swift build -c release
.build/release/rorksign --help
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
    .package(url: "https://github.com/rorkai/rork-sign.git", from: "0.2.9"),
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

Validate a profile/private-key pair before signing:

```swift
let teamID = try RorkSigner.validatedTeamIdentifier(
    provisioningProfileData: Data(contentsOf: URL(fileURLWithPath: "app.mobileprovision")),
    credentialData: Data(contentsOf: URL(fileURLWithPath: "dev.p12")),
    password: "password"
)
```

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

NSString *teamID = [signer validatedTeamIdentifierWithProvisioningProfileData:profile
                                                                credentialData:credential
                                                                      password:@"password"
                                                                         error:&error];
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
| Entitlements/profile handling | `-e/--entitlements`, `-R/--rm_provision` |
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

Use `-V/--verbose` to print signed, cached, sealed, and archived paths.

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
rorksign standalone-sign-ipa-adhoc <input-ipa> <output-ipa> <bundle-id> <profile-path>
rorksign standalone-sign-ipa-p12 <input-ipa> <output-ipa> <bundle-id> <profile-path> <p12-path> <password>
rorksign standalone-sign-ipa-profile-key <input-ipa> <output-ipa> <bundle-id> <profile-path> <credential-path> <password>
rorksign seal-resources <bundle-path>
rorksign verify-resources <bundle-path>
rorksign team-id <profile-path> <credential-path> <password>
```

For `*-profile-key` commands, `credential-path` can point to a PEM/DER private
key or a PKCS#12 container. The password unlocks PKCS#12, encrypted PKCS#8, and
traditional encrypted RSA PEM credentials. Pass an empty password for
unencrypted PEM/DER credentials.

## Limitations

- Signing currently supports 64-bit Mach-O slices. 32-bit Mach-O files can be
  inspected, but not signed.
- The PKCS#12 importer focuses on common signing identities: one RSA, P-256,
  P-384, or P-521 private key plus a matching X.509 leaf certificate.
- Additional certificates are preserved in generated CMS output, but the signer
  does not perform platform trust-store evaluation.
- The CLI does not download CRLs or make Apple certificate-policy decisions.
- `--zip_level` preserves the ZSign flag shape, but Swift ZIPFoundation exposes
  stored vs deflated output rather than exact numeric compression tuning.

## Development

```bash
swift test
swift build -c release
```

The test suite uses synthetic Mach-O fixtures and temporary app/IPA bundles. It
asserts load-command mutations, SuperBlob indexes, CodeDirectory hash families,
entitlement slots, resource-directory hashes, CMS embedding, universal slice
rewrites, bundle signing order, standalone bundle rewriting, CodeResources
verification, PKCS#12 import, OCSP parsing, and CLI behavior.

Some identity and CMS tests call OpenSSL as an external compatibility oracle
when it is available on the development machine. OpenSSL is not part of the
production signing path.

## License

rork-sign is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
