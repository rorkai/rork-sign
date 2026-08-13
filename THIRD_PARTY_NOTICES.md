# Third-Party Notices

This distribution includes the open-source components listed below. The
versions and source revisions are the values resolved by Swift Package Manager
and recorded in this repository's `Package.resolved`.

The Apache License 2.0 text is available in the repository's
[LICENSE](LICENSE) file. Exact upstream license and attribution texts are
preserved under [ThirdPartyLicenses](ThirdPartyLicenses).

## Apache License 2.0 Components

- [Swift Argument Parser 1.8.2](https://github.com/apple/swift-argument-parser),
  revision `6a52f3251125d74daf04fcbd5e6f08a75d074382`
- [Swift ASN.1 1.7.1](https://github.com/apple/swift-asn1), revision
  `a9a5efd40eaf558a2bcd48d64b1d1646be686008`
- [Swift Crypto](https://github.com/rorkai/swift-crypto), revision
  `f171fca4c1718d685c495350fe9136a3fda6f262`, based on upstream 4.5.0
  revision `1b6b2e274e85105bfa155183145a1dcfd63331f1`
- [Swift Log 1.13.2](https://github.com/apple/swift-log), revision
  `92448c359f00ebe36ae97d3bd9086f13c7692b5a`

The corresponding upstream legal texts are reproduced in:

- [SwiftArgumentParser-LICENSE.txt](ThirdPartyLicenses/SwiftArgumentParser-LICENSE.txt)
- [SwiftASN1-LICENSE.txt](ThirdPartyLicenses/SwiftASN1-LICENSE.txt)
- [SwiftASN1-NOTICE.txt](ThirdPartyLicenses/SwiftASN1-NOTICE.txt)
- [SwiftCrypto-LICENSE.txt](ThirdPartyLicenses/SwiftCrypto-LICENSE.txt)
- [SwiftCrypto-NOTICE.txt](ThirdPartyLicenses/SwiftCrypto-NOTICE.txt)
- [SwiftLog-LICENSE.txt](ThirdPartyLicenses/SwiftLog-LICENSE.txt)
- [SwiftLog-NOTICE.txt](ThirdPartyLicenses/SwiftLog-NOTICE.txt)

## Other Components

### Windows Static Runtime

The Windows x64 executable statically incorporates the standard library,
runtime support, Foundation, Dispatch, and Blocks Runtime from the
checksum-pinned Swift 6.4 development snapshot dated August 1, 2026. These
components use the Apache License 2.0 with the Swift Runtime Library Exception.
The Apache License 2.0 text is included in the package-level `LICENSE`, and the
exception is reproduced in
[SwiftRuntime-EXCEPTION.txt](ThirdPartyLicenses/SwiftRuntime-EXCEPTION.txt).

The executable also incorporates ICU 76.1, curl 8.9.1-DEV, zlib 1.3.1, and
Brotli 1.2.0 from the same pinned SDK. Their legal texts are reproduced in
[ICU-LICENSE.txt](ThirdPartyLicenses/ICU-LICENSE.txt),
[Curl-LICENSE.txt](ThirdPartyLicenses/Curl-LICENSE.txt),
[Zlib-LICENSE.txt](ThirdPartyLicenses/Zlib-LICENSE.txt), and
[Brotli-LICENSE.txt](ThirdPartyLicenses/Brotli-LICENSE.txt).

### Swift Zip Archive

[Swift Zip Archive](https://github.com/rorkai/swift-zip-archive), revision
`8e1b462cee9875e8a4ef991df1a43ba884cc70bb`, is based on
[the upstream project](https://github.com/adam-fowler/swift-zip-archive) and is
distributed under the Apache License 2.0. It includes a namespaced copy of
[zlib](https://www.zlib.net/) under the zlib License. The corresponding legal
and attribution texts are reproduced in:

- [SwiftZipArchive-LICENSE.txt](ThirdPartyLicenses/SwiftZipArchive-LICENSE.txt)
- [SwiftZipArchive-NOTICE.txt](ThirdPartyLicenses/SwiftZipArchive-NOTICE.txt)
- [Zlib-LICENSE.txt](ThirdPartyLicenses/Zlib-LICENSE.txt)

### BoringSSL

Swift Crypto incorporates [BoringSSL](https://boringssl.googlesource.com/boringssl/)
source derived from revision `0226f30467f540a3f62ef48d453f93927da199b6`.
BoringSSL contains code under Apache 2.0, ISC, OpenSSL, SSLeay, and additional
compatible license terms. The complete license file for that revision is
reproduced in
[BoringSSL-LICENSE.txt](ThirdPartyLicenses/BoringSSL-LICENSE.txt).
