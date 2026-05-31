#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Operation identifiers accepted by `RorkSignCExecute`.
///
/// Requests and responses are binary property lists. This keeps the C ABI small
/// and stable while allowing callers to pass structured inputs such as
/// dictionaries, arrays, `NSData` values, dates, and strings through
/// `CFPropertyList`.
typedef enum RorkSignCOperation : int32_t {
    RorkSignCOperationVersion = 0,
    RorkSignCOperationInspectMachO = 1,
    RorkSignCOperationExtractBundleMetadata = 2,
    RorkSignCOperationExtractIPAMetadata = 3,
    RorkSignCOperationCheckCertificate = 4,
    RorkSignCOperationCheckCertificateChain = 5,
    RorkSignCOperationValidateCertificateChain = 6,
    RorkSignCOperationMakeOCSPRequest = 7,
    RorkSignCOperationParseOCSPResponse = 8,
    RorkSignCOperationVerifyOCSPResponseSignature = 9,
    RorkSignCOperationValidateOCSPResponse = 10,
    RorkSignCOperationCheckProvisioningProfile = 11,
    RorkSignCOperationCheckPKCS12Identity = 12,
    RorkSignCOperationCheckSigningIdentity = 13,
    RorkSignCOperationCheckProfileCredential = 14,
    RorkSignCOperationCheckMachOCodeSignatures = 15,
    RorkSignCOperationReadEmbeddedCodeSignatures = 16,
    RorkSignCOperationDylibLoadCommands = 17,
    RorkSignCOperationInjectDylibLoadCommand = 18,
    RorkSignCOperationRemoveDylibLoadCommands = 19,
    RorkSignCOperationSignMachOAdHoc = 20,
    RorkSignCOperationPrepareMachOCMSCodeDirectories = 21,
    RorkSignCOperationSignMachOWithCMSBlobs = 22,
    RorkSignCOperationMakeDetachedCMSSignature = 23,
    RorkSignCOperationVerifyDetachedCMSSignature = 24,
    RorkSignCOperationSignMachOWithIdentity = 25,
    RorkSignCOperationDecodeProvisioningProfile = 26,
    RorkSignCOperationValidatedTeamIdentifier = 27,
    RorkSignCOperationBuildCodeResources = 28,
    RorkSignCOperationSealBundleResources = 29,
    RorkSignCOperationVerifyCodeResources = 30,
    RorkSignCOperationVerifyCodeResourcesRecursively = 31,
    RorkSignCOperationSignBundleAdHoc = 32,
    RorkSignCOperationSignBundleWithIdentity = 33,
    RorkSignCOperationSignBundleWithCredential = 34,
    RorkSignCOperationSignStandaloneBundleAdHoc = 35,
    RorkSignCOperationSignStandaloneBundleWithIdentity = 36,
    RorkSignCOperationSignStandaloneBundleWithCredential = 37,
    RorkSignCOperationSignIPAAdHoc = 38,
    RorkSignCOperationSignIPAWithIdentity = 39,
    RorkSignCOperationSignStandaloneIPAAdHoc = 40,
    RorkSignCOperationSignStandaloneIPAWithIdentity = 41,
    RorkSignCOperationSignStandaloneIPAWithCredential = 42,
} RorkSignCOperation;

/// Executes a RorkSign operation through a C-compatible ABI.
///
/// `requestBytes` may be `NULL` when `requestLength` is zero; otherwise it must
/// point to a binary property-list dictionary. On success, the function writes a
/// newly allocated binary property-list response to `valueBytes` and
/// `valueLength`. On failure, it writes a newly allocated UTF-8 error message to
/// `errorBytes` and `errorLength`.
///
/// The caller owns any non-NULL output pointer and must release it with
/// `RorkSignCFree`.
bool RorkSignCExecute(RorkSignCOperation operation,
                      const void *requestBytes,
                      intptr_t requestLength,
                      void **valueBytes,
                      intptr_t *valueLength,
                      char **errorBytes,
                      intptr_t *errorLength);

/// Releases a pointer returned by `RorkSignCExecute`.
void RorkSignCFree(void *bytes);

#ifdef __cplusplus
}
#endif
