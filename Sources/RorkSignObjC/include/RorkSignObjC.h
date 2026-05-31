#import <Foundation/Foundation.h>
#import "RorkSignC.h"

NS_ASSUME_NONNULL_BEGIN

/// Objective-C operation identifiers matching the public C ABI.
typedef NS_ENUM(NSInteger, RorkSignObjCOperation) {
    RorkSignObjCOperationVersion = RorkSignCOperationVersion,
    RorkSignObjCOperationInspectMachO = RorkSignCOperationInspectMachO,
    RorkSignObjCOperationExtractBundleMetadata = RorkSignCOperationExtractBundleMetadata,
    RorkSignObjCOperationExtractIPAMetadata = RorkSignCOperationExtractIPAMetadata,
    RorkSignObjCOperationCheckCertificate = RorkSignCOperationCheckCertificate,
    RorkSignObjCOperationCheckCertificateChain = RorkSignCOperationCheckCertificateChain,
    RorkSignObjCOperationValidateCertificateChain = RorkSignCOperationValidateCertificateChain,
    RorkSignObjCOperationMakeOCSPRequest = RorkSignCOperationMakeOCSPRequest,
    RorkSignObjCOperationParseOCSPResponse = RorkSignCOperationParseOCSPResponse,
    RorkSignObjCOperationVerifyOCSPResponseSignature = RorkSignCOperationVerifyOCSPResponseSignature,
    RorkSignObjCOperationValidateOCSPResponse = RorkSignCOperationValidateOCSPResponse,
    RorkSignObjCOperationCheckProvisioningProfile = RorkSignCOperationCheckProvisioningProfile,
    RorkSignObjCOperationCheckPKCS12Identity = RorkSignCOperationCheckPKCS12Identity,
    RorkSignObjCOperationCheckSigningIdentity = RorkSignCOperationCheckSigningIdentity,
    RorkSignObjCOperationCheckProfileCredential = RorkSignCOperationCheckProfileCredential,
    RorkSignObjCOperationCheckMachOCodeSignatures = RorkSignCOperationCheckMachOCodeSignatures,
    RorkSignObjCOperationReadEmbeddedCodeSignatures = RorkSignCOperationReadEmbeddedCodeSignatures,
    RorkSignObjCOperationDylibLoadCommands = RorkSignCOperationDylibLoadCommands,
    RorkSignObjCOperationInjectDylibLoadCommand = RorkSignCOperationInjectDylibLoadCommand,
    RorkSignObjCOperationRemoveDylibLoadCommands = RorkSignCOperationRemoveDylibLoadCommands,
    RorkSignObjCOperationSignMachOAdHoc = RorkSignCOperationSignMachOAdHoc,
    RorkSignObjCOperationPrepareMachOCMSCodeDirectories = RorkSignCOperationPrepareMachOCMSCodeDirectories,
    RorkSignObjCOperationSignMachOWithCMSBlobs = RorkSignCOperationSignMachOWithCMSBlobs,
    RorkSignObjCOperationMakeDetachedCMSSignature = RorkSignCOperationMakeDetachedCMSSignature,
    RorkSignObjCOperationVerifyDetachedCMSSignature = RorkSignCOperationVerifyDetachedCMSSignature,
    RorkSignObjCOperationSignMachOWithIdentity = RorkSignCOperationSignMachOWithIdentity,
    RorkSignObjCOperationDecodeProvisioningProfile = RorkSignCOperationDecodeProvisioningProfile,
    RorkSignObjCOperationValidatedTeamIdentifier = RorkSignCOperationValidatedTeamIdentifier,
    RorkSignObjCOperationBuildCodeResources = RorkSignCOperationBuildCodeResources,
    RorkSignObjCOperationSealBundleResources = RorkSignCOperationSealBundleResources,
    RorkSignObjCOperationVerifyCodeResources = RorkSignCOperationVerifyCodeResources,
    RorkSignObjCOperationVerifyCodeResourcesRecursively = RorkSignCOperationVerifyCodeResourcesRecursively,
    RorkSignObjCOperationSignBundleAdHoc = RorkSignCOperationSignBundleAdHoc,
    RorkSignObjCOperationSignBundleWithIdentity = RorkSignCOperationSignBundleWithIdentity,
    RorkSignObjCOperationSignBundleWithCredential = RorkSignCOperationSignBundleWithCredential,
    RorkSignObjCOperationSignStandaloneBundleAdHoc = RorkSignCOperationSignStandaloneBundleAdHoc,
    RorkSignObjCOperationSignStandaloneBundleWithIdentity = RorkSignCOperationSignStandaloneBundleWithIdentity,
    RorkSignObjCOperationSignStandaloneBundleWithCredential = RorkSignCOperationSignStandaloneBundleWithCredential,
    RorkSignObjCOperationSignIPAAdHoc = RorkSignCOperationSignIPAAdHoc,
    RorkSignObjCOperationSignIPAWithIdentity = RorkSignCOperationSignIPAWithIdentity,
    RorkSignObjCOperationSignStandaloneIPAAdHoc = RorkSignCOperationSignStandaloneIPAAdHoc,
    RorkSignObjCOperationSignStandaloneIPAWithIdentity = RorkSignCOperationSignStandaloneIPAWithIdentity,
    RorkSignObjCOperationSignStandaloneIPAWithCredential = RorkSignCOperationSignStandaloneIPAWithCredential,
};

FOUNDATION_EXPORT NSErrorDomain const RorkSignObjCErrorDomain;

/// Foundation-friendly Objective-C facade over the Swift `RorkSign` engine.
///
/// Methods accept property-list-compatible Foundation types and return
/// `NSDictionary` reports produced by the Swift signer. The Objective-C layer is
/// intentionally thin: it serializes requests, calls the public C ABI, decodes
/// responses, and maps failures into `NSError`.
@interface RorkSignSigner : NSObject

/// Returns the underlying Swift signer version.
+ (NSString *)version;

/// Performs any public signer operation using a property-list request.
///
/// See `RorkSignCOperation` for the complete operation list. Requests and
/// responses use the same field names as the Swift C bridge:
/// `data`, `bundlePath`, `archivePath`, `outputArchivePath`,
/// `provisioningProfileData`, `credentialData`, `password`,
/// `bundleIdentifier`, and operation-specific option keys.
+ (nullable NSDictionary<NSString *, id> *)performOperation:(RorkSignObjCOperation)operation
                                                    request:(nullable NSDictionary<NSString *, id> *)request
                                                      error:(NSError **)error;

/// Validates a provisioning profile and signing credential, then returns the
/// authorized Apple team identifier.
+ (nullable NSString *)validatedTeamIdentifierWithProvisioningProfileData:(NSData *)provisioningProfileData
                                                           credentialData:(NSData *)credentialData
                                                                 password:(NSString *)password
                                                                    error:(NSError **)error;

/// Signs an app-style bundle with a provisioning profile and private-key
/// credential.
+ (nullable NSDictionary<NSString *, id> *)signBundleWithCredentialAtURL:(NSURL *)bundleURL
                                                 provisioningProfileData:(NSData *)provisioningProfileData
                                                          credentialData:(NSData *)credentialData
                                                                password:(NSString *)password
                                               embedProvisioningProfile:(BOOL)embedProvisioningProfile
                                           codeDirectoryHashingModeName:(NSString *)codeDirectoryHashingModeName
                                                                   error:(NSError **)error;

/// Rewrites and signs a copied app as a standalone installable bundle.
+ (nullable NSDictionary<NSString *, id> *)signStandaloneBundleWithCredentialAtURL:(NSURL *)bundleURL
                                                           provisioningProfileData:(NSData *)provisioningProfileData
                                                                    credentialData:(NSData *)credentialData
                                                                          password:(NSString *)password
                                                                  bundleIdentifier:(NSString *)bundleIdentifier
                                      provisioningProfilesByBundleIdentifier:(nullable NSDictionary<NSString *, NSData *> *)profilesByBundleIdentifier
                                                    watchProvisioningProfileData:(nullable NSData *)watchProvisioningProfileData
                                                               appGroupIdentifiers:(nullable NSArray<NSString *> *)appGroupIdentifiers
                                                       codeDirectoryHashingModeName:(NSString *)codeDirectoryHashingModeName
                                                                             error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
