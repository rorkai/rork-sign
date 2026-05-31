#import "RorkSignObjC.h"

NSErrorDomain const RorkSignObjCErrorDomain = @"RorkSignObjC";

static NSError *RorkSignObjCError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:RorkSignObjCErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"RorkSign operation failed."}];
}

static NSDictionary<NSString *,id> *RorkSignObjCResponseDictionary(NSData *data, NSError **error) {
    if (data.length == 0) {
        return @{};
    }

    id propertyList = [NSPropertyListSerialization propertyListWithData:data
                                                                 options:0
                                                                  format:nil
                                                                   error:error];
    if (![propertyList isKindOfClass:NSDictionary.class]) {
        if (error) {
            *error = RorkSignObjCError(2, @"RorkSign response was not a dictionary.");
        }
        return nil;
    }
    return propertyList;
}

@implementation RorkSignSigner

+ (NSString *)version {
    NSDictionary<NSString *, id> *response = [self performOperation:RorkSignObjCOperationVersion
                                                            request:nil
                                                              error:nil];
    NSString *version = [response[@"version"] isKindOfClass:NSString.class] ? response[@"version"] : nil;
    return version ?: @"";
}

+ (NSDictionary<NSString *,id> *)performOperation:(RorkSignObjCOperation)operation
                                          request:(NSDictionary<NSString *,id> *)request
                                            error:(NSError **)error {
    NSError *serializationError = nil;
    NSData *requestData = [NSPropertyListSerialization dataWithPropertyList:request ?: @{}
                                                                    format:NSPropertyListBinaryFormat_v1_0
                                                                   options:0
                                                                     error:&serializationError];
    if (requestData.length == 0) {
        if (error) {
            *error = serializationError ?: RorkSignObjCError(1, @"Failed to encode RorkSign request.");
        }
        return nil;
    }

    void *valueBytes = NULL;
    intptr_t valueLength = 0;
    char *errorBytes = NULL;
    intptr_t errorLength = 0;
    bool success = RorkSignCExecute((RorkSignCOperation)operation,
                                    requestData.bytes,
                                    (intptr_t)requestData.length,
                                    &valueBytes,
                                    &valueLength,
                                    &errorBytes,
                                    &errorLength);
    if (!success) {
        NSString *message = nil;
        if (errorBytes && errorLength > 0) {
            message = [[NSString alloc] initWithBytes:errorBytes
                                              length:(NSUInteger)errorLength
                                            encoding:NSUTF8StringEncoding];
        }
        if (errorBytes) {
            RorkSignCFree(errorBytes);
        }
        if (error) {
            *error = RorkSignObjCError((NSInteger)operation, message);
        }
        return nil;
    }

    NSData *responseData = valueBytes && valueLength > 0
        ? [NSData dataWithBytes:valueBytes length:(NSUInteger)valueLength]
        : [NSData data];
    if (valueBytes) {
        RorkSignCFree(valueBytes);
    }
    return RorkSignObjCResponseDictionary(responseData, error);
}

+ (NSString *)validatedTeamIdentifierWithProvisioningProfileData:(NSData *)provisioningProfileData
                                                 credentialData:(NSData *)credentialData
                                                       password:(NSString *)password
                                                          error:(NSError **)error {
    NSDictionary<NSString *, id> *response = [self performOperation:RorkSignObjCOperationValidatedTeamIdentifier
                                                            request:@{
                                                                @"provisioningProfileData": provisioningProfileData,
                                                                @"credentialData": credentialData,
                                                                @"password": password ?: @"",
                                                            }
                                                              error:error];
    NSString *teamIdentifier = [response[@"teamIdentifier"] isKindOfClass:NSString.class] ? response[@"teamIdentifier"] : nil;
    if (!teamIdentifier && error && !*error) {
        *error = RorkSignObjCError(3, @"RorkSign response did not include a team identifier.");
    }
    return teamIdentifier;
}

+ (NSDictionary<NSString *,id> *)signBundleWithCredentialAtURL:(NSURL *)bundleURL
                                      provisioningProfileData:(NSData *)provisioningProfileData
                                               credentialData:(NSData *)credentialData
                                                     password:(NSString *)password
                                    embedProvisioningProfile:(BOOL)embedProvisioningProfile
                                codeDirectoryHashingModeName:(NSString *)codeDirectoryHashingModeName
                                                        error:(NSError **)error {
    return [self performOperation:RorkSignObjCOperationSignBundleWithCredential
                          request:@{
                              @"bundlePath": bundleURL.path ?: @"",
                              @"provisioningProfileData": provisioningProfileData,
                              @"credentialData": credentialData,
                              @"password": password ?: @"",
                              @"embedProvisioningProfile": @(embedProvisioningProfile),
                              @"codeDirectoryHashingMode": codeDirectoryHashingModeName ?: @"compatible",
                          }
                            error:error];
}

+ (NSDictionary<NSString *,id> *)signStandaloneBundleWithCredentialAtURL:(NSURL *)bundleURL
                                                 provisioningProfileData:(NSData *)provisioningProfileData
                                                          credentialData:(NSData *)credentialData
                                                                password:(NSString *)password
                                                        bundleIdentifier:(NSString *)bundleIdentifier
                             provisioningProfilesByBundleIdentifier:(NSDictionary<NSString *,NSData *> *)profilesByBundleIdentifier
                                           watchProvisioningProfileData:(NSData *)watchProvisioningProfileData
                                                    appGroupIdentifiers:(NSArray<NSString *> *)appGroupIdentifiers
                                            codeDirectoryHashingModeName:(NSString *)codeDirectoryHashingModeName
                                                                   error:(NSError **)error {
    NSMutableDictionary<NSString *, id> *request = [@{
        @"bundlePath": bundleURL.path ?: @"",
        @"provisioningProfileData": provisioningProfileData,
        @"credentialData": credentialData,
        @"password": password ?: @"",
        @"bundleIdentifier": bundleIdentifier ?: @"",
        @"provisioningProfilesByBundleIdentifier": profilesByBundleIdentifier ?: @{},
        @"appGroupIdentifiers": appGroupIdentifiers ?: @[],
        @"codeDirectoryHashingMode": codeDirectoryHashingModeName ?: @"sha256Only",
    } mutableCopy];
    if (watchProvisioningProfileData.length > 0) {
        request[@"watchProvisioningProfileData"] = watchProvisioningProfileData;
    }
    return [self performOperation:RorkSignObjCOperationSignStandaloneBundleWithCredential
                          request:request
                            error:error];
}

@end
