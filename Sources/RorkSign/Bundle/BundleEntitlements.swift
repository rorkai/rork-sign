import Foundation

/// Builds final entitlement XML from a provisioning profile and executable state.
///
/// Provisioning profiles describe the capabilities Apple is willing to authorize,
/// but their entitlement payload often contains wildcard or profile-specific App
/// IDs. A signed executable needs entitlements scoped to the bundle identifier
/// being written into its CodeDirectory. This helper performs that expansion
/// while keeping optional capabilities limited to those the original executable
/// already requested.
enum BundleEntitlements {
    private static let associatedApplicationIdentifierKeys: Set<String> = [
        "associated-application-identifier",
        "com.apple.developer.associated-application-identifier",
    ]

    private static let generatedEntitlementKeys = Set([
        "application-identifier",
        "com.apple.developer.team-identifier",
        "keychain-access-groups",
    ]).union(associatedApplicationIdentifierKeys)

    private static let alwaysKeptEntitlementKeys: Set<String> = generatedEntitlementKeys.union([
        "get-task-allow",
    ])

    /// Expands profile entitlements for one bundle identifier.
    ///
    /// The profile is the upper bound of allowed capabilities. The original
    /// executable entitlement plist is used as a filter so optional profile
    /// capabilities are kept only when the executable already asked for them.
    static func expand(
        profile: ProvisioningProfile,
        bundleIdentifier: String,
        originalEntitlementsXML: String,
        associatedBundleIdentifier: String? = nil,
        appGroupIdentifiers: [String] = []
    ) throws -> String {
        var entitlements = try EntitlementPlist.dictionary(fromXML: profile.entitlementsXML)
        guard !entitlements.isEmpty else {
            return ""
        }

        let original = try EntitlementPlist.dictionary(fromXML: originalEntitlementsXML)
        let appGroups = AppGroupIdentifiers.normalize(appGroupIdentifiers)
        for key in Array(entitlements.keys) {
            guard shouldKeep(key, original: original, appGroupIdentifiers: appGroups) else {
                entitlements.removeValue(forKey: key)
                continue
            }
            if let narrowedValue = narrowedProfileValue(
                entitlements[key],
                requestedValue: original[key],
                key: key
            ) {
                entitlements[key] = narrowedValue
            }
        }

        let applicationIdentifier = "\(profile.teamIdentifier).\(bundleIdentifier)"
        entitlements["application-identifier"] = applicationIdentifier
        entitlements["com.apple.developer.team-identifier"] = profile.teamIdentifier
        let keychainGroups = normalizedKeychainGroups(
            original: original,
            teamIdentifier: profile.teamIdentifier,
            applicationIdentifier: applicationIdentifier
        )
        entitlements["keychain-access-groups"] = keychainGroups

        if let associatedBundleIdentifier, !associatedBundleIdentifier.isEmpty {
            for key in associatedApplicationIdentifierKeys where entitlements[key] != nil {
                entitlements[key] = "\(profile.teamIdentifier).\(associatedBundleIdentifier)"
            }
        }

        if !appGroups.isEmpty {
            entitlements["com.apple.security.application-groups"] = appGroups
        }

        return try EntitlementPlist.xml(from: entitlements)
    }

    /// Decides whether a profile entitlement should remain in the signed output.
    private static func shouldKeep(
        _ key: String,
        original: [String: Any],
        appGroupIdentifiers: [String]
    ) -> Bool {
        if alwaysKeptEntitlementKeys.contains(key) {
            return true
        }
        if key == "com.apple.security.application-groups" {
            return !appGroupIdentifiers.isEmpty || original[key] != nil
        }
        return original[key] != nil
    }

    /// Preserves explicit string-array entitlement requests when the profile
    /// authorizes a broader set of values.
    private static func narrowedProfileValue(
        _ profileValue: Any?,
        requestedValue: Any?,
        key: String
    ) -> Any? {
        let profileValues = stringArray(profileValue)
        let requestedValues = stringArray(requestedValue)
        guard !profileValues.isEmpty, !requestedValues.isEmpty else {
            return nil
        }
        guard requestedValues.allSatisfy(profileValues.contains) else {
            return nil
        }
        return generatedEntitlementKeys.contains(key) ? nil : requestedValues
    }

    private static func stringArray(_ value: Any?) -> [String] {
        guard let values = value as? [String] else {
            return []
        }
        return values
    }

    /// Rewrites requested keychain access groups to the signing team's App ID prefix.
    private static func normalizedKeychainGroups(
        original: [String: Any],
        teamIdentifier: String,
        applicationIdentifier: String
    ) -> [String] {
        var groups: [String] = []
        for value in original["keychain-access-groups"] as? [String] ?? [] {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                continue
            }

            let normalized: String
            if let dot = trimmed.firstIndex(of: ".") {
                normalized = teamIdentifier + trimmed[dot...]
            } else {
                normalized = "\(teamIdentifier).\(trimmed)"
            }
            if !groups.contains(normalized) {
                groups.append(normalized)
            }
        }

        return groups.isEmpty ? [applicationIdentifier] : groups
    }
}

/// Normalizes caller-provided app-group identifiers while preserving order.
enum AppGroupIdentifiers {
    /// Removes blank duplicates while preserving the first occurrence.
    static func normalize(_ values: [String]) -> [String] {
        var result: [String] = []
        for value in values {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, !result.contains(trimmed) else {
                continue
            }
            result.append(trimmed)
        }
        return result
    }
}

/// XML property-list helpers for entitlement dictionaries.
enum EntitlementPlist {
    /// Parses XML entitlement plist data into a dictionary.
    static func dictionary(fromXML xml: String) throws -> [String: Any] {
        let trimmed = xml.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return [:]
        }
        do {
            let data = Data(trimmed.utf8)
            let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            guard let dictionary = plist as? [String: Any] else {
                throw RorkSignError.invalidEntitlements("Entitlement plist must contain a dictionary.")
            }
            return dictionary
        } catch let error as RorkSignError {
            throw error
        } catch {
            throw RorkSignError.invalidEntitlements("Entitlement plist could not be parsed.")
        }
    }

    /// Serializes an entitlement dictionary as XML plist data.
    static func xml(from dictionary: [String: Any]) throws -> String {
        do {
            let data = try PropertyListWriter.data(
                from: dictionary,
                format: .xml
            )
            return String(decoding: data, as: UTF8.self)
        } catch {
            throw RorkSignError.invalidEntitlements("Entitlement plist could not be serialized.")
        }
    }
}
