import Foundation

/// Decodes Apple provisioning profiles into the small model the signer needs.
///
/// Real `.mobileprovision` files are CMS envelopes, but their payload is still a
/// property list. For signing decisions we only need the payload fields, not CMS
/// trust validation, so the decoder supports both raw plist data and wrapped
/// profiles that contain an embedded XML plist.
enum ProvisioningProfileDecoder {
    /// Decodes raw plist data or CMS-wrapped `.mobileprovision` bytes.
    static func decode(_ data: Data) throws -> ProvisioningProfile {
        guard !data.isEmpty else {
            throw RorkSignError.invalidProvisioningProfile("Provisioning profile data is empty.")
        }

        let plistData = try directPlistData(data) ?? embeddedXMLPlistData(data)
        let plist = try parsePlist(plistData)
        return try profile(from: plist)
    }

    /// Returns `data` when it is already a property-list dictionary.
    private static func directPlistData(_ data: Data) throws -> Data? {
        do {
            let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            return (plist as? [String: Any]) == nil ? nil : data
        } catch {
            return nil
        }
    }

    /// Extracts the first XML plist from a CMS-wrapped provisioning profile.
    ///
    /// This mirrors the practical behavior of Apple provisioning profiles: the
    /// plist payload is embedded as XML bytes inside the CMS envelope. The method
    /// is deliberately strict about both start and end markers so random binary
    /// data cannot be silently accepted.
    private static func embeddedXMLPlistData(_ data: Data) throws -> Data {
        let startMarker = Data("<?xml".utf8)
        let endMarker = Data("</plist>".utf8)
        guard let startRange = data.range(of: startMarker),
              let endRange = data.range(of: endMarker, in: startRange.lowerBound..<data.endIndex)
        else {
            throw RorkSignError.invalidProvisioningProfile(
                "Provisioning profile is not a plist and no embedded XML plist was found."
            )
        }

        return Data(data[startRange.lowerBound..<endRange.upperBound])
    }

    private static func parsePlist(_ data: Data) throws -> [String: Any] {
        do {
            let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            guard let dictionary = plist as? [String: Any] else {
                throw RorkSignError.invalidProvisioningProfile("Provisioning profile plist is not a dictionary.")
            }
            return dictionary
        } catch let error as RorkSignError {
            throw error
        } catch {
            throw RorkSignError.invalidProvisioningProfile("Provisioning profile plist could not be parsed.")
        }
    }

    /// Maps the plist dictionary into a public, value-typed profile.
    private static func profile(from plist: [String: Any]) throws -> ProvisioningProfile {
        let entitlements = plist["Entitlements"] as? [String: Any] ?? [:]
        let teamIdentifier = teamIdentifier(from: plist, entitlements: entitlements)
        guard let teamIdentifier else {
            throw RorkSignError.invalidProvisioningProfile(
                "Provisioning profile does not contain a team identifier."
            )
        }

        let entitlementXML = try entitlementXML(from: entitlements)
        let developerCertificates = (plist["DeveloperCertificates"] as? [Data]) ?? []
        guard !developerCertificates.isEmpty else {
            throw RorkSignError.invalidProvisioningProfile(
                "Provisioning profile does not contain developer certificates."
            )
        }

        return ProvisioningProfile(
            teamIdentifier: teamIdentifier,
            entitlementsXML: entitlementXML,
            applicationIdentifier: trimmedString(entitlements["application-identifier"]),
            expirationDate: plist["ExpirationDate"] as? Date,
            developerCertificatesDER: developerCertificates
        )
    }

    /// Resolves the team identifier from the canonical profile field, then from
    /// entitlement fallbacks used by older fixtures.
    private static func teamIdentifier(from plist: [String: Any], entitlements: [String: Any]) -> String? {
        if let teams = plist["TeamIdentifier"] as? [String],
           let team = teams.compactMap(trimmedString).first {
            return team
        }
        if let team = trimmedString(entitlements["com.apple.developer.team-identifier"]) {
            return team
        }
        guard let applicationIdentifier = trimmedString(entitlements["application-identifier"]),
              let dotIndex = applicationIdentifier.firstIndex(of: "."),
              dotIndex > applicationIdentifier.startIndex else {
            return nil
        }
        return String(applicationIdentifier[..<dotIndex])
    }

    /// Serializes only the profile's entitlement dictionary as XML.
    private static func entitlementXML(from entitlements: [String: Any]) throws -> String {
        guard !entitlements.isEmpty else {
            return ""
        }
        let data = try PropertyListWriter.data(
            from: entitlements,
            format: .xml
        )
        return String(decoding: data, as: UTF8.self)
    }

    private static func trimmedString(_ value: Any?) -> String? {
        guard let string = value as? String else {
            return nil
        }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
