import Foundation
import RorkSign
import XCTest

final class ProvisioningProfileTests: XCTestCase {
    func testDecodesRawProvisioningProfilePlist() throws {
        let expirationDate = Date(timeIntervalSince1970: 1_800_000_000)
        let profile = try RorkSigner.decodeProvisioningProfile(
            try provisioningProfilePlist(
                teamIdentifiers: ["TEAMID1234"],
                applicationIdentifier: "TEAMID1234.app.rork.fixture",
                expirationDate: expirationDate,
                developerCertificates: [Data([0x01, 0x02, 0x03])]
            )
        )

        XCTAssertEqual(profile.teamIdentifier, "TEAMID1234")
        XCTAssertEqual(profile.applicationIdentifier, "TEAMID1234.app.rork.fixture")
        XCTAssertEqual(profile.authorizedBundleIdentifier, "app.rork.fixture")
        XCTAssertEqual(profile.explicitAuthorizedBundleIdentifier, "app.rork.fixture")
        XCTAssertFalse(profile.usesWildcardBundleIdentifier)
        XCTAssertEqual(profile.expirationDate, expirationDate)
        XCTAssertEqual(profile.developerCertificatesDER, [Data([0x01, 0x02, 0x03])])
        XCTAssertTrue(profile.containsDeveloperCertificateDER(Data([0x01, 0x02, 0x03])))
        XCTAssertFalse(profile.containsDeveloperCertificateDER(Data([0x03, 0x02, 0x01])))
        XCTAssertTrue(profile.entitlementsXML.contains("application-identifier"))
        XCTAssertFalse(profile.isExpired(at: Date(timeIntervalSince1970: 1_700_000_000)))
        XCTAssertTrue(profile.isExpired(at: Date(timeIntervalSince1970: 1_900_000_000)))
    }

    func testDecodesCMSWrappedProfileByExtractingEmbeddedXMLPlist() throws {
        let plist = try provisioningProfilePlist(
            teamIdentifiers: ["TEAMID1234"],
            applicationIdentifier: "TEAMID1234.app.rork.fixture",
            developerCertificates: [Data([0x0a])]
        )
        var wrapped = Data([0x30, 0x82, 0x01, 0x00])
        wrapped.append(plist)
        wrapped.append(Data([0x00, 0x01, 0x02]))

        let profile = try RorkSigner.decodeProvisioningProfile(wrapped)

        XCTAssertEqual(profile.teamIdentifier, "TEAMID1234")
        XCTAssertEqual(profile.applicationIdentifier, "TEAMID1234.app.rork.fixture")
        XCTAssertEqual(profile.developerCertificatesDER, [Data([0x0a])])
    }

    func testFallsBackToApplicationIdentifierTeamPrefix() throws {
        let profile = try RorkSigner.decodeProvisioningProfile(
            try provisioningProfilePlist(
                teamIdentifiers: [],
                applicationIdentifier: "TEAMID1234.app.rork.fixture",
                developerCertificates: [Data([0x0a])]
            )
        )

        XCTAssertEqual(profile.teamIdentifier, "TEAMID1234")
    }

    func testReturnsTeamIdentifierFromProfileDataAndFile() throws {
        let data = try provisioningProfilePlist(
            teamIdentifiers: ["TEAMID1234"],
            applicationIdentifier: "TEAMID1234.app.rork.fixture",
            developerCertificates: [Data([0x0a])]
        )
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try data.write(to: url)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertEqual(try RorkSigner.teamIdentifier(provisioningProfileData: data), "TEAMID1234")
        XCTAssertEqual(try RorkSigner.teamIdentifier(provisioningProfileAt: url), "TEAMID1234")
        XCTAssertEqual(
            RorkSigner.teamIdentifier(provisioningProfile: try RorkSigner.decodeProvisioningProfile(data)),
            "TEAMID1234"
        )
        XCTAssertEqual(try RorkSigner.authorizedBundleIdentifier(provisioningProfileData: data), "app.rork.fixture")
        XCTAssertEqual(try RorkSigner.authorizedBundleIdentifier(provisioningProfileAt: url), "app.rork.fixture")
        XCTAssertEqual(
            RorkSigner.authorizedBundleIdentifier(provisioningProfile: try RorkSigner.decodeProvisioningProfile(data)),
            "app.rork.fixture"
        )
        XCTAssertEqual(try RorkSigner.explicitAuthorizedBundleIdentifier(provisioningProfileData: data), "app.rork.fixture")
        XCTAssertEqual(try RorkSigner.explicitAuthorizedBundleIdentifier(provisioningProfileAt: url), "app.rork.fixture")
        XCTAssertEqual(
            RorkSigner.explicitAuthorizedBundleIdentifier(provisioningProfile: try RorkSigner.decodeProvisioningProfile(data)),
            "app.rork.fixture"
        )
    }

    func testSupportsExplicitBundleIdentifier() throws {
        let profile = try RorkSigner.decodeProvisioningProfile(
            try provisioningProfilePlist(
                teamIdentifiers: ["TEAMID1234"],
                applicationIdentifier: "TEAMID1234.app.rork.fixture",
                developerCertificates: [Data([0x0a])]
            )
        )

        XCTAssertTrue(profile.supportsBundleIdentifier("app.rork.fixture"))
        XCTAssertTrue(profile.supportsBundleIdentifier(" app.rork.fixture "))
        XCTAssertFalse(profile.supportsBundleIdentifier("app.rork.other"))
        XCTAssertEqual(profile.authorizedBundleIdentifier, "app.rork.fixture")
        XCTAssertEqual(profile.explicitAuthorizedBundleIdentifier, "app.rork.fixture")
        XCTAssertFalse(profile.usesWildcardBundleIdentifier)
    }

    func testSupportsRootWildcardBundleIdentifier() throws {
        let profile = try RorkSigner.decodeProvisioningProfile(
            try provisioningProfilePlist(
                teamIdentifiers: ["TEAMID1234"],
                applicationIdentifier: "TEAMID1234.*",
                developerCertificates: [Data([0x0a])]
            )
        )

        XCTAssertTrue(profile.supportsBundleIdentifier("app.rork.fixture"))
        XCTAssertTrue(profile.supportsBundleIdentifier("com.example.tool"))
        XCTAssertFalse(profile.supportsBundleIdentifier(""))
        XCTAssertEqual(profile.authorizedBundleIdentifier, "*")
        XCTAssertNil(profile.explicitAuthorizedBundleIdentifier)
        XCTAssertTrue(profile.usesWildcardBundleIdentifier)
    }

    func testSupportsPrefixWildcardBundleIdentifier() throws {
        let profile = try RorkSigner.decodeProvisioningProfile(
            try provisioningProfilePlist(
                teamIdentifiers: ["TEAMID1234"],
                applicationIdentifier: "TEAMID1234.com.example.*",
                developerCertificates: [Data([0x0a])]
            )
        )

        XCTAssertTrue(profile.supportsBundleIdentifier("com.example.child"))
        XCTAssertTrue(profile.supportsBundleIdentifier("com.example.child.extension"))
        XCTAssertFalse(profile.supportsBundleIdentifier("com.example"))
        XCTAssertFalse(profile.supportsBundleIdentifier("com.examples.child"))
        XCTAssertEqual(profile.authorizedBundleIdentifier, "com.example.*")
        XCTAssertNil(profile.explicitAuthorizedBundleIdentifier)
        XCTAssertTrue(profile.usesWildcardBundleIdentifier)
    }

    func testRejectsProfileWithoutDeveloperCertificates() {
        XCTAssertThrowsError(
            try RorkSigner.decodeProvisioningProfile(
                try provisioningProfilePlist(
                    teamIdentifiers: ["TEAMID1234"],
                    applicationIdentifier: "TEAMID1234.app.rork.fixture",
                    developerCertificates: []
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidProvisioningProfile("Provisioning profile does not contain developer certificates.")
            )
        }
    }

    func testRejectsDataWithoutPlistPayload() {
        XCTAssertThrowsError(try RorkSigner.decodeProvisioningProfile(Data([0x01, 0x02, 0x03]))) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidProvisioningProfile("Provisioning profile is not a plist and no embedded XML plist was found.")
            )
        }
    }
}

private func provisioningProfilePlist(
    teamIdentifiers: [String],
    applicationIdentifier: String,
    expirationDate: Date = Date(timeIntervalSince1970: 1_800_000_000),
    developerCertificates: [Data]
) throws -> Data {
    let plist: [String: Any] = [
        "TeamIdentifier": teamIdentifiers,
        "ExpirationDate": expirationDate,
        "DeveloperCertificates": developerCertificates,
        "Entitlements": [
            "application-identifier": applicationIdentifier,
            "get-task-allow": true,
        ],
    ]
    return try PropertyListSerialization.data(
        fromPropertyList: plist,
        format: .xml,
        options: 0
    )
}
