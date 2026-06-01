import Foundation
import RorkSign
import XCTest

final class StandaloneBundleSigningTests: XCTestCase {
    /// Verifies standalone inspection previews rewritten identifiers without touching Info.plists.
    func testStandaloneInspectionReportsRewrittenProvisioningRequirementsWithoutMutatingBundle() throws {
        let fixture = try makeStandaloneBundleFixture(includeWatchApp: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        let report = try RorkSigner.inspectStandaloneBundle(
            at: fixture.bundleURL,
            replacementBundleIdentifier: " app.rork.inspect "
        )

        XCTAssertEqual(report.rootBundleURL, fixture.bundleURL)
        XCTAssertEqual(report.rootBundleIdentifier, "com.original.host")
        XCTAssertEqual(report.replacementBundleIdentifier, "app.rork.inspect")
        XCTAssertEqual(report.rewrittenBundleIdentifiers, [
            "app.rork.inspect",
            "app.rork.inspect.ShareExtension",
            "app.rork.inspect.watchkitapp",
        ])
        XCTAssertEqual(report.appExtensionBundleIdentifiers, ["app.rork.inspect.ShareExtension"])
        XCTAssertEqual(report.watchBundleIdentifiers, ["app.rork.inspect.watchkitapp"])

        let root = try XCTUnwrap(report.provisioningRequirements.first)
        XCTAssertEqual(root.url, fixture.bundleURL)
        XCTAssertEqual(root.relativePath, ".")
        XCTAssertEqual(root.originalBundleIdentifier, "com.original.host")
        XCTAssertEqual(root.rewrittenBundleIdentifier, "app.rork.inspect")
        XCTAssertEqual(root.kind, .rootApp)
        XCTAssertFalse(root.isWatchBundle)
        XCTAssertNil(root.associatedBundleIdentifier)
        XCTAssertEqual(root.executableName, "Host")

        let extensionRequirement = try XCTUnwrap(report.provisioningRequirements.dropFirst().first)
        XCTAssertEqual(extensionRequirement.url, fixture.extensionURL)
        XCTAssertEqual(extensionRequirement.relativePath, "PlugIns/Share.appex")
        XCTAssertEqual(extensionRequirement.originalBundleIdentifier, "com.vendor.ShareExtension")
        XCTAssertEqual(extensionRequirement.rewrittenBundleIdentifier, "app.rork.inspect.ShareExtension")
        XCTAssertEqual(extensionRequirement.kind, .appExtension)
        XCTAssertFalse(extensionRequirement.isWatchBundle)
        XCTAssertEqual(extensionRequirement.associatedBundleIdentifier, "app.rork.inspect")
        XCTAssertEqual(extensionRequirement.executableName, "Share")

        let watchURL = try XCTUnwrap(fixture.watchURL)
        let watchRequirement = try XCTUnwrap(report.provisioningRequirements.dropFirst(2).first)
        XCTAssertEqual(watchRequirement.url, watchURL)
        XCTAssertEqual(watchRequirement.relativePath, "Watch/WatchApp.app")
        XCTAssertEqual(watchRequirement.originalBundleIdentifier, "com.original.host.watchkitapp")
        XCTAssertEqual(watchRequirement.rewrittenBundleIdentifier, "app.rork.inspect.watchkitapp")
        XCTAssertEqual(watchRequirement.kind, .watchApp)
        XCTAssertTrue(watchRequirement.isWatchBundle)
        XCTAssertNil(watchRequirement.associatedBundleIdentifier)
        XCTAssertEqual(watchRequirement.executableName, "WatchApp")

        XCTAssertEqual(try infoPlist(at: fixture.bundleURL)["CFBundleIdentifier"] as? String, "com.original.host")
        XCTAssertEqual(try infoPlist(at: fixture.extensionURL)["CFBundleIdentifier"] as? String, "com.vendor.ShareExtension")
        XCTAssertEqual(
            try infoPlist(at: watchURL)["CFBundleIdentifier"] as? String,
            "com.original.host.watchkitapp"
        )
    }

    /// Verifies Watch extensions keep their extension role and Watch marker separately.
    func testStandaloneInspectionClassifiesWatchAppExtensionsAsExtensions() throws {
        let fixture = try makeStandaloneBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }
        let watchExtensionURL = fixture.bundleURL.appendingPathComponent(
            "Watch/WatchExtension.appex",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: watchExtensionURL, withIntermediateDirectories: true)
        try writeInfoPlist(
            [
                "CFBundleIdentifier": "com.original.host.watchkitextension",
                "CFBundleExecutable": "WatchExtension",
                "NSExtension": [
                    "NSExtensionAttributes": [
                        "WKAppBundleIdentifier": "com.original.host.watchkitapp",
                    ],
                ],
            ],
            to: watchExtensionURL.appendingPathComponent("Info.plist")
        )

        let report = try RorkSigner.inspectStandaloneBundle(
            at: fixture.bundleURL,
            replacementBundleIdentifier: "app.rork.inspect"
        )
        let requirement = try XCTUnwrap(
            report.provisioningRequirements.first { $0.relativePath == "Watch/WatchExtension.appex" }
        )

        XCTAssertEqual(requirement.kind, .appExtension)
        XCTAssertTrue(requirement.isWatchBundle)
        XCTAssertEqual(requirement.originalBundleIdentifier, "com.original.host.watchkitextension")
        XCTAssertEqual(requirement.rewrittenBundleIdentifier, "app.rork.inspect.watchkitextension")
        XCTAssertEqual(requirement.associatedBundleIdentifier, "app.rork.inspect.watchkitapp")
    }

    func testStandaloneAdHocRewritesIdentifiersEmbedsProfilesAndExpandsEntitlements() throws {
        let fixture = try makeStandaloneBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
                "aps-environment": "development",
                "com.apple.developer.associated-domains": ["applinks:drop.example"],
            ]
        )
        let extensionProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
                "com.apple.developer.associated-application-identifier": "TEAMID1234.placeholder",
            ]
        )

        let report = try RorkSigner.signStandaloneBundleAdHoc(
            at: fixture.bundleURL,
            options: StandaloneBundleSigningOptions(
                bundleIdentifier: "app.rork.standalone",
                rootProvisioningProfile: rootProfile,
                provisioningProfilesByBundleIdentifier: [
                    "app.rork.standalone.ShareExtension": extensionProfile,
                ],
                appGroupIdentifiers: [" group.rork.shared ", "group.rork.shared", "group.rork.extra"]
            )
        )

        XCTAssertEqual(
            try report.embeddedProvisioningProfiles.map { try relativePath($0, under: fixture.bundleURL) },
            [
                "PlugIns/Share.appex/embedded.mobileprovision",
                "embedded.mobileprovision",
            ]
        )
        XCTAssertEqual(try Data(contentsOf: fixture.bundleURL.appendingPathComponent("embedded.mobileprovision")), rootProfile)
        XCTAssertEqual(
            try Data(contentsOf: fixture.extensionURL.appendingPathComponent("embedded.mobileprovision")),
            extensionProfile
        )

        let rootInfo = try infoPlist(at: fixture.bundleURL)
        let extensionInfo = try infoPlist(at: fixture.extensionURL)
        XCTAssertEqual(rootInfo["CFBundleIdentifier"] as? String, "app.rork.standalone")
        XCTAssertEqual(extensionInfo["CFBundleIdentifier"] as? String, "app.rork.standalone.ShareExtension")
        XCTAssertEqual(extensionInfo["WKCompanionAppBundleIdentifier"] as? String, "app.rork.standalone")
        let extensionDictionary = try XCTUnwrap(extensionInfo["NSExtension"] as? [String: Any])
        let attributes = try XCTUnwrap(extensionDictionary["NSExtensionAttributes"] as? [String: Any])
        XCTAssertEqual(attributes["WKAppBundleIdentifier"] as? String, "app.rork.standalone.watchkitapp")

        let hostEntitlements = try entitlementDictionary(
            inSignedMachOAt: fixture.bundleURL.appendingPathComponent("Host")
        )
        XCTAssertEqual(hostEntitlements["application-identifier"] as? String, "TEAMID1234.app.rork.standalone")
        XCTAssertEqual(hostEntitlements["com.apple.developer.team-identifier"] as? String, "TEAMID1234")
        XCTAssertEqual(hostEntitlements["aps-environment"] as? String, "development")
        XCTAssertNil(hostEntitlements["com.apple.developer.associated-domains"])
        XCTAssertEqual(
            hostEntitlements["keychain-access-groups"] as? [String],
            ["TEAMID1234.com.original.host", "TEAMID1234.legacy"]
        )
        XCTAssertEqual(
            hostEntitlements["com.apple.security.application-groups"] as? [String],
            ["group.rork.shared", "group.rork.extra"]
        )

        let extensionEntitlements = try entitlementDictionary(
            inSignedMachOAt: fixture.extensionURL.appendingPathComponent("Share")
        )
        XCTAssertEqual(
            extensionEntitlements["application-identifier"] as? String,
            "TEAMID1234.app.rork.standalone.ShareExtension"
        )
        XCTAssertEqual(
            extensionEntitlements["com.apple.developer.associated-application-identifier"] as? String,
            "TEAMID1234.app.rork.standalone"
        )

        let hostBlobs = try signatureBlobs(
            in: Data(contentsOf: fixture.bundleURL.appendingPathComponent("Host"))
        )
        let hostCodeDirectory = try XCTUnwrap(hostBlobs[0])
        XCTAssertNil(hostBlobs[0x1000])
        XCTAssertEqual(hostCodeDirectory[36], 32)
        XCTAssertEqual(hostCodeDirectory[37], 2)
    }

    /// Verifies signing uses the same associated bundle identifier source as inspection.
    func testStandaloneUsesExtensionAttributeAssociatedBundleIdentifierForEntitlements() throws {
        let fixture = try makeStandaloneBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }
        try writeInfoPlist(
            [
                "CFBundleIdentifier": "com.vendor.ShareExtension",
                "CFBundleExecutable": "Share",
                "NSExtension": [
                    "NSExtensionAttributes": [
                        "WKAppBundleIdentifier": "com.original.host.watchkitapp",
                    ],
                ],
            ],
            to: fixture.extensionURL.appendingPathComponent("Info.plist")
        )

        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
            ]
        )
        let extensionProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
                "com.apple.developer.associated-application-identifier": "TEAMID1234.placeholder",
            ]
        )

        try RorkSigner.signStandaloneBundleAdHoc(
            at: fixture.bundleURL,
            options: StandaloneBundleSigningOptions(
                bundleIdentifier: "app.rork.associated",
                rootProvisioningProfile: rootProfile,
                provisioningProfilesByBundleIdentifier: [
                    "app.rork.associated.ShareExtension": extensionProfile,
                ]
            )
        )

        let extensionInfo = try infoPlist(at: fixture.extensionURL)
        XCTAssertNil(extensionInfo["WKCompanionAppBundleIdentifier"])
        let extensionDictionary = try XCTUnwrap(extensionInfo["NSExtension"] as? [String: Any])
        let attributes = try XCTUnwrap(extensionDictionary["NSExtensionAttributes"] as? [String: Any])
        XCTAssertEqual(attributes["WKAppBundleIdentifier"] as? String, "app.rork.associated.watchkitapp")

        let extensionEntitlements = try entitlementDictionary(
            inSignedMachOAt: fixture.extensionURL.appendingPathComponent("Share")
        )
        XCTAssertEqual(
            extensionEntitlements["com.apple.developer.associated-application-identifier"] as? String,
            "TEAMID1234.app.rork.associated.watchkitapp"
        )
    }

    func testStandaloneRootEntitlementsOverrideProfileExpansion() throws {
        let fixture = try makeStandaloneBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
                "aps-environment": "development",
            ]
        )
        let explicitRootEntitlements = try entitlementsXML(
            [
                "application-identifier": "TEAMID1234.com.example.explicit",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": false,
                "com.apple.developer.associated-domains": ["applinks:explicit.example"],
            ]
        )

        try RorkSigner.signStandaloneBundleAdHoc(
            at: fixture.bundleURL,
            options: StandaloneBundleSigningOptions(
                bundleIdentifier: "com.example.override",
                rootProvisioningProfile: rootProfile,
                rootEntitlementsXML: explicitRootEntitlements
            )
        )

        let rootEntitlements = try entitlementDictionary(
            inSignedMachOAt: fixture.bundleURL.appendingPathComponent("Host")
        )
        XCTAssertEqual(rootEntitlements["application-identifier"] as? String, "TEAMID1234.com.example.explicit")
        XCTAssertEqual(rootEntitlements["com.apple.developer.team-identifier"] as? String, "TEAMID1234")
        XCTAssertEqual(rootEntitlements["get-task-allow"] as? Bool, false)
        XCTAssertEqual(
            rootEntitlements["com.apple.developer.associated-domains"] as? [String],
            ["applinks:explicit.example"]
        )
        XCTAssertNil(rootEntitlements["aps-environment"])
    }

    func testStandaloneRejectsProfilesFromDifferentTeamsBeforeRewritingBundleIdentifiers() throws {
        let fixture = try makeStandaloneBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        XCTAssertThrowsError(
            try RorkSigner.signStandaloneBundleAdHoc(
                at: fixture.bundleURL,
                options: StandaloneBundleSigningOptions(
                    bundleIdentifier: "app.rork.standalone",
                    rootProvisioningProfile: try provisioningProfilePlist(
                        teamIdentifier: "TEAMID1234",
                        entitlements: [
                            "application-identifier": "TEAMID1234.*",
                            "com.apple.developer.team-identifier": "TEAMID1234",
                        ]
                    ),
                    provisioningProfilesByBundleIdentifier: [
                        "app.rork.standalone.ShareExtension": try provisioningProfilePlist(
                            teamIdentifier: "OTHERTEAM",
                            entitlements: [
                                "application-identifier": "OTHERTEAM.*",
                                "com.apple.developer.team-identifier": "OTHERTEAM",
                            ]
                        ),
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidProvisioningProfile("Standalone provisioning profiles must belong to the same Apple team.")
            )
        }

        XCTAssertEqual(
            try infoPlist(at: fixture.bundleURL)["CFBundleIdentifier"] as? String,
            "com.original.host"
        )
    }

    func testStandaloneCanUseProfileEntitlementsWithoutEmbeddingProfiles() throws {
        let fixture = try makeStandaloneBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
            ]
        )

        let report = try RorkSigner.signStandaloneBundleAdHoc(
            at: fixture.bundleURL,
            options: StandaloneBundleSigningOptions(
                bundleIdentifier: "app.rork.no-profile",
                rootProvisioningProfile: rootProfile,
                embedProvisioningProfiles: false
            )
        )

        XCTAssertEqual(report.embeddedProvisioningProfiles, [])
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: fixture.bundleURL.appendingPathComponent("embedded.mobileprovision").path
            )
        )

        let hostEntitlements = try entitlementDictionary(
            inSignedMachOAt: fixture.bundleURL.appendingPathComponent("Host")
        )
        XCTAssertEqual(hostEntitlements["application-identifier"] as? String, "TEAMID1234.app.rork.no-profile")
    }

    func testStandaloneRejectsProfileThatDoesNotAuthorizeRewrittenIdentifier() throws {
        let fixture = try makeStandaloneBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        XCTAssertThrowsError(
            try RorkSigner.signStandaloneBundleAdHoc(
                at: fixture.bundleURL,
                options: StandaloneBundleSigningOptions(
                    bundleIdentifier: "app.rork.standalone",
                    rootProvisioningProfile: try provisioningProfilePlist(
                        teamIdentifier: "TEAMID1234",
                        entitlements: [
                            "application-identifier": "TEAMID1234.com.other.app",
                            "com.apple.developer.team-identifier": "TEAMID1234",
                        ]
                    )
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidProvisioningProfile(
                    "Provisioning profile does not authorize bundle identifier app.rork.standalone."
                )
            )
        }
    }

    func testStandaloneUsesWatchProvisioningProfileForEmbeddedWatchApps() throws {
        let fixture = try makeStandaloneBundleFixture(includeWatchApp: true)
        let watchURL = try XCTUnwrap(fixture.watchURL)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
            ]
        )
        let watchProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
                "com.apple.security.application-groups": ["group.watch.profile"],
            ]
        )

        try RorkSigner.signStandaloneBundleAdHoc(
            at: fixture.bundleURL,
            options: StandaloneBundleSigningOptions(
                bundleIdentifier: "app.rork.standalone",
                rootProvisioningProfile: rootProfile,
                watchProvisioningProfile: watchProfile,
                appGroupIdentifiers: ["group.rork.shared"]
            )
        )

        XCTAssertEqual(
            try Data(contentsOf: watchURL.appendingPathComponent("embedded.mobileprovision")),
            watchProfile
        )
        let watchInfo = try infoPlist(at: watchURL)
        XCTAssertEqual(watchInfo["CFBundleIdentifier"] as? String, "app.rork.standalone.watchkitapp")

        let watchEntitlements = try entitlementDictionary(
            inSignedMachOAt: watchURL.appendingPathComponent("WatchApp")
        )
        XCTAssertEqual(
            watchEntitlements["application-identifier"] as? String,
            "TEAMID1234.app.rork.standalone.watchkitapp"
        )
        XCTAssertNil(watchEntitlements["com.apple.security.application-groups"])
    }

    func testStandaloneOnlyRewritesNestedBundleIdentifierRootPrefix() throws {
        let fixture = try makeStandaloneBundleFixture(includeWatchApp: true)
        let watchURL = try XCTUnwrap(fixture.watchURL)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }
        try writeInfoPlist(
            [
                "CFBundleIdentifier": "com.vendor.com.original.host.watchkitapp",
                "CFBundleExecutable": "WatchApp",
                "CFBundleSupportedPlatforms": ["WatchOS"],
                "WKApplication": true,
            ],
            to: watchURL.appendingPathComponent("Info.plist")
        )

        let wildcardProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
            ]
        )

        try RorkSigner.signStandaloneBundleAdHoc(
            at: fixture.bundleURL,
            options: StandaloneBundleSigningOptions(
                bundleIdentifier: "app.rork.standalone",
                rootProvisioningProfile: wildcardProfile,
                watchProvisioningProfile: wildcardProfile
            )
        )

        let watchInfo = try infoPlist(at: watchURL)
        XCTAssertEqual(watchInfo["CFBundleIdentifier"] as? String, "com.vendor.com.original.host.watchkitapp")
    }

    func testStandaloneAppliesRootMetadataOptionsBeforeSigning() throws {
        let fixture = try makeStandaloneBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
            ]
        )

        try RorkSigner.signStandaloneBundleAdHoc(
            at: fixture.bundleURL,
            options: StandaloneBundleSigningOptions(
                bundleIdentifier: "app.rork.metadata",
                rootProvisioningProfile: rootProfile,
                displayName: "Signed Fixture",
                bundleVersion: "2.3.4",
                minimumOSVersion: "15.0",
                enableDocuments: true,
                removeUISupportedDevices: true
            )
        )

        let rootInfo = try infoPlist(at: fixture.bundleURL)
        XCTAssertEqual(rootInfo["CFBundleIdentifier"] as? String, "app.rork.metadata")
        XCTAssertEqual(rootInfo["CFBundleName"] as? String, "Signed Fixture")
        XCTAssertEqual(rootInfo["CFBundleDisplayName"] as? String, "Signed Fixture")
        XCTAssertEqual(rootInfo["CFBundleVersion"] as? String, "2.3.4")
        XCTAssertEqual(rootInfo["CFBundleShortVersionString"] as? String, "2.3.4")
        XCTAssertEqual(rootInfo["MinimumOSVersion"] as? String, "15.0")
        XCTAssertEqual(rootInfo["UISupportsDocumentBrowser"] as? Bool, true)
        XCTAssertEqual(rootInfo["UIFileSharingEnabled"] as? Bool, true)
        XCTAssertNil(rootInfo["UISupportedDevices"])

        let localizedInfo = try plistDictionary(
            at: fixture.bundleURL.appendingPathComponent("en.lproj/InfoPlist.strings")
        )
        XCTAssertEqual(localizedInfo["CFBundleName"] as? String, "Signed Fixture")
        XCTAssertEqual(localizedInfo["CFBundleDisplayName"] as? String, "Signed Fixture")
    }

    func testStandaloneCanRemoveExtensionsAndWatchAppsBeforeSigning() throws {
        let fixture = try makeStandaloneBundleFixture(includeWatchApp: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
            ]
        )

        let report = try RorkSigner.signStandaloneBundleAdHoc(
            at: fixture.bundleURL,
            options: StandaloneBundleSigningOptions(
                bundleIdentifier: "app.rork.pruned",
                rootProvisioningProfile: rootProfile,
                removeExtensions: true,
                removeWatchApps: true
            )
        )

        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.extensionURL.path))
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: fixture.bundleURL.appendingPathComponent("Watch").path
            )
        )
        XCTAssertEqual(
            try report.signedCode.map { try relativePath($0, under: fixture.bundleURL) },
            ["Host"]
        )
        XCTAssertEqual(
            try report.embeddedProvisioningProfiles.map { try relativePath($0, under: fixture.bundleURL) },
            ["embedded.mobileprovision"]
        )
    }

    func testStandaloneCredentialSigningBuildsIdentityFromRootProfile() throws {
        let openssl = try OpenSSLFixture()
        defer {
            openssl.remove()
        }
        let fixture = try makeStandaloneBundleFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }
        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            certificatesDER: [openssl.identity.certificateDER],
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
            ]
        )

        let report = try RorkSigner.signStandaloneBundleWithCredential(
            at: fixture.bundleURL,
            provisioningProfileData: rootProfile,
            credentialData: Data(openssl.privateKeyPEM.utf8),
            bundleIdentifier: "app.rork.standalone"
        )

        XCTAssertEqual(
            try report.embeddedProvisioningProfiles.map { try relativePath($0, under: fixture.bundleURL) },
            ["PlugIns/Share.appex/embedded.mobileprovision", "embedded.mobileprovision"]
        )
        XCTAssertEqual(
            try Data(contentsOf: fixture.bundleURL.appendingPathComponent("embedded.mobileprovision")),
            rootProfile
        )

        let hostExecutable = try Data(contentsOf: fixture.bundleURL.appendingPathComponent("Host"))
        let hostBlobs = try signatureBlobs(in: hostExecutable)
        let codeDirectory = try XCTUnwrap(hostBlobs[0])
        let cmsBlob = try XCTUnwrap(hostBlobs[0x10000])
        let cmsLength = Int(cmsBlob.readUInt32BE(at: 4))
        try openssl.verifyDetachedCMS(cmsBlob.subdata(in: 8..<cmsLength), content: codeDirectory)
    }
}

private struct StandaloneBundleFixture {
    let bundleURL: URL
    let extensionURL: URL
    let watchURL: URL?
}

private func makeStandaloneBundleFixture(includeWatchApp: Bool = false) throws -> StandaloneBundleFixture {
    let rootURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let bundleURL = rootURL.appendingPathComponent("Host.app", isDirectory: true)
    let extensionURL = bundleURL.appendingPathComponent("PlugIns/Share.appex", isDirectory: true)
    try FileManager.default.createDirectory(at: extensionURL, withIntermediateDirectories: true)

    try writeInfoPlist(
        [
            "CFBundleIdentifier": "com.original.host",
            "CFBundleExecutable": "Host",
            "CFBundleName": "OriginalHost",
            "CFBundleDisplayName": "Original Host",
            "CFBundleVersion": "1",
            "CFBundleShortVersionString": "1.0",
            "MinimumOSVersion": "14.0",
            "UISupportedDevices": ["iPhone15,2"],
        ],
        to: bundleURL.appendingPathComponent("Info.plist")
    )
    try FileManager.default.createDirectory(
        at: bundleURL.appendingPathComponent("en.lproj", isDirectory: true),
        withIntermediateDirectories: true
    )
    try writeInfoPlist(
        [
            "CFBundleName": "LocalizedOriginalHost",
            "CFBundleDisplayName": "Localized Original Host",
        ],
        to: bundleURL.appendingPathComponent("en.lproj/InfoPlist.strings")
    )
    try writeInfoPlist(
        [
            "CFBundleIdentifier": "com.vendor.ShareExtension",
            "CFBundleExecutable": "Share",
            "WKCompanionAppBundleIdentifier": "com.original.host",
            "NSExtension": [
                "NSExtensionAttributes": [
                    "WKAppBundleIdentifier": "com.original.host.watchkitapp",
                ],
            ],
        ],
        to: extensionURL.appendingPathComponent("Info.plist")
    )

    let host = try RorkSigner.signMachOAdHoc(
        Fixtures.machO64WithCodeSignature(),
        bundleIdentifier: "com.original.host",
        entitlementsXML: entitlementsXML(
            [
                "application-identifier": "OLDTEAM.com.original.host",
                "com.apple.developer.team-identifier": "OLDTEAM",
                "aps-environment": "development",
                "keychain-access-groups": [
                    "OLDTEAM.com.original.host",
                    "legacy",
                ],
            ]
        )
    )
    let share = try RorkSigner.signMachOAdHoc(
        Fixtures.machO64WithCodeSignature(),
        bundleIdentifier: "com.vendor.ShareExtension",
        entitlementsXML: entitlementsXML(
            [
                "application-identifier": "OLDTEAM.com.vendor.ShareExtension",
                "com.apple.developer.team-identifier": "OLDTEAM",
                "com.apple.developer.associated-application-identifier": "OLDTEAM.com.original.host",
            ]
        )
    )
    try host.write(to: bundleURL.appendingPathComponent("Host"))
    try share.write(to: extensionURL.appendingPathComponent("Share"))

    let watchURL = try includeWatchApp ? makeWatchAppFixture(in: bundleURL) : nil
    return StandaloneBundleFixture(bundleURL: bundleURL, extensionURL: extensionURL, watchURL: watchURL)
}

private func makeWatchAppFixture(in bundleURL: URL) throws -> URL {
    let watchURL = bundleURL.appendingPathComponent("Watch/WatchApp.app", isDirectory: true)
    try FileManager.default.createDirectory(at: watchURL, withIntermediateDirectories: true)
    try writeInfoPlist(
        [
            "CFBundleIdentifier": "com.original.host.watchkitapp",
            "CFBundleExecutable": "WatchApp",
            "CFBundleSupportedPlatforms": ["WatchOS"],
            "WKApplication": true,
        ],
        to: watchURL.appendingPathComponent("Info.plist")
    )
    let executable = try RorkSigner.signMachOAdHoc(
        Fixtures.machO64WithCodeSignature(),
        bundleIdentifier: "com.original.host.watchkitapp",
        entitlementsXML: entitlementsXML(
            [
                "application-identifier": "OLDTEAM.com.original.host.watchkitapp",
                "com.apple.developer.team-identifier": "OLDTEAM",
            ]
        )
    )
    try executable.write(to: watchURL.appendingPathComponent("WatchApp"))
    return watchURL
}

private func provisioningProfilePlist(
    teamIdentifier: String,
    certificatesDER: [Data] = [Data([0x01, 0x02, 0x03])],
    entitlements: [String: Any]
) throws -> Data {
    let plist: [String: Any] = [
        "TeamIdentifier": [teamIdentifier],
        "ExpirationDate": Date(timeIntervalSince1970: 1_900_000_000),
        "DeveloperCertificates": certificatesDER,
        "Entitlements": entitlements,
    ]
    return try PropertyListSerialization.data(
        fromPropertyList: plist,
        format: .xml,
        options: 0
    )
}

private func entitlementsXML(_ dictionary: [String: Any]) throws -> String {
    let data = try PropertyListSerialization.data(
        fromPropertyList: dictionary,
        format: .xml,
        options: 0
    )
    return String(decoding: data, as: UTF8.self)
}

private func writeInfoPlist(_ dictionary: [String: Any], to url: URL) throws {
    let data = try PropertyListSerialization.data(
        fromPropertyList: dictionary,
        format: .xml,
        options: 0
    )
    try data.write(to: url)
}

private func infoPlist(at bundleURL: URL) throws -> [String: Any] {
    try plistDictionary(at: bundleURL.appendingPathComponent("Info.plist"))
}

private func plistDictionary(at url: URL) throws -> [String: Any] {
    let data = try Data(contentsOf: url)
    let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    return try XCTUnwrap(plist as? [String: Any])
}

private func entitlementDictionary(inSignedMachOAt url: URL) throws -> [String: Any] {
    let signed = try Data(contentsOf: url)
    let blobs = try signatureBlobs(in: signed)
    let entitlements = try XCTUnwrap(blobs[5])
    let length = Int(entitlements.readUInt32BE(at: 4))
    let payload = entitlements.subdata(in: 8..<length)
    let plist = try PropertyListSerialization.propertyList(from: payload, options: [], format: nil)
    return try XCTUnwrap(plist as? [String: Any])
}

private func relativePath(_ url: URL, under rootURL: URL) throws -> String {
    let rootPath = rootURL.standardizedFileURL.path
    let path = url.standardizedFileURL.path
    guard path.hasPrefix(rootPath + "/") else {
        throw RorkSignError.invalidBundle("Path escaped root: \(path).")
    }
    return String(path.dropFirst(rootPath.count + 1))
}
