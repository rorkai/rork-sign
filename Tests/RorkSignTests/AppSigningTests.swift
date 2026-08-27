import Foundation
import RorkSign
import XCTest

final class AppSigningTests: XCTestCase {
    /// Verifies app inspection previews rewritten identifiers without touching Info.plists.
    func testAppSigningInspectionReportsRewrittenProvisioningRequirementsWithoutMutatingBundle() throws {
        let fixture = try makeAppSigningFixture(includeWatchApp: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        let report = try RorkSigner.inspectApp(
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
    func testAppSigningInspectionClassifiesWatchAppExtensionsAsExtensions() throws {
        let fixture = try makeAppSigningFixture()
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

        let report = try RorkSigner.inspectApp(
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

    func testAppSigningAdHocRewritesIdentifiersEmbedsProfilesAndExpandsEntitlements() throws {
        let fixture = try makeAppSigningFixture()
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

        let report = try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.signed",
                rootProvisioningProfile: rootProfile,
                provisioningProfilesByBundleIdentifier: [
                    "app.rork.signed.ShareExtension": extensionProfile,
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
        XCTAssertEqual(rootInfo["CFBundleIdentifier"] as? String, "app.rork.signed")
        let urlTypes = try XCTUnwrap(rootInfo["CFBundleURLTypes"] as? [[String: Any]])
        let urlSchemes = urlTypes.flatMap {
            $0["CFBundleURLSchemes"] as? [String] ?? []
        }
        XCTAssertEqual(
            urlSchemes,
            [
                "shared-callback",
                "app.rork.signed",
                "callback-app.rork.signed",
                "prefixcom.original.host",
                "callback-com.original.host.extra",
            ]
        )
        XCTAssertEqual(extensionInfo["CFBundleIdentifier"] as? String, "app.rork.signed.ShareExtension")
        XCTAssertEqual(extensionInfo["WKCompanionAppBundleIdentifier"] as? String, "app.rork.signed")
        let extensionDictionary = try XCTUnwrap(extensionInfo["NSExtension"] as? [String: Any])
        let attributes = try XCTUnwrap(extensionDictionary["NSExtensionAttributes"] as? [String: Any])
        XCTAssertEqual(attributes["WKAppBundleIdentifier"] as? String, "app.rork.signed.watchkitapp")

        let hostEntitlements = try entitlementDictionary(
            inSignedMachOAt: fixture.bundleURL.appendingPathComponent("Host")
        )
        XCTAssertEqual(hostEntitlements["application-identifier"] as? String, "TEAMID1234.app.rork.signed")
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
            "TEAMID1234.app.rork.signed.ShareExtension"
        )
        XCTAssertEqual(
            extensionEntitlements["com.apple.developer.associated-application-identifier"] as? String,
            "TEAMID1234.app.rork.signed"
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
    func testAppSigningUsesExtensionAttributeAssociatedBundleIdentifierForEntitlements() throws {
        let fixture = try makeAppSigningFixture()
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
        try Fixtures.machO64WithCodeSignature().write(to: fixture.extensionURL.appendingPathComponent("Share"))

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

        try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
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

    func testAppSigningUsesBundleEntitlementsResourceWhenExecutableHasNoEntitlements() throws {
        let fixture = try makeAppSigningFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }
        let entitlementsResourceName = "FixtureEntitlements.plist"
        try Fixtures.machO64WithCodeSignature().write(to: fixture.bundleURL.appendingPathComponent("Host"))
        try entitlementsXML(
            [
                "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
                "com.apple.developer.networking.vpn.api": ["allow-vpn"],
            ]
        )
        .write(
            to: fixture.bundleURL.appendingPathComponent(entitlementsResourceName),
            atomically: true,
            encoding: .utf8
        )
        try Fixtures.machO64WithCodeSignature().write(to: fixture.extensionURL.appendingPathComponent("Share"))
        try entitlementsXML(
            [
                "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
            ]
        )
        .write(
            to: fixture.extensionURL.appendingPathComponent(entitlementsResourceName),
            atomically: true,
            encoding: .utf8
        )

        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
                "com.apple.developer.networking.networkextension": [
                    "app-proxy-provider",
                    "packet-tunnel-provider",
                ],
                "com.apple.developer.networking.vpn.api": ["allow-vpn"],
            ]
        )
        let extensionProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
                "com.apple.developer.networking.networkextension": [
                    "app-proxy-provider",
                    "packet-tunnel-provider",
                ],
            ]
        )

        try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.tunnel",
                rootProvisioningProfile: rootProfile,
                provisioningProfilesByBundleIdentifier: [
                    "app.rork.tunnel.ShareExtension": extensionProfile,
                ],
                entitlementsResourceName: entitlementsResourceName
            )
        )

        let rootEntitlements = try entitlementDictionary(
            inSignedMachOAt: fixture.bundleURL.appendingPathComponent("Host")
        )
        XCTAssertEqual(
            rootEntitlements["com.apple.developer.networking.networkextension"] as? [String],
            ["packet-tunnel-provider"]
        )
        XCTAssertEqual(
            rootEntitlements["com.apple.developer.networking.vpn.api"] as? [String],
            ["allow-vpn"]
        )

        let extensionEntitlements = try entitlementDictionary(
            inSignedMachOAt: fixture.extensionURL.appendingPathComponent("Share")
        )
        XCTAssertEqual(
            extensionEntitlements["com.apple.developer.networking.networkextension"] as? [String],
            ["packet-tunnel-provider"]
        )
    }

    func testAppSigningRootEntitlementsOverrideProfileExpansion() throws {
        let fixture = try makeAppSigningFixture()
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

        try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
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

    func testAppSigningRejectsProfilesFromDifferentTeamsBeforeRewritingBundleIdentifiers() throws {
        let fixture = try makeAppSigningFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        XCTAssertThrowsError(
            try RorkSigner.signBundle(
                at: fixture.bundleURL,
                options: AppSigningOptions(
                    bundleIdentifier: "app.rork.signed",
                    rootProvisioningProfile: try provisioningProfilePlist(
                        teamIdentifier: "TEAMID1234",
                        entitlements: [
                            "application-identifier": "TEAMID1234.*",
                            "com.apple.developer.team-identifier": "TEAMID1234",
                        ]
                    ),
                    provisioningProfilesByBundleIdentifier: [
                        "app.rork.signed.ShareExtension": try provisioningProfilePlist(
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
                .invalidProvisioningProfile("App signing provisioning profiles must belong to the same Apple team.")
            )
        }

        XCTAssertEqual(
            try infoPlist(at: fixture.bundleURL)["CFBundleIdentifier"] as? String,
            "com.original.host"
        )
    }

    func testAppSigningCanUseProfileEntitlementsWithoutEmbeddingProfiles() throws {
        let fixture = try makeAppSigningFixture()
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

        let report = try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
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

    func testAppSigningRejectsProfileThatDoesNotAuthorizeRewrittenIdentifier() throws {
        let fixture = try makeAppSigningFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        XCTAssertThrowsError(
            try RorkSigner.signBundle(
                at: fixture.bundleURL,
                options: AppSigningOptions(
                    bundleIdentifier: "app.rork.signed",
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
                    "Provisioning profile does not authorize bundle identifier app.rork.signed."
                )
            )
        }
    }

    func testAppSigningUsesWatchProvisioningProfileForEmbeddedWatchApps() throws {
        let fixture = try makeAppSigningFixture(includeWatchApp: true)
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

        try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.signed",
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
        XCTAssertEqual(watchInfo["CFBundleIdentifier"] as? String, "app.rork.signed.watchkitapp")

        let watchEntitlements = try entitlementDictionary(
            inSignedMachOAt: watchURL.appendingPathComponent("WatchApp")
        )
        XCTAssertEqual(
            watchEntitlements["application-identifier"] as? String,
            "TEAMID1234.app.rork.signed.watchkitapp"
        )
        XCTAssertNil(watchEntitlements["com.apple.security.application-groups"])
    }

    func testAppSigningOnlyRewritesNestedBundleIdentifierRootPrefix() throws {
        let fixture = try makeAppSigningFixture(includeWatchApp: true)
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

        try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.signed",
                rootProvisioningProfile: wildcardProfile,
                watchProvisioningProfile: wildcardProfile
            )
        )

        let watchInfo = try infoPlist(at: watchURL)
        XCTAssertEqual(watchInfo["CFBundleIdentifier"] as? String, "com.vendor.com.original.host.watchkitapp")
    }

    /// Protects the root-only metadata contract from being lost while nested
    /// bundles and resources are rewritten during signing.
    func testAppSigningAppliesRootMetadataOptionsBeforeSigning() throws {
        let fixture = try makeAppSigningFixture()
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

        try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
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

    /// Protects the ordering contract that caller files are replaced before
    /// CodeResources hashes the final bundle contents.
    func testAppSigningWritesAdditionalBundleFilesBeforeSealingResources() throws {
        let fixture = try makeAppSigningFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }
        let certificateURL = fixture.bundleURL.appendingPathComponent("dev-signing-cert.p12")
        try Data("stale certificate".utf8).write(to: certificateURL)

        try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.additional-files",
                additionalBundleFiles: [
                    "dev-signing-cert.p12": Data("current certificate".utf8),
                    "Signing/credential-password.txt": Data("secret".utf8),
                ]
            )
        )

        XCTAssertEqual(
            try Data(contentsOf: certificateURL),
            Data("current certificate".utf8)
        )
        XCTAssertEqual(
            try Data(
                contentsOf: fixture.bundleURL
                    .appendingPathComponent("Signing/credential-password.txt")
            ),
            Data("secret".utf8)
        )

        let codeResources = try parseCodeResources(
            Data(
                contentsOf: fixture.bundleURL
                    .appendingPathComponent("_CodeSignature/CodeResources")
            )
        )
        let sealedFiles = try XCTUnwrap(codeResources["files2"] as? [String: Any])
        XCTAssertNotNil(sealedFiles["dev-signing-cert.p12"])
        XCTAssertNotNil(sealedFiles["Signing/credential-password.txt"])
    }

    /// Ensures invalid bundle identifiers fail before any caller file can
    /// mutate an otherwise valid app bundle.
    func testAppSigningRejectsInvalidBundleIdentifierBeforeWritingAdditionalFiles()
        throws
    {
        let fixture = try makeAppSigningFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(
                at: fixture.bundleURL.deletingLastPathComponent()
            )
        }
        let additionalFileURL = fixture.bundleURL.appendingPathComponent(
            "credential.txt"
        )

        XCTAssertThrowsError(
            try RorkSigner.signBundle(
                at: fixture.bundleURL,
                options: AppSigningOptions(
                    bundleIdentifier: "invalid/identifier",
                    additionalBundleFiles: [
                        "credential.txt": Data("secret".utf8),
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidBundle(
                    "Bundle identifier contains a path separator: invalid/identifier."
                )
            )
        }
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: additionalFileURL.path)
        )
    }

    /// Caller-provided resources must not replace files whose contents and
    /// lifecycle are owned by the signing pipeline.
    func testAppSigningRejectsSignerOwnedAdditionalBundleFilesBeforeMutation()
        throws
    {
        let reservedPaths = [
            "Info.plist",
            "info.plist",
            "Host",
            "_CodeSignature/CodeResources",
            "_codesignature/CodeResources",
            "embedded.mobileprovision",
            "EMBEDDED.MOBILEPROVISION",
        ]

        for relativePath in reservedPaths {
            let fixture = try makeAppSigningFixture()
            let fixtureRootURL = fixture.bundleURL.deletingLastPathComponent()
            defer {
                try? FileManager.default.removeItem(at: fixtureRootURL)
            }
            let infoURL = fixture.bundleURL.appendingPathComponent("Info.plist")
            let originalInfo = try Data(contentsOf: infoURL)
            let executableURL = fixture.bundleURL.appendingPathComponent("Host")
            let originalExecutable = try Data(contentsOf: executableURL)

            XCTAssertThrowsError(
                try RorkSigner.signBundle(
                    at: fixture.bundleURL,
                    options: AppSigningOptions(
                        bundleIdentifier: "app.rork.additional-files",
                        additionalBundleFiles: [
                            relativePath: Data("replacement".utf8),
                        ]
                    )
                ),
                "Expected \(relativePath) to be reserved."
            ) { error in
                XCTAssertEqual(
                    error as? RorkSignError,
                    .invalidBundle(
                        "Additional bundle file path is owned by the signing process: \(relativePath)."
                    )
                )
            }

            XCTAssertEqual(try Data(contentsOf: infoURL), originalInfo)
            XCTAssertEqual(
                try Data(contentsOf: executableURL),
                originalExecutable
            )
            XCTAssertFalse(
                FileManager.default.fileExists(
                    atPath: fixture.bundleURL
                        .appendingPathComponent("_CodeSignature/CodeResources")
                        .path
                )
            )
            XCTAssertFalse(
                FileManager.default.fileExists(
                    atPath: fixture.bundleURL
                        .appendingPathComponent("embedded.mobileprovision")
                        .path
                )
            )
        }
    }

    /// Verifies one escaping path prevents every requested write and leaves
    /// bundle metadata untouched.
    func testAppSigningRejectsAdditionalBundleFileOutsideRootBeforeWritingFiles() throws {
        let fixture = try makeAppSigningFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }
        let validFileURL = fixture.bundleURL.appendingPathComponent("valid.txt")

        XCTAssertThrowsError(
            try RorkSigner.signBundle(
                at: fixture.bundleURL,
                options: AppSigningOptions(
                    bundleIdentifier: "app.rork.additional-files",
                    additionalBundleFiles: [
                        "../escaped.txt": Data("escaped".utf8),
                        "valid.txt": Data("valid".utf8),
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidBundle(
                    "Additional bundle file path must remain inside the root app bundle: ../escaped.txt."
                )
            )
        }

        XCTAssertFalse(FileManager.default.fileExists(atPath: validFileURL.path))
        XCTAssertEqual(
            try infoPlist(at: fixture.bundleURL)["CFBundleIdentifier"] as? String,
            "com.original.host"
        )
    }

    /// Verifies lexical path validation is reinforced by rejecting existing
    /// symlinks that could redirect a write outside the app bundle.
    func testAppSigningRejectsAdditionalBundleFileThroughSymbolicLinkBeforeWritingFiles() throws {
        let fixture = try makeAppSigningFixture()
        let fixtureRootURL = fixture.bundleURL.deletingLastPathComponent()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixtureRootURL)
        }
        let linkURL = fixture.bundleURL.appendingPathComponent("Signing")
        let escapedFileURL = fixtureRootURL.appendingPathComponent(
            "escaped.txt"
        )
        let validFileURL = fixture.bundleURL.appendingPathComponent("valid.txt")
        try FileManager.default.createSymbolicLink(
            atPath: linkURL.path,
            withDestinationPath: ".."
        )

        XCTAssertThrowsError(
            try RorkSigner.signBundle(
                at: fixture.bundleURL,
                options: AppSigningOptions(
                    bundleIdentifier: "app.rork.additional-files",
                    additionalBundleFiles: [
                        "Signing/escaped.txt": Data("escaped".utf8),
                        "valid.txt": Data("valid".utf8),
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidBundle(
                    "Additional bundle file path must remain inside the root app bundle: Signing/escaped.txt."
                )
            )
        }

        XCTAssertFalse(
            FileManager.default.fileExists(atPath: escapedFileURL.path)
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: validFileURL.path))
        XCTAssertEqual(
            try infoPlist(at: fixture.bundleURL)["CFBundleIdentifier"] as? String,
            "com.original.host"
        )
    }

    /// Ensures parent-file and child-file requests are preflighted as one set so
    /// dictionary iteration order cannot leave a partial update.
    func testAppSigningRejectsConflictingAdditionalBundleFilePathsBeforeWritingFiles() throws {
        let fixture = try makeAppSigningFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(
                at: fixture.bundleURL.deletingLastPathComponent()
            )
        }
        let signingURL = fixture.bundleURL.appendingPathComponent("Signing")
        let validFileURL = fixture.bundleURL.appendingPathComponent("valid.txt")

        XCTAssertThrowsError(
            try RorkSigner.signBundle(
                at: fixture.bundleURL,
                options: AppSigningOptions(
                    bundleIdentifier: "app.rork.additional-files",
                    additionalBundleFiles: [
                        "Signing": Data("file".utf8),
                        "Signing/credential.txt": Data("credential".utf8),
                        "valid.txt": Data("valid".utf8),
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidBundle(
                    "Additional bundle file path must remain inside the root app bundle: Signing/credential.txt."
                )
            )
        }

        XCTAssertFalse(FileManager.default.fileExists(atPath: signingURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: validFileURL.path))
        XCTAssertEqual(
            try infoPlist(at: fixture.bundleURL)["CFBundleIdentifier"] as? String,
            "com.original.host"
        )
    }

    /// Case-only path differences must be preflighted consistently with common
    /// case-insensitive destination filesystems.
    func testAppSigningRejectsCaseInsensitiveAdditionalBundleFileConflictsBeforeWritingFiles()
        throws
    {
        let fixture = try makeAppSigningFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(
                at: fixture.bundleURL.deletingLastPathComponent()
            )
        }
        let signingURL = fixture.bundleURL.appendingPathComponent("Signing")
        let validFileURL = fixture.bundleURL.appendingPathComponent("valid.txt")

        XCTAssertThrowsError(
            try RorkSigner.signBundle(
                at: fixture.bundleURL,
                options: AppSigningOptions(
                    bundleIdentifier: "app.rork.additional-files",
                    additionalBundleFiles: [
                        "Signing": Data("file".utf8),
                        "signing/credential.txt": Data("credential".utf8),
                        "valid.txt": Data("valid".utf8),
                    ]
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? RorkSignError,
                .invalidBundle(
                    "Additional bundle file path must remain inside the root app bundle: signing/credential.txt."
                )
            )
        }

        XCTAssertFalse(FileManager.default.fileExists(atPath: signingURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: validFileURL.path))
        XCTAssertEqual(
            try infoPlist(at: fixture.bundleURL)["CFBundleIdentifier"] as? String,
            "com.original.host"
        )
    }

    func testAppSigningCanRemoveExtensionsAndWatchAppsBeforeSigning() throws {
        let fixture = try makeAppSigningFixture(includeWatchApp: true)
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

        let report = try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
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

    func testAppSigningRemovesOnlyNamedExtensions() throws {
        let fixture = try makeAppSigningFixture()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fixture.bundleURL.deletingLastPathComponent())
        }

        // A second extension that the caller wants dropped because the signing
        // identity cannot provision it. It is otherwise a normal nested bundle,
        // so if pruning failed the signer would discover and sign it.
        let removableURL = fixture.bundleURL.appendingPathComponent("PlugIns/Removable.appex", isDirectory: true)
        try FileManager.default.createDirectory(at: removableURL, withIntermediateDirectories: true)
        try writeInfoPlist(
            [
                "CFBundleIdentifier": "com.vendor.RemovableExtension",
                "CFBundleExecutable": "Removable",
            ],
            to: removableURL.appendingPathComponent("Info.plist")
        )
        let removable = try RorkSigner.signMachOAdHoc(
            Fixtures.machO64WithCodeSignature(),
            bundleIdentifier: "com.vendor.RemovableExtension",
            entitlementsXML: entitlementsXML(
                [
                    "application-identifier": "OLDTEAM.com.vendor.RemovableExtension",
                    "com.apple.developer.team-identifier": "OLDTEAM",
                    "com.apple.developer.associated-application-identifier": "OLDTEAM.com.original.host",
                ]
            )
        )
        try removable.write(to: removableURL.appendingPathComponent("Removable"))

        let rootProfile = try provisioningProfilePlist(
            teamIdentifier: "TEAMID1234",
            entitlements: [
                "application-identifier": "TEAMID1234.*",
                "com.apple.developer.team-identifier": "TEAMID1234",
                "get-task-allow": true,
            ]
        )

        let report = try RorkSigner.signBundle(
            at: fixture.bundleURL,
            options: AppSigningOptions(
                bundleIdentifier: "app.rork.kept",
                rootProvisioningProfile: rootProfile,
                extensionsToRemove: ["Removable.appex"]
            )
        )

        XCTAssertFalse(FileManager.default.fileExists(atPath: removableURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: fixture.extensionURL.path))
        let signedPaths = try report.signedCode.map { try relativePath($0, under: fixture.bundleURL) }
        XCTAssertTrue(signedPaths.contains("Host"))
        XCTAssertTrue(signedPaths.contains("PlugIns/Share.appex/Share"))
        XCTAssertFalse(signedPaths.contains { $0.contains("Removable") })
    }

    func testAppSigningRejectsExtensionsToRemoveWithPathTraversal() throws {
        let fixture = try makeAppSigningFixture()
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

        XCTAssertThrowsError(
            try RorkSigner.signBundle(
                at: fixture.bundleURL,
                options: AppSigningOptions(
                    bundleIdentifier: "app.rork.invalid",
                    rootProvisioningProfile: rootProfile,
                    extensionsToRemove: ["../Evil.appex"]
                )
            )
        ) { error in
            guard case RorkSignError.invalidBundle = error else {
                return XCTFail("Expected invalidBundle, got \(error).")
            }
        }
    }

    func testAppSigningCredentialSigningBuildsIdentityFromRootProfile() throws {
        let openssl = try OpenSSLFixture()
        defer {
            openssl.remove()
        }
        let fixture = try makeAppSigningFixture()
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

        let report = try RorkSigner.signBundle(
            at: fixture.bundleURL,
            provisioningProfileData: rootProfile,
            credentialData: Data(openssl.privateKeyPEM.utf8),
            options: AppSigningOptions(bundleIdentifier: "app.rork.signed")
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

private struct AppSigningFixture {
    let bundleURL: URL
    let extensionURL: URL
    let watchURL: URL?
}

private func makeAppSigningFixture(includeWatchApp: Bool = false) throws -> AppSigningFixture {
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
            "CFBundleURLTypes": [
                [
                    "CFBundleURLName": "callbacks",
                    "CFBundleURLSchemes": [
                        "shared-callback",
                        "com.original.host",
                        "callback-com.original.host",
                        "prefixcom.original.host",
                        "callback-com.original.host.extra",
                    ],
                ],
            ],
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
    return AppSigningFixture(bundleURL: bundleURL, extensionURL: extensionURL, watchURL: watchURL)
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
