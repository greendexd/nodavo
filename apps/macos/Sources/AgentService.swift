import Foundation
import ServiceManagement

/// Registers the embedded per-user agent without copying executables or
/// writing directly to LaunchAgents. ServiceManagement keeps the bundle-
/// relative executable path valid when the user moves the application.
@MainActor
enum BundledAgentRegistration {
    private static let launchAgentPlist = "dev.nodavo.agent.plist"

    static func ensureRegistered() {
        guard Bundle.main.bundleURL.pathExtension == "app",
              Bundle.main.object(forInfoDictionaryKey: "NodavoDevelopmentBuild") as? Bool != true
        else {
            return
        }

        let service = SMAppService.agent(plistName: launchAgentPlist)
        switch service.status {
        case .notRegistered:
            // A failed or user-denied registration leaves the UI connected to
            // no agent; it never falls back to launching an unregistered copy.
            try? service.register()
        case .enabled, .requiresApproval, .notFound:
            break
        @unknown default:
            break
        }
    }
}
