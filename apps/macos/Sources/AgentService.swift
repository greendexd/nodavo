import Foundation
import ServiceManagement

enum BundledAgentRegistrationStatus: Equatable {
    case notApplicable
    case enabled
    case registered
    case requiresApproval
    case notFound
    case failed
}

/// Registers the embedded per-user agent without copying executables or
/// writing directly to LaunchAgents. ServiceManagement keeps the bundle-
/// relative executable path valid when the user moves the application.
@MainActor
enum BundledAgentRegistration {
    private static let launchAgentPlist = "dev.nodavo.agent.plist"

    static func ensureRegistered() -> BundledAgentRegistrationStatus {
        guard Bundle.main.bundleURL.pathExtension == "app",
              Bundle.main.object(forInfoDictionaryKey: "NodavoDevelopmentBuild") as? Bool != true
        else {
            return .notApplicable
        }

        let service = SMAppService.agent(plistName: launchAgentPlist)
        switch service.status {
        case .notRegistered:
            // A failed or user-denied registration leaves the UI connected to
            // no agent; it never falls back to launching an unregistered copy.
            do {
                try service.register()
                return service.status == .requiresApproval ? .requiresApproval : .registered
            } catch {
                return .failed
            }
        case .enabled:
            return .enabled
        case .requiresApproval:
            return .requiresApproval
        case .notFound:
            return .notFound
        @unknown default:
            return .failed
        }
    }
}
