import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    enum ConnectionState {
        case checking
        case ready
        case connected
        case unavailable
        case failed
    }

    enum PairingState {
        case idle
        case waiting
        case comparing
        case confirming
        case paired
        case declined
        case failed
    }

    enum TrustedPeersState {
        case idle
        case loading
        case ready
        case unavailable
        case failed
    }

    @Published private(set) var connectionState: ConnectionState = .checking
    @Published private(set) var connectedPeer: String?
    @Published private(set) var inputOwner = "local"
    @Published private(set) var focusState = "local"
    @Published private(set) var pairingState: PairingState = .idle
    @Published private(set) var pairingPrompt: PairingPrompt?
    @Published private(set) var trustedPeersState: TrustedPeersState = .idle
    @Published private(set) var trustedPeers = [TrustedPeerSummary]()
    @Published private(set) var deviceOperationPeerIDs = Set<String>()
    @Published private(set) var devicesErrorKey: String?
    @Published private(set) var transferIsBusy = false
    @Published private(set) var queuedTransferReference: QueuedTransferReference?
    @Published private(set) var transferErrorKey: String?
    @Published private(set) var agentRegistrationStatus: BundledAgentRegistrationStatus

    private let statusClient = AgentClient()
    private let safetyClient = AgentClient()
    private let pairingClient = AgentClient()
    private let focusClient = AgentClient()
    private let trustedDevicesClient = AgentClient()
    private let transferClient = AgentClient()

    init() {
        agentRegistrationStatus = BundledAgentRegistration.ensureRegistered()
    }

    var menuBarSymbol: String {
        connectionState == .connected ? "cursorarrow.motionlines" : "cursorarrow"
    }

    var statusSymbol: String {
        switch connectionState {
        case .checking: "hourglass"
        case .ready: "checkmark.circle.fill"
        case .connected: "link.circle.fill"
        case .unavailable: "minus.circle"
        case .failed: "exclamationmark.triangle.fill"
        }
    }

    var statusColor: Color {
        switch connectionState {
        case .checking: .secondary
        case .ready, .connected: .green
        case .unavailable: .orange
        case .failed: .red
        }
    }

    var statusText: LocalizedStringKey {
        switch connectionState {
        case .checking: "status_checking"
        case .ready: "status_ready"
        case .connected: "status_connected"
        case .unavailable: "status_agent_unavailable"
        case .failed: "status_failed"
        }
    }

    var pairingStatusText: LocalizedStringKey {
        switch pairingState {
        case .idle: "pairing_idle"
        case .waiting: "pairing_waiting"
        case .comparing: "pairing_compare"
        case .confirming: "pairing_confirming"
        case .paired: "pairing_succeeded"
        case .declined: "pairing_declined"
        case .failed: "pairing_failed"
        }
    }

    var pairingIsBusy: Bool {
        pairingState == .waiting || pairingState == .confirming
    }

    var trustedPeersIsLoading: Bool {
        trustedPeersState == .loading
    }

    var agentRegistrationStatusText: LocalizedStringKey {
        switch agentRegistrationStatus {
        case .notApplicable: "agent_registration_development"
        case .enabled: "agent_registration_enabled"
        case .registered: "agent_registration_registered"
        case .requiresApproval: "agent_registration_requires_approval"
        case .notFound: "agent_registration_not_found"
        case .failed: "agent_registration_failed"
        }
    }

    var agentRegistrationNeedsAttention: Bool {
        switch agentRegistrationStatus {
        case .requiresApproval, .notFound, .failed: true
        case .notApplicable, .enabled, .registered: false
        }
    }

    var focusStatusText: LocalizedStringKey {
        switch focusState {
        case "controlling_peer": "focus_controlling_peer"
        case "controlled_by_peer": "focus_controlled_by_peer"
        default: "focus_local"
        }
    }

    func refresh() {
        connectionState = .checking
        Task {
            do {
                let response = try await statusClient.status()
                connectedPeer = response.connectedPeer
                inputOwner = response.inputOwner
                focusState = response.focusState
                connectionState = response.connectedPeer == nil ? .ready : .connected
            } catch AgentClientError.agentUnavailable {
                connectedPeer = nil
                focusState = "local"
                connectionState = .unavailable
            } catch {
                connectedPeer = nil
                focusState = "local"
                connectionState = .failed
            }
        }
    }

    func emergencyStop() {
        Task {
            do {
                let response = try await safetyClient.emergencyStop()
                connectedPeer = response.connectedPeer
                inputOwner = response.inputOwner
                focusState = response.focusState
                connectionState = .ready
            } catch AgentClientError.agentUnavailable {
                connectionState = .unavailable
                focusState = "local"
            } catch {
                connectionState = .failed
                focusState = "local"
            }
        }
    }

    func requestRemoteFocus() {
        Task {
            do {
                let response = try await focusClient.requestRemoteFocus()
                connectedPeer = response.connectedPeer
                inputOwner = response.inputOwner
                focusState = response.focusState
                connectionState = .connected
            } catch AgentClientError.agentUnavailable {
                connectionState = .unavailable
                focusState = "local"
            } catch {
                connectionState = .failed
            }
        }
    }

    func releaseFocus() {
        Task {
            do {
                let response = try await focusClient.releaseFocus()
                connectedPeer = response.connectedPeer
                inputOwner = response.inputOwner
                focusState = response.focusState
                connectionState = response.connectedPeer == nil ? .ready : .connected
            } catch AgentClientError.agentUnavailable {
                connectionState = .unavailable
                focusState = "local"
            } catch {
                connectionState = .failed
            }
        }
    }

    func listenForPairing(capabilities: [PairingCapability]) {
        beginPairing(endpoint: "listen", capabilities: capabilities)
    }

    func connectForPairing(endpoint: String, capabilities: [PairingCapability]) {
        beginPairing(
            endpoint: endpoint.trimmingCharacters(in: .whitespacesAndNewlines),
            capabilities: capabilities
        )
    }

    func confirmPairing(accepted: Bool) {
        guard let prompt = pairingPrompt, pairingState == .comparing else { return }
        pairingState = .confirming
        Task {
            do {
                let paired = try await pairingClient.confirmPairing(
                    pairingID: prompt.pairingID,
                    accepted: accepted
                )
                pairingPrompt = nil
                pairingState = paired ? .paired : .declined
                refresh()
                if paired {
                    refreshTrustedPeers()
                }
            } catch AgentClientError.agentUnavailable {
                pairingPrompt = nil
                pairingState = .failed
                connectionState = .unavailable
            } catch {
                pairingPrompt = nil
                pairingState = .failed
            }
        }
    }

    func resetPairingStatus() {
        guard !pairingIsBusy else { return }
        pairingPrompt = nil
        pairingState = .idle
    }

    func refreshTrustedPeers() {
        guard trustedPeersState != .loading else { return }
        trustedPeersState = .loading
        devicesErrorKey = nil
        Task {
            do {
                trustedPeers = try await trustedDevicesClient.listTrustedPeers()
                trustedPeersState = .ready
            } catch AgentClientError.agentUnavailable {
                trustedPeersState = .unavailable
                devicesErrorKey = "trusted_devices_agent_unavailable"
                connectionState = .unavailable
            } catch {
                trustedPeersState = .failed
                devicesErrorKey = "trusted_devices_load_failed"
            }
        }
    }

    func setCapability(
        peerID: String,
        capability: PairingCapability,
        enabled: Bool
    ) {
        guard let peer = trustedPeers.first(where: { $0.peerID == peerID }),
              peer.state == .active,
              peer.localGrants.contains(capability) != enabled,
              !deviceOperationPeerIDs.contains(peerID)
        else { return }

        deviceOperationPeerIDs.insert(peerID)
        devicesErrorKey = nil
        Task {
            defer { deviceOperationPeerIDs.remove(peerID) }
            do {
                try await trustedDevicesClient.setCapability(
                    peerID: peerID,
                    capability: capability,
                    enabled: enabled
                )
                guard let index = trustedPeers.firstIndex(where: { $0.peerID == peerID }),
                      trustedPeers[index].state == .active
                else { return }
                if enabled {
                    trustedPeers[index].localGrants.insert(capability)
                } else {
                    trustedPeers[index].localGrants.remove(capability)
                }
            } catch AgentClientError.agentUnavailable {
                devicesErrorKey = "trusted_devices_agent_unavailable"
                connectionState = .unavailable
            } catch {
                devicesErrorKey = "trusted_devices_capability_failed"
            }
        }
    }

    func revokePeer(peerID: String) {
        guard let peer = trustedPeers.first(where: { $0.peerID == peerID }),
              peer.state == .active,
              !deviceOperationPeerIDs.contains(peerID)
        else { return }

        deviceOperationPeerIDs.insert(peerID)
        devicesErrorKey = nil
        Task {
            defer { deviceOperationPeerIDs.remove(peerID) }
            do {
                let response = try await trustedDevicesClient.revokePeer(peerID: peerID)
                if let index = trustedPeers.firstIndex(where: { $0.peerID == peerID }) {
                    trustedPeers[index].state = .revoked
                }
                applyStatus(response)
            } catch AgentClientError.agentUnavailable {
                devicesErrorKey = "trusted_devices_agent_unavailable"
                connectionState = .unavailable
            } catch {
                devicesErrorKey = "trusted_devices_revoke_failed"
            }
        }
    }

    func sendFiles(paths: [String]) {
        guard !transferIsBusy else { return }
        transferIsBusy = true
        transferErrorKey = nil
        queuedTransferReference = nil
        Task {
            defer { transferIsBusy = false }
            do {
                queuedTransferReference = try await transferClient.sendFiles(paths: paths)
            } catch AgentClientError.unsafeValue {
                transferErrorKey = "transfer_selection_invalid"
            } catch AgentClientError.agentUnavailable {
                transferErrorKey = "transfer_agent_unavailable"
                connectionState = .unavailable
            } catch {
                transferErrorKey = "transfer_queue_failed"
            }
        }
    }

    func rejectOversizedTransferSelection() {
        queuedTransferReference = nil
        transferErrorKey = "transfer_selection_too_many"
    }

    func clearTransferFeedback() {
        queuedTransferReference = nil
        transferErrorKey = nil
    }

    private func beginPairing(endpoint: String, capabilities: [PairingCapability]) {
        guard !endpoint.isEmpty, !pairingIsBusy else {
            pairingState = .failed
            return
        }
        pairingPrompt = nil
        pairingState = .waiting
        Task {
            do {
                pairingPrompt = try await pairingClient.beginPairing(
                    endpoint: endpoint,
                    capabilities: capabilities
                )
                pairingState = .comparing
            } catch AgentClientError.agentUnavailable {
                pairingState = .failed
                connectionState = .unavailable
            } catch {
                pairingState = .failed
            }
        }
    }

    private func applyStatus(_ response: AgentStatusResponse) {
        connectedPeer = response.connectedPeer
        inputOwner = response.inputOwner
        focusState = response.focusState
        connectionState = response.connectedPeer == nil ? .ready : .connected
    }
}
