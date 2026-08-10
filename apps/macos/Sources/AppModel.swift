import SwiftUI

struct UpdatePollingOwner {
    private(set) var generation: UInt64 = 0
    private(set) var isActive = false

    mutating func begin(for phase: UpdatePhase) -> UInt64? {
        guard phase.requiresAutomaticPolling, !isActive else { return nil }
        generation &+= 1
        isActive = true
        return generation
    }

    func owns(_ candidate: UInt64) -> Bool {
        isActive && candidate == generation
    }

    mutating func finish(_ candidate: UInt64) -> Bool {
        guard owns(candidate) else { return false }
        isActive = false
        return true
    }

    mutating func stop() {
        generation &+= 1
        isActive = false
    }
}

struct ReadinessRequestOwner {
    private(set) var generation: UInt64 = 0
    private(set) var isRequestInProgress = false

    mutating func begin() -> UInt64 {
        generation &+= 1
        isRequestInProgress = true
        return generation
    }

    func owns(_ candidate: UInt64) -> Bool {
        candidate == generation
    }

    mutating func finish(_ candidate: UInt64) -> Bool {
        guard owns(candidate) else { return false }
        isRequestInProgress = false
        return true
    }
}

enum ReadinessRequestPolicy {
    static func allowsAccessibilityPrompt(for readiness: AgentReadiness) -> Bool {
        readiness.accessibility == .actionRequired
    }
}

struct AuthoritativeAgentStatus: Equatable {
    let connectedPeer: String?
    let inputOwner: String
    let focusState: String
    let readiness: AgentReadiness

    init(_ response: AgentStatusResponse) {
        connectedPeer = response.connectedPeer
        inputOwner = response.inputOwner
        focusState = response.focusState
        readiness = response.readiness
    }
}

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
    @Published private(set) var readiness = AgentReadiness.unavailable
    @Published private(set) var readinessRequestInProgress = false
    @Published private(set) var pairingState: PairingState = .idle
    @Published private(set) var pairingPrompt: PairingPrompt?
    @Published private(set) var trustedPeersState: TrustedPeersState = .idle
    @Published private(set) var trustedPeers = [TrustedPeerSummary]()
    @Published private(set) var deviceOperationPeerIDs = Set<String>()
    @Published private(set) var devicesErrorKey: String?
    @Published private(set) var transferIsBusy = false
    @Published private(set) var queuedTransferReference: QueuedTransferReference?
    @Published private(set) var transferErrorKey: String?
    @Published private(set) var transferSession = TransferSessionState()
    @Published private(set) var transferProgressIsStale = false
    @Published private(set) var transferCancellationAuthority = TransferCancellationAuthority()
    @Published private(set) var transferSelectionRequiresFreshPicker = false
    @Published private(set) var agentRegistrationStatus: BundledAgentRegistrationStatus
    @Published private(set) var updateStatus = UpdateStatusSnapshot.idle
    @Published private(set) var updateOperationInProgress = false
    @Published private(set) var updateClientErrorKey: String?

    private let readinessClient = AgentClient()
    private let safetyClient = AgentClient()
    private let pairingClient = AgentClient()
    private let focusClient = AgentClient()
    private let trustedDevicesClient = AgentClient()
    private let transferAdmissionClient = AgentClient()
    private let transferPollingClient = AgentClient()
    private let transferMutationClient = AgentClient()
    private let updateClient = AgentClient()
    private let updatePollingClient = AgentClient()
    private var readinessRequestOwner = ReadinessRequestOwner()
    private var updateRequestGeneration: UInt64 = 0
    private var updatePollingOwner = UpdatePollingOwner()
    private var updatePollingTask: Task<Void, Never>?
    private var transferPollingOwner = TransferPollingOwner()
    private var transferPollingTask: Task<Void, Never>?
    private var transferPollingFailureCount = 0
    private var transferAdmissionOutcomeNeedsPoll = false
    private static let updatePollingInterval = Duration.milliseconds(750)
    private static let maximumUpdatePollAttempts = 14_400

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

    var readinessCanRequestAccessibilityPermission: Bool {
        #if os(macOS)
        ReadinessRequestPolicy.allowsAccessibilityPrompt(for: readiness)
            && !readinessRequestInProgress
        #else
        false
        #endif
    }

    var updateStatusText: LocalizedStringKey {
        switch updateStatus.phase {
        case .idle: "update_status_idle"
        case .checking: "update_status_checking"
        case .upToDate: "update_status_up_to_date"
        case .offerAvailable: "update_status_offer_available"
        case .consentRecorded: "update_status_consent_recorded"
        case .downloading: "update_status_downloading"
        case .downloadPaused: "update_status_download_paused"
        case .verifiedStaged: "update_status_verified_staged"
        case .declined: "update_status_declined"
        case .unavailable: "update_status_unavailable"
        case .failed: "update_status_failed"
        }
    }

    var updateStatusSymbol: String {
        switch updateStatus.phase {
        case .idle: "arrow.triangle.2.circlepath"
        case .checking, .consentRecorded, .downloading: "hourglass"
        case .upToDate: "checkmark.circle.fill"
        case .offerAvailable: "arrow.down.circle"
        case .downloadPaused: "pause.circle"
        case .verifiedStaged: "checkmark.shield.fill"
        case .declined: "xmark.circle"
        case .unavailable: "minus.circle"
        case .failed: "exclamationmark.triangle.fill"
        }
    }

    var updateStatusColor: Color {
        switch updateStatus.phase {
        case .upToDate, .verifiedStaged: .green
        case .unavailable, .downloadPaused: .orange
        case .failed: .red
        default: .secondary
        }
    }

    var updateFailureText: LocalizedStringKey? {
        if let updateClientErrorKey {
            return LocalizedStringKey(updateClientErrorKey)
        }
        guard let failure = updateStatus.failure else { return nil }
        let key = switch failure {
        case .notConfigured: "update_failure_not_configured"
        case .busy: "update_failure_busy"
        case .manifestRejected: "update_failure_manifest_rejected"
        case .network: "update_failure_network"
        case .staging: "update_failure_staging"
        case .verification: "update_failure_verification"
        case .internal: "update_failure_internal"
        }
        return LocalizedStringKey(key)
    }

    var updateCanCheck: Bool {
        guard !updateOperationInProgress else { return false }
        return switch updateStatus.phase {
        case .consentRecorded, .downloading, .downloadPaused:
            false
        default:
            true
        }
    }

    var updateCanDecide: Bool {
        !updateOperationInProgress
            && updateStatus.phase.acceptsPositiveDecision
            && updateStatus.offerID != nil
            && updateStatus.version != nil
    }

    var updateCanDecline: Bool {
        !updateOperationInProgress
            && updateStatus.phase.acceptsDecline
            && updateStatus.offerID != nil
            && updateStatus.version != nil
    }

    func refresh() {
        refreshReadiness()
    }

    func refreshReadiness() {
        let generation = beginReadinessRequest()
        connectionState = .checking
        Task {
            do {
                let response = try await readinessClient.status()
                finishReadinessRequest(response, generation: generation)
            } catch {
                failReadinessRequest(generation: generation)
            }
        }
    }

    func requestAccessibilityPermission() {
        guard readinessCanRequestAccessibilityPermission else { return }
        let generation = beginReadinessRequest()
        Task {
            do {
                // The agent returns a fresh status after requesting the system prompt.
                // We apply that status verbatim; requesting the prompt is not a grant.
                let response = try await readinessClient.requestAccessibilityPermission()
                finishReadinessRequest(response, generation: generation)
            } catch {
                failReadinessRequest(generation: generation)
            }
        }
    }

    func emergencyStop() {
        Task {
            do {
                let response = try await safetyClient.emergencyStop()
                applyStatus(response)
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
        guard !transferIsBusy, !transferSelectionRequiresFreshPicker else { return }
        transferIsBusy = true
        transferErrorKey = nil
        queuedTransferReference = nil
        Task {
            defer { transferIsBusy = false }
            do {
                let reference = try await transferAdmissionClient.sendFiles(paths: paths)
                queuedTransferReference = reference
                transferSession.noteAdmittedTransfer(reference.transferID)
                scheduleTransferPoll(force: true)
            } catch {
                switch TransferAdmissionFailureDisposition.classify(error) {
                case .invalidSelection:
                    transferErrorKey = "transfer_selection_invalid"
                case .rejected:
                    transferErrorKey = "transfer_queue_failed"
                case .outcomeUnknown:
                    // The local admission may already have happened before an IPC
                    // reply was lost or rejected. Keep this exact selection locked
                    // so it cannot be blindly submitted a second time.
                    transferSelectionRequiresFreshPicker = true
                    transferAdmissionOutcomeNeedsPoll = true
                    transferErrorKey = "transfer_outcome_unknown"
                    transferProgressIsStale = true
                    scheduleTransferPoll(force: true)
                }
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
        transferSelectionRequiresFreshPicker = false
        transferAdmissionOutcomeNeedsPoll = false
        if !transferPollingNeeded {
            transferPollingTask?.cancel()
            transferPollingTask = nil
            transferPollingOwner.stop()
        }
    }

    var currentTransfers: [TransferSummary] {
        transferSession.currentTransfers
    }

    var recentTransfers: [TransferSummary] {
        transferSession.recentTransfers
    }

    var transferCancellationInProgress: Set<String> {
        guard let transferID = transferCancellationAuthority.transferID,
              transferCancellationAuthority.inFlightGeneration != nil
        else { return [] }
        return [transferID]
    }

    var transferCancellationNeedsRetry: Set<String> {
        guard let transferID = transferCancellationAuthority.transferID,
              transferCancellationAuthority.needsRetry
        else { return [] }
        return [transferID]
    }

    func setTransfersVisible(_ visible: Bool) {
        transferPollingOwner.setVisible(visible)
        transferPollingTask?.cancel()
        transferPollingTask = nil
        transferPollingFailureCount = 0
        if visible {
            scheduleTransferPoll(force: true)
        }
    }

    func retryTransferProgress() {
        transferProgressIsStale = false
        transferPollingFailureCount = 0
        scheduleTransferPoll(force: true)
    }

    func cancelTransfer(_ transferID: String) {
        guard TransferSummary.isCanonicalNonNilUUID(transferID) else { return }
        let eligible = transferSession.transfers.contains(where: {
                  $0.transferID == transferID && !$0.phase.isTerminal && $0.cancellable
              })
        guard let generation = transferCancellationAuthority.begin(
            transferID: transferID,
            eligible: eligible
        ) else { return }

        Task {
            do {
                let snapshot = try await transferMutationClient.cancelTransfer(transferID: transferID)
                finishTransferCancellation(
                    transferID: transferID,
                    generation: generation,
                    snapshot: snapshot,
                    error: nil
                )
            } catch {
                finishTransferCancellation(
                    transferID: transferID,
                    generation: generation,
                    snapshot: nil,
                    error: error
                )
            }
        }
    }

    private var transferPollingNeeded: Bool {
        transferSession.transfers.contains { !$0.phase.isTerminal }
            || transferCancellationAuthority.isActive
            || transferAdmissionOutcomeNeedsPoll
            || transferSession.hasPendingAdmissions
    }

    private func scheduleTransferPoll(force: Bool) {
        if force, transferPollingOwner.isRequestInProgress {
            transferPollingTask?.cancel()
            transferPollingTask = nil
            transferPollingOwner.stop()
        }
        guard let generation = transferPollingOwner.begin(
            force: force,
            needsPolling: transferPollingNeeded
        ) else { return }
        transferPollingTask?.cancel()
        transferPollingTask = Task {
            if !force {
                do {
                    try await Task.sleep(
                        for: .milliseconds(
                            TransferPollBackoff.delayMilliseconds(
                                consecutiveFailures: transferPollingFailureCount
                            )
                        )
                    )
                } catch {
                    return
                }
            }
            do {
                let snapshot = try await transferPollingClient.listTransfers()
                finishTransferPoll(snapshot, generation: generation, error: nil)
            } catch {
                finishTransferPoll(nil, generation: generation, error: error)
            }
        }
    }

    private func finishTransferPoll(
        _ snapshot: TransferSnapshot?,
        generation: UInt64,
        error: Error?
    ) {
        guard transferPollingOwner.finish(generation) else { return }
        transferPollingTask = nil
        if let snapshot {
            let application = applyTransferSnapshot(snapshot)
            if application == .stale {
                recordTransferPollFailure()
                transferProgressIsStale = true
            } else {
                transferPollingFailureCount = 0
                transferProgressIsStale = false
                if !snapshot.truncated {
                    transferAdmissionOutcomeNeedsPoll = false
                }
            }
        } else if error != nil {
            recordTransferPollFailure()
            transferProgressIsStale = true
        }
        if transferPollingNeeded {
            scheduleTransferPoll(force: false)
        }
    }

    private func finishTransferCancellation(
        transferID: String,
        generation: UInt64,
        snapshot: TransferSnapshot?,
        error: Error?
    ) {
        guard transferCancellationAuthority.owns(
            transferID: transferID,
            generation: generation
        ) else { return }
        if let snapshot {
            let application = applyTransferSnapshot(snapshot)
            if transferCancellationAuthority.owns(
                transferID: transferID,
                generation: generation
            ) {
                transferCancellationAuthority.markAmbiguous(
                    transferID: transferID,
                    generation: generation
                )
                transferProgressIsStale = true
            } else if application != .stale {
                transferProgressIsStale = false
            }
        } else if let clientError = error as? AgentClientError,
                  case .agent = clientError {
            transferCancellationAuthority.markRejected(
                transferID: transferID,
                generation: generation
            )
            transferProgressIsStale = true
            transferErrorKey = "transfer_cancel_rejected"
        } else if error != nil {
            // A timeout or malformed/lost acknowledgement does not prove that
            // cancellation failed. Poll, and only retry this same transfer ID.
            transferCancellationAuthority.markAmbiguous(
                transferID: transferID,
                generation: generation
            )
            transferProgressIsStale = true
        }
        scheduleTransferPoll(force: true)
    }

    @discardableResult
    private func applyTransferSnapshot(_ snapshot: TransferSnapshot) -> TransferSessionState.Application {
        var retainingIDs = Set<String>()
        if let transferID = transferCancellationAuthority.transferID {
            retainingIDs.insert(transferID)
        }
        let result = transferSession.apply(snapshot, retainingIDs: retainingIDs)
        guard result != .stale, result != .unchanged else { return result }
        if result == .newInstance {
            queuedTransferReference = nil
            transferAdmissionOutcomeNeedsPoll = false
        }
        transferCancellationAuthority.reconcile(snapshot: snapshot, application: result)
        return result
    }

    private func recordTransferPollFailure() {
        if transferPollingFailureCount < 4 {
            transferPollingFailureCount += 1
        }
    }

    func refreshUpdateStatus() {
        guard let generation = beginUpdateRequest() else { return }
        Task {
            do {
                let status = try await updateClient.updateStatus()
                finishUpdateRequest(status, generation: generation)
            } catch {
                failUpdateRequest(error, generation: generation)
            }
        }
    }

    func checkForUpdate() {
        guard updateCanCheck, let generation = beginUpdateRequest() else { return }
        updateStatus = UpdateStatusSnapshot(
            phase: .checking,
            offerID: nil,
            version: nil,
            receivedBytes: nil,
            totalBytes: nil,
            failure: nil
        )
        Task {
            do {
                let status = try await updateClient.checkForUpdate()
                finishUpdateRequest(status, generation: generation)
            } catch {
                failUpdateRequest(error, generation: generation)
            }
        }
    }

    func decideUpdate(accepted: Bool) {
        guard (accepted ? updateCanDecide : updateCanDecline),
              let offerID = updateStatus.offerID,
              let generation = beginUpdateRequest()
        else { return }
        Task {
            do {
                let status = try await updateClient.decideUpdate(
                    offerID: offerID,
                    accepted: accepted
                )
                guard status.offerID == nil || status.offerID == offerID else {
                    throw AgentClientError.invalidResponse
                }
                finishUpdateRequest(status, generation: generation)
            } catch {
                failUpdateRequest(error, generation: generation)
            }
        }
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
        let status = AuthoritativeAgentStatus(response)
        connectedPeer = status.connectedPeer
        inputOwner = status.inputOwner
        focusState = status.focusState
        readiness = status.readiness
        connectionState = status.connectedPeer == nil ? .ready : .connected
    }

    private func beginReadinessRequest() -> UInt64 {
        let generation = readinessRequestOwner.begin()
        readinessRequestInProgress = true
        return generation
    }

    private func finishReadinessRequest(_ response: AgentStatusResponse, generation: UInt64) {
        guard readinessRequestOwner.finish(generation) else { return }
        readinessRequestInProgress = false
        applyStatus(response)
    }

    private func failReadinessRequest(generation: UInt64) {
        guard readinessRequestOwner.finish(generation) else { return }
        readinessRequestInProgress = false
        connectedPeer = nil
        inputOwner = "local"
        focusState = "local"
        readiness = .unavailable
        connectionState = .unavailable
    }

    private func beginUpdateRequest() -> UInt64? {
        guard !updateOperationInProgress else { return nil }
        stopUpdatePolling()
        updateRequestGeneration &+= 1
        updateOperationInProgress = true
        updateClientErrorKey = nil
        return updateRequestGeneration
    }

    private func finishUpdateRequest(_ status: UpdateStatusSnapshot, generation: UInt64) {
        guard generation == updateRequestGeneration else { return }
        updateStatus = status
        updateOperationInProgress = false
        reconcileUpdatePolling()
    }

    private func failUpdateRequest(_ error: Error, generation: UInt64) {
        guard generation == updateRequestGeneration else { return }
        updateOperationInProgress = false
        updateStatus = UpdateStatusSnapshot(
            phase: .failed,
            offerID: nil,
            version: nil,
            receivedBytes: nil,
            totalBytes: nil,
            failure: nil
        )
        if let clientError = error as? AgentClientError,
           case .agentUnavailable = clientError {
            updateStatus = UpdateStatusSnapshot(
                phase: .unavailable,
                offerID: nil,
                version: nil,
                receivedBytes: nil,
                totalBytes: nil,
                failure: nil
            )
            updateClientErrorKey = "update_agent_unavailable"
        } else {
            updateClientErrorKey = "update_request_failed"
        }
    }

    private func reconcileUpdatePolling() {
        guard updateStatus.phase.requiresAutomaticPolling,
              let expectedOfferID = updateStatus.offerID,
              let generation = updatePollingOwner.begin(for: updateStatus.phase)
        else {
            if !updateStatus.phase.requiresAutomaticPolling {
                stopUpdatePolling()
            }
            return
        }

        updatePollingTask = Task { [weak self] in
            await self?.runUpdatePolling(
                generation: generation,
                expectedOfferID: expectedOfferID
            )
        }
    }

    private func runUpdatePolling(
        generation: UInt64,
        expectedOfferID: String
    ) async {
        for _ in 0 ..< Self.maximumUpdatePollAttempts {
            do {
                try await Task.sleep(for: Self.updatePollingInterval)
            } catch {
                finishUpdatePolling(generation)
                return
            }

            let status: UpdateStatusSnapshot
            do {
                status = try await updatePollingClient.updateStatus()
            } catch {
                failUpdatePolling(error, generation: generation)
                return
            }

            guard updatePollingOwner.owns(generation) else { return }
            if let offerID = status.offerID, offerID != expectedOfferID {
                failUpdatePolling(AgentClientError.invalidResponse, generation: generation)
                return
            }

            updateStatus = status
            updateClientErrorKey = nil
            guard status.phase.requiresAutomaticPolling else {
                finishUpdatePolling(generation)
                return
            }
        }

        finishUpdatePolling(generation)
    }

    private func failUpdatePolling(_ error: Error, generation: UInt64) {
        guard updatePollingOwner.owns(generation) else { return }
        finishUpdatePolling(generation)
        updateStatus = UpdateStatusSnapshot(
            phase: .failed,
            offerID: nil,
            version: nil,
            receivedBytes: nil,
            totalBytes: nil,
            failure: nil
        )
        if let clientError = error as? AgentClientError,
           case .agentUnavailable = clientError {
            updateStatus = UpdateStatusSnapshot(
                phase: .unavailable,
                offerID: nil,
                version: nil,
                receivedBytes: nil,
                totalBytes: nil,
                failure: nil
            )
            updateClientErrorKey = "update_agent_unavailable"
        } else {
            updateClientErrorKey = "update_request_failed"
        }
    }

    private func finishUpdatePolling(_ generation: UInt64) {
        guard updatePollingOwner.finish(generation) else { return }
        updatePollingTask = nil
    }

    private func stopUpdatePolling() {
        updatePollingOwner.stop()
        updatePollingTask?.cancel()
        updatePollingTask = nil
    }
}
